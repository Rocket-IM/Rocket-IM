use super::{
    client::Client,
    database::{self, Journal, Local},
    error,
    protocol::{self, Action, Response, Status},
};
use crate::{
    crypto::{
        requests::{Action as CryptoAction, Request},
        store,
    },
    protocol::ApiError,
    StorageProbe,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorTest {
    checkpoint: String,
}

fn parse(json: &str, test_mode: bool) -> Result<(Value, Option<String>), ApiError> {
    if json.len() > 256 * 1024 {
        return Err(ApiError::invalid());
    }
    let mut value: Value = serde_json::from_str(json).map_err(|_| ApiError::invalid())?;
    let object = value.as_object_mut().ok_or_else(ApiError::invalid)?;
    let checkpoint = match object.remove("anchorTest") {
        Some(_) if !test_mode => return Err(ApiError::test_only()),
        Some(value) => {
            let test: AnchorTest =
                serde_json::from_value(value).map_err(|_| ApiError::invalid())?;
            if !matches!(
                test.checkpoint.as_str(),
                "after_anchor_reserve" | "after_candidate_commit" | "after_anchor_finish"
            ) {
                return Err(ApiError::invalid());
            }
            Some(test.checkpoint)
        }
        None => None,
    };
    if checkpoint.is_some() && object.contains_key("test") {
        return Err(ApiError::invalid());
    }
    Ok((value, checkpoint))
}

fn connection(storage: &mut StorageProbe) -> Result<&mut Connection, ApiError> {
    storage.connection.as_mut().ok_or_else(ApiError::closed)
}

async fn inspect(client: &Client, head: &str) -> Result<Response, ApiError> {
    let remote = client
        .rpc(
            Action::Inspect,
            &protocol::random_hex()?,
            head,
            "absent",
            "0",
        )
        .await?;
    if remote.status != Status::Inspected {
        return Err(error("anchor_response"));
    }
    Ok(remote)
}

fn view(local: &Local, remote: &Response, snapshot: Option<Value>) -> Value {
    let reason = if local.head != remote.head {
        Some("anchor_head_mismatch")
    } else if remote.active_txn.is_some() {
        Some("anchor_unresolved")
    } else if local.gate.is_some() || local.journal.is_some() {
        Some("anchor_recovery_required")
    } else {
        None
    };
    json!({"snapshot":snapshot,"status":{"assurance":"synthetic_local","phase":if reason.is_some(){"paused"}else{"ready"},
        "localHead":local.head,"remoteHead":remote.head,"remoteRevision":remote.revision,
        "remotePending":remote.active_txn,"localPending":local.gate.is_some(),"reason":reason}})
}

fn bump(revision: &str) -> Result<String, ApiError> {
    crate::protocol::parse_revision(revision)?
        .checked_add(1)
        .map(|value| value.to_string())
        .ok_or_else(|| error("anchor_revision_exhausted"))
}

async fn finish(client: &Client, journal: &Journal) -> Result<Response, ApiError> {
    let gate = &journal.gate;
    let revision = gate
        .reserved_revision
        .as_deref()
        .ok_or_else(|| error("anchor_journal_invalid"))?;
    let remote = client
        .rpc(
            Action::Finish,
            &gate.txn,
            &gate.base,
            &journal.target,
            revision,
        )
        .await?;
    if !matches!(remote.status, Status::Finished | Status::FinishedDuplicate)
        || remote.head != journal.target
        || remote.active_txn.is_some()
        || remote.revision != bump(revision)?
    {
        return Err(error("anchor_conflict"));
    }
    Ok(remote)
}

fn checkpoint(
    storage: &StorageProbe,
    requested: Option<&str>,
    phase: &str,
) -> Result<(), ApiError> {
    if requested == Some(phase) {
        crate::transaction::pause_for_termination(storage.checkpoint.as_ref(), phase, true)?;
    }
    Ok(())
}

pub(super) async fn execute(
    storage: &mut StorageProbe,
    client: &Client,
    json: &str,
) -> Result<Value, ApiError> {
    let (value, phase) = parse(json, storage.test_mode)?;
    let operation = value["op"].as_str().ok_or_else(ApiError::invalid)?;
    if operation == "rebuild_basis" {
        if value.as_object().ok_or_else(ApiError::invalid)?.len() != 1 || phase.is_some() {
            return Err(ApiError::invalid());
        }
        return super::rebuild_basis::inspect_basis(storage, client).await;
    }
    if matches!(operation, "status" | "resume") {
        if value.as_object().ok_or_else(ApiError::invalid)?.len() != 1 || phase.is_some() {
            return Err(ApiError::invalid());
        }
        if operation == "resume" {
            storage.ensure_available()?;
            return resume(connection(storage)?, client).await;
        }
        return status(connection(storage)?, client).await;
    }
    storage.ensure_available()?;
    let request = Request::parse(
        &serde_json::to_string(&value).map_err(|_| ApiError::invalid())?,
        storage.test_mode,
    )?;
    if matches!(request.action, CryptoAction::Initialize) {
        return Err(error("anchor_initialization"));
    }
    if phase.is_some() && storage.checkpoint.is_none() {
        return Err(ApiError::invalid());
    }
    let input = protocol::hash_bytes(
        &serde_json::to_vec(&request.action).map_err(|_| ApiError::invalid())?,
    );
    let gate = database::begin(connection(storage)?, client, &input)?;
    let observed = inspect(client, &gate.base).await?;
    let reserved = client
        .rpc(
            Action::Reserve,
            &gate.txn,
            &gate.base,
            "absent",
            &observed.revision,
        )
        .await?;
    if reserved.status != Status::Reserved
        || reserved.head != gate.base
        || reserved.active_txn.as_deref() != Some(&gate.txn)
        || reserved.revision != bump(&observed.revision)?
    {
        return Err(error("anchor_conflict"));
    }
    let gate = database::reserved(connection(storage)?, client, &gate, &reserved.revision)?;
    checkpoint(storage, phase.as_deref(), "after_anchor_reserve")?;
    let before = |tx: &rusqlite::Transaction<'_>| database::validate_base(tx, client, &gate);
    let complete =
        |tx: &rusqlite::Transaction<'_>, result| database::completed(tx, client, &gate, result);
    let hooks = store::Hooks {
        before: &before,
        complete: &complete,
    };
    let scope = storage.scope.clone();
    let hook = storage.checkpoint.clone();
    let result = store::execute_completed(
        connection(storage)?,
        &scope,
        request,
        hook.as_ref(),
        Some(&hooks),
    )?;
    checkpoint(storage, phase.as_deref(), "after_candidate_commit")?;
    let local = database::read(connection(storage)?, client)?;
    let journal = local
        .journal
        .ok_or_else(|| error("anchor_journal_missing"))?;
    if local.head != journal.target
        || journal.gate != gate
        || journal.result_hash
            != protocol::hash_bytes(
                &serde_json::to_vec(&result).map_err(|_| error("anchor_journal_invalid"))?,
            )
    {
        return Err(error("anchor_state_changed"));
    }
    let remote = finish(client, &journal).await?;
    checkpoint(storage, phase.as_deref(), "after_anchor_finish")?;
    database::clear(connection(storage)?, client, Some(&gate), &journal.target)?;
    let local = database::read(connection(storage)?, client)?;
    if local.head != remote.head || local.gate.is_some() {
        return Err(error("anchor_state_changed"));
    }
    Ok(view(&local, &remote, Some(result)))
}

async fn status(connection: &mut Connection, client: &Client) -> Result<Value, ApiError> {
    let mut local = database::read(connection, client)?;
    let remote = inspect(client, &local.head).await?;
    if (remote.head != local.head || remote.active_txn.is_some()) && local.gate.is_none() {
        database::begin(
            connection,
            client,
            &protocol::hash_bytes(b"diagnostic_mismatch"),
        )?;
        local = database::read(connection, client)?;
    }
    // 不输出任何 outbox、正文或 Welcome；状态查询永不自动解除门禁。
    Ok(view(&local, &remote, None))
}

async fn resume(connection: &mut Connection, client: &Client) -> Result<Value, ApiError> {
    let local = database::read(connection, client)?;
    let remote = if let Some(journal) = &local.journal {
        if journal.target != local.head {
            return Err(error("anchor_state_changed"));
        }
        finish(client, journal).await?
    } else {
        let remote = inspect(client, &local.head).await?;
        if remote.active_txn.is_some() || remote.head != local.head {
            return Err(error("anchor_unresolved"));
        }
        if let Some(gate) = &local.gate {
            if gate.reserved_revision.is_some() || gate.base != local.head {
                return Err(error("anchor_journal_missing"));
            }
        }
        remote
    };
    database::clear(connection, client, local.gate.as_ref(), &local.head)?;
    Ok(view(&database::read(connection, client)?, &remote, None))
}
