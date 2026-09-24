//! 只读证明未决范围的完整前序；不删除预约，不导入 provider，不交付密码快照。
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};

use super::{
    client::Client,
    commitment,
    database::{self, Gate},
    error,
    protocol::{self, Action, Status},
};
use crate::{
    protocol::{parse_revision, validate_id, ApiError, Checkpoint, Fault},
    transaction, StorageProbe,
};

#[derive(PartialEq, Eq)]
struct Basis {
    gate: Gate,
    local_head: String,
    baseline_head: String,
    conversation: String,
}

struct Reservation {
    operation: String,
    attempt_id: String,
    input_hash: String,
    base_revision: String,
    base_provider_hash: Option<String>,
}

fn denied() -> ApiError {
    error("anchor_rebuild_basis")
}

fn validate_reservation(tx: &Transaction<'_>, gate: &Gate) -> Result<(), ApiError> {
    let count: u32 = tx
        .query_row("SELECT COUNT(*) FROM crypto_reservation", [], |row| {
            row.get(0)
        })
        .map_err(ApiError::database)?;
    if count > 1 {
        return Err(denied());
    }
    let reservation = tx.query_row(
        "SELECT operation, attempt_id, input_hash, base_revision, base_provider_hash FROM crypto_reservation WHERE singleton = 1",
        [], |row| Ok(Reservation { operation: row.get(0)?, attempt_id: row.get(1)?, input_hash: row.get(2)?,
            base_revision: row.get(3)?, base_provider_hash: row.get(4)? }))
        .optional().map_err(ApiError::database)?;
    let Some(reservation) = reservation else {
        return if count == 0 { Ok(()) } else { Err(denied()) };
    };
    if count != 1
        || gate.reserved_revision.is_none()
        || reservation.input_hash != gate.input
        || !matches!(reservation.operation.as_str(), "send" | "process_next")
    {
        return Err(denied());
    }
    validate_id(&reservation.attempt_id).map_err(|_| denied())?;
    parse_revision(&reservation.base_revision).map_err(|_| denied())?;
    protocol::decode_hex(&reservation.input_hash).map_err(|_| denied())?;
    let length: Option<i64> = tx
        .query_row(
            "SELECT length(provider) FROM crypto_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(ApiError::database)?;
    if !length.is_some_and(|length| (1..=2 * 1024 * 1024).contains(&length)) {
        return Err(denied());
    }
    let (revision, provider, processing): (String, Vec<u8>, String) = tx
        .query_row(
            "SELECT revision, provider, processing_cursor FROM crypto_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(ApiError::database)?;
    if reservation.base_revision != revision
        || reservation.base_provider_hash.as_deref() != Some(&protocol::hash_bytes(&provider))
    {
        return Err(denied());
    }
    match reservation.operation.as_str() {
        "send" => {
            let cached: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM crypto_outbox WHERE attempt_id = ?1)",
                    [&reservation.attempt_id],
                    |row| row.get(0),
                )
                .map_err(ApiError::database)?;
            if cached {
                return Err(denied());
            }
        }
        "process_next" => {
            let expected = parse_revision(&processing)
                .map_err(|_| denied())?
                .checked_add(1)
                .ok_or_else(denied)?
                .to_string();
            let event: Option<String> = tx
                .query_row(
                    "SELECT event_id FROM crypto_events WHERE sequence = ?1",
                    [&expected],
                    |row| row.get(0),
                )
                .optional()
                .map_err(ApiError::database)?;
            let action = serde_json::to_vec(&crate::crypto::requests::Action::ProcessNext)
                .map_err(|_| denied())?;
            if event.as_deref() != Some(reservation.attempt_id.as_str())
                || protocol::hash_bytes(&action) != gate.input
            {
                return Err(denied());
            }
        }
        _ => return Err(denied()),
    }
    Ok(())
}

fn read(connection: &mut Connection, client: &Client) -> Result<Basis, ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Deferred,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| {
            let local = database::local(tx, client)?;
            if local.journal.is_some() {
                return Err(denied());
            }
            let gate = local.gate.ok_or_else(denied)?;
            let conversation: Option<String> = tx
                .query_row(
                    "SELECT conversation FROM crypto_meta WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(ApiError::database)?;
            let conversation = conversation.ok_or_else(denied)?;
            validate_id(&conversation).map_err(|_| denied())?;
            validate_reservation(tx, &gate)?;
            let baseline_head = commitment::without_crypto_reservation(tx)?;
            if baseline_head != gate.base {
                return Err(denied());
            }
            Ok(Basis {
                gate,
                local_head: local.head,
                baseline_head,
                conversation,
            })
        },
    )
}

pub(super) async fn inspect_basis(
    storage: &mut StorageProbe,
    client: &Client,
) -> Result<Value, ApiError> {
    let connection = storage.connection.as_mut().ok_or_else(ApiError::closed)?;
    let before = read(connection, client)?;
    let remote = client
        .rpc(
            Action::Inspect,
            &protocol::random_hex()?,
            &before.gate.base,
            "absent",
            "0",
        )
        .await?;
    if remote.status != Status::Inspected
        || remote.head != before.gate.base
        || remote.active_txn.as_deref() != Some(before.gate.txn.as_str())
        || parse_revision(&remote.revision).map_err(|_| denied())? == 0
        || before
            .gate
            .reserved_revision
            .as_ref()
            .is_some_and(|revision| revision != &remote.revision)
    {
        return Err(denied());
    }
    // 网络期间未持有事务；重新核对整个本地事实，任何改变都拒绝本次基线。
    let after = read(connection, client)?;
    if before != after {
        return Err(denied());
    }
    Ok(
        json!({"snapshot":null,"status":{"assurance":"synthetic_local","phase":"paused",
        "localHead":after.local_head,"remoteHead":remote.head,"remoteRevision":remote.revision,
        "remotePending":remote.active_txn,"localPending":true,"reason":"anchor_unresolved"},
        "rebuildBasis":{"oldScope":client.config.scope,"oldHead":after.gate.base,"oldTxn":after.gate.txn,
        "oldRevision":remote.revision,"oldConversation":after.conversation,
        "localHead":after.local_head,"baselineHead":after.baseline_head}}),
    )
}
