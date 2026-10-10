//! 协调记录不含 MLS 秘密；门禁和结果分别签名绑定，和业务结果共用最终事务。
use super::{client::Client, commitment, error, protocol};
use crate::{
    crypto::{preflight, requests::Action},
    protocol::{ApiError, Checkpoint, Fault, Scope},
    transaction,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Gate {
    pub kind: String,
    pub binding: String,
    pub txn: String,
    pub base: String,
    pub input: String,
    pub reserved_revision: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub kind: String,
    pub gate: Gate,
    pub target: String,
    pub result_hash: String,
}

pub(super) struct Local {
    pub head: String,
    pub gate: Option<Gate>,
    pub journal: Option<Journal>,
}

fn exists(tx: &Transaction<'_>) -> Result<bool, ApiError> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'anchor_control')",
        [],
        |row| row.get(0),
    )
    .map_err(ApiError::database)
}

pub(crate) fn reject_bound(connection: &mut Connection) -> Result<(), ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Deferred,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| {
            if exists(tx)? {
                Err(error("anchor_required"))
            } else {
                Ok(())
            }
        },
    )
}

pub(super) fn initialize(connection: &mut Connection, client: &Client) -> Result<(), ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Immediate,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| {
            check_identity(tx, client)?;
            if !exists(tx)? {
                tx.execute_batch("CREATE TABLE anchor_control (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), binding TEXT NOT NULL, gate_json TEXT, journal_json TEXT)").map_err(ApiError::database)?;
                tx.execute(
                    "INSERT INTO anchor_control(singleton, binding) VALUES (1, ?1)",
                    [client.fingerprint()],
                )
                .map_err(ApiError::database)?;
            }
            local(tx, client)?;
            Ok(())
        },
    )
}

fn check_identity(tx: &Transaction<'_>, client: &Client) -> Result<(), ApiError> {
    let text: Option<String> = tx
        .query_row(
            "SELECT identity_json FROM crypto_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(ApiError::database)?;
    let value: Value = serde_json::from_str(&text.ok_or_else(|| error("anchor_identity_missing"))?)
        .map_err(|_| error("anchor_identity"))?;
    let key = STANDARD
        .decode(
            value["identityKey"]
                .as_str()
                .ok_or_else(|| error("anchor_identity"))?,
        )
        .map_err(|_| error("anchor_identity"))?;
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    if value["service"] != client.config.scope.service
        || value["account"] != client.config.scope.account
        || value["device"] != client.config.scope.device
        || hex != client.config.scope.identity_key
    {
        return Err(error("anchor_identity"));
    }
    Ok(())
}

fn decode<T: for<'de> Deserialize<'de>>(
    text: Option<String>,
    client: &Client,
) -> Result<Option<T>, ApiError> {
    text.map(|text| {
        if text.len() > 32768 {
            return Err(error("anchor_journal_invalid"));
        }
        let signed = serde_json::from_str(&text).map_err(|_| error("anchor_journal_invalid"))?;
        client.verify_journal(&signed)
    })
    .transpose()
}

pub(super) fn local(tx: &Transaction<'_>, client: &Client) -> Result<Local, ApiError> {
    check_identity(tx, client)?;
    let (binding, gate, journal): (String, Option<String>, Option<String>) = tx
        .query_row(
            "SELECT binding, gate_json, journal_json FROM anchor_control WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(ApiError::database)?;
    if binding != client.fingerprint() {
        return Err(error("anchor_config_mismatch"));
    }
    let gate: Option<Gate> = decode(gate, client)?;
    if let Some(gate) = &gate {
        if gate.kind != "gate_v1" || gate.binding != binding {
            return Err(error("anchor_journal_invalid"));
        }
        for value in [&gate.txn, &gate.base, &gate.input] {
            protocol::decode_hex(value)?;
        }
        if let Some(revision) = &gate.reserved_revision {
            crate::protocol::parse_revision(revision)?;
        }
    }
    let journal: Option<Journal> = decode(journal, client)?;
    if let Some(journal) = &journal {
        if journal.kind != "completed_v1"
            || Some(&journal.gate) != gate.as_ref()
            || journal.gate.reserved_revision.is_none()
        {
            return Err(error("anchor_journal_invalid"));
        }
        protocol::decode_hex(&journal.target)?;
        protocol::decode_hex(&journal.result_hash)?;
    }
    Ok(Local {
        head: commitment::in_transaction(tx)?,
        gate,
        journal,
    })
}

pub(super) fn read(connection: &mut Connection, client: &Client) -> Result<Local, ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Deferred,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| local(tx, client),
    )
}

fn save_gate(tx: &Transaction<'_>, client: &Client, gate: &Gate) -> Result<(), ApiError> {
    let signed = client.sign_journal(gate)?;
    let text = serde_json::to_string(&signed).map_err(|_| error("anchor_journal_invalid"))?;
    if tx
        .execute(
            "UPDATE anchor_control SET gate_json = ?1 WHERE singleton = 1",
            [text],
        )
        .map_err(ApiError::database)?
        != 1
    {
        return Err(error("anchor_journal_invalid"));
    }
    Ok(())
}

pub(super) fn begin(
    connection: &mut Connection,
    client: &Client,
    input: &str,
) -> Result<Gate, ApiError> {
    begin_inner(connection, client, input, None)
}

pub(super) fn begin_checked(
    connection: &mut Connection,
    client: &Client,
    input: &str,
    scope: &Scope,
    action: &Action,
) -> Result<Gate, ApiError> {
    begin_inner(connection, client, input, Some((scope, action)))
}

fn begin_inner(
    connection: &mut Connection,
    client: &Client,
    input: &str,
    request: Option<(&Scope, &Action)>,
) -> Result<Gate, ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Immediate,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| {
            let state = local(tx, client)?;
            if state.gate.is_some() || state.journal.is_some() {
                return Err(error("anchor_paused"));
            }
            // 与写门共用同一事务，普通业务拒绝不得留下本地门或发出远端预约。
            if let Some((scope, action)) = request {
                preflight::check(tx, scope, action)?;
            }
            let gate = Gate {
                kind: "gate_v1".into(),
                binding: client.fingerprint(),
                txn: protocol::random_hex()?,
                base: state.head,
                input: input.into(),
                reserved_revision: None,
            };
            save_gate(tx, client, &gate)?;
            Ok(gate)
        },
    )
}

pub(super) fn reserved(
    connection: &mut Connection,
    client: &Client,
    gate: &Gate,
    revision: &str,
) -> Result<Gate, ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Immediate,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| {
            let state = local(tx, client)?;
            if state.head != gate.base
                || state.gate.as_ref() != Some(gate)
                || state.journal.is_some()
            {
                return Err(error("anchor_state_changed"));
            }
            let mut next = gate.clone();
            next.reserved_revision = Some(revision.into());
            save_gate(tx, client, &next)?;
            Ok(next)
        },
    )
}

pub(super) fn validate_base(
    tx: &Transaction<'_>,
    client: &Client,
    gate: &Gate,
) -> Result<(), ApiError> {
    let state = local(tx, client)?;
    if state.head != gate.base
        || state.gate.as_ref() != Some(gate)
        || state.journal.is_some()
        || gate.reserved_revision.is_none()
    {
        return Err(error("anchor_state_changed"));
    }
    Ok(())
}

pub(super) fn completed(
    tx: &Transaction<'_>,
    client: &Client,
    gate: &Gate,
    result: Value,
) -> Result<Value, ApiError> {
    let state = local(tx, client)?;
    if state.gate.as_ref() != Some(gate) || state.journal.is_some() {
        return Err(error("anchor_state_changed"));
    }
    let journal = Journal {
        kind: "completed_v1".into(),
        gate: gate.clone(),
        target: state.head,
        result_hash: protocol::hash_bytes(
            &serde_json::to_vec(&result).map_err(|_| error("anchor_journal_invalid"))?,
        ),
    };
    let text = serde_json::to_string(&client.sign_journal(&journal)?)
        .map_err(|_| error("anchor_journal_invalid"))?;
    tx.execute(
        "UPDATE anchor_control SET journal_json = ?1 WHERE singleton = 1",
        [text],
    )
    .map_err(ApiError::database)?;
    Ok(result)
}

pub(super) fn clear(
    connection: &mut Connection,
    client: &Client,
    gate: Option<&Gate>,
    head: &str,
) -> Result<(), ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Immediate,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| {
            let state = local(tx, client)?;
            if state.head != head || state.gate.as_ref() != gate {
                return Err(error("anchor_state_changed"));
            }
            tx.execute("UPDATE anchor_control SET gate_json = NULL, journal_json = NULL WHERE singleton = 1", []).map_err(ApiError::database)?;
            Ok(())
        },
    )
}
