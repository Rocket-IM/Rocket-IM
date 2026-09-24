//! 在一个显式事务内承诺全部密码业务表；协调表在独立签名域，避免清理自引用。
use crate::{
    protocol::{ApiError, Checkpoint, Fault},
    transaction,
};
use rusqlite::{types::ValueRef, Connection, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

const QUERIES: &[(&str, &str)] = &[
    ("schema", "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE tbl_name GLOB 'crypto_*' ORDER BY type, name LIMIT 129"),
    ("meta", "SELECT singleton, format, service, account, revision, identity_json, conversation, provider, welcome, encryptions, decryptions, download_cursor, processing_cursor FROM crypto_meta ORDER BY singleton LIMIT 129"),
    ("reservation", "SELECT singleton, operation, attempt_id, input_hash, base_revision, base_provider_hash FROM crypto_reservation ORDER BY singleton LIMIT 129"),
    ("outbox", "SELECT attempt_id, message_id, record_json FROM crypto_outbox ORDER BY attempt_id LIMIT 129"),
    ("events", "SELECT sequence, event_id, record_json FROM crypto_events ORDER BY length(sequence), sequence LIMIT 129"),
    ("messages", "SELECT sequence, event_id, message_id, record_json FROM crypto_messages ORDER BY length(sequence), sequence LIMIT 129"),
    ("receipts", "SELECT event_id, record_json FROM crypto_receipts ORDER BY event_id LIMIT 129"),
    ("journal", "SELECT revision, operation, attempt_id, input_hash, provider_hash, result_hash FROM crypto_journal ORDER BY length(revision), revision LIMIT 129"),
];

fn bounded(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(super::error("anchor_state_limit"));
    }
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

pub(crate) fn in_transaction(tx: &Transaction<'_>) -> Result<String, ApiError> {
    commitment(tx, false)
}

/// 只读核验预约前序：调用者先验证唯一预约与已签门禁的绑定；绝不清除实际预约。
/// 保持原摘要域、列数和表结束标记，只把该槽按前序的空表编码。
pub(super) fn without_crypto_reservation(tx: &Transaction<'_>) -> Result<String, ApiError> {
    commitment(tx, true)
}

fn commitment(tx: &Transaction<'_>, project_reservation_empty: bool) -> Result<String, ApiError> {
    let mut hasher = Sha256::new();
    hasher.update(b"Rocket-IM/browser-crypto-complete-state/v1\0");
    let mut total = 0usize;
    for (name, sql) in QUERIES {
        bounded(&mut hasher, name.as_bytes())?;
        let mut statement = tx.prepare(sql).map_err(ApiError::database)?;
        let columns = statement.column_count();
        hasher.update((columns as u64).to_be_bytes());
        if project_reservation_empty && *name == "reservation" {
            hasher.update([0]);
            hasher.update(0u64.to_be_bytes());
            continue;
        }
        let mut rows = statement.query([]).map_err(ApiError::database)?;
        let mut count = 0u64;
        while let Some(row) = rows.next().map_err(ApiError::database)? {
            count += 1;
            if count > 128 {
                return Err(super::error("anchor_state_limit"));
            }
            hasher.update([1]);
            for column in 0..columns {
                let value = row.get_ref(column).map_err(ApiError::database)?;
                match value {
                    ValueRef::Null => hasher.update([0]),
                    ValueRef::Integer(value) => {
                        hasher.update([1]);
                        hasher.update(value.to_be_bytes());
                    }
                    ValueRef::Text(value) | ValueRef::Blob(value) => {
                        total = total
                            .checked_add(value.len())
                            .ok_or_else(|| super::error("anchor_state_limit"))?;
                        if total > 8 * 1024 * 1024 {
                            return Err(super::error("anchor_state_limit"));
                        }
                        hasher.update([
                            if matches!(
                                row.get_ref(column).map_err(ApiError::database)?,
                                ValueRef::Text(_)
                            ) {
                                2
                            } else {
                                3
                            },
                        ]);
                        bounded(&mut hasher, value)?;
                    }
                    ValueRef::Real(_) => return Err(super::error("anchor_state_format")),
                }
            }
        }
        hasher.update([0]);
        hasher.update(count.to_be_bytes());
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(crate) fn read(connection: &mut Connection) -> Result<String, ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Deferred,
        Fault::None,
        Checkpoint::None,
        None,
        in_transaction,
    )
}
