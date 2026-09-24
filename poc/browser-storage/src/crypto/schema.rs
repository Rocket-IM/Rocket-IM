//! 只创建全新的密码表集合；已有空间缺表或缺元数据时拒绝打开，不尝试补建。

use rusqlite::{params, Connection, Transaction};

use super::query;
use crate::{
    protocol::{ApiError, Checkpoint, Fault, Scope},
    transaction,
};

const TABLES: [&str; 7] = [
    "crypto_events",
    "crypto_journal",
    "crypto_messages",
    "crypto_meta",
    "crypto_outbox",
    "crypto_receipts",
    "crypto_reservation",
];

pub(crate) fn initialize_schema(
    connection: &mut Connection,
    scope: &Scope,
) -> Result<(), ApiError> {
    transaction::run(
        connection,
        rusqlite::TransactionBehavior::Immediate,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| {
            let tables = table_names(tx)?;
            if tables.is_empty() {
                create(tx, scope)?;
            } else if !tables.iter().map(String::as_str).eq(TABLES) {
                return Err(query::corrupt());
            }
            let rows: u32 = tx
                .query_row("SELECT COUNT(*) FROM crypto_meta", [], |row| row.get(0))
                .map_err(ApiError::database)?;
            if rows != 1 {
                return Err(query::corrupt());
            }
            query::reservation(tx)?;
            query::load(tx, scope)?;
            Ok(())
        },
    )
}

fn table_names(tx: &Transaction<'_>) -> Result<Vec<String>, ApiError> {
    let mut statement = tx
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name GLOB 'crypto_*' ORDER BY name LIMIT 8")
        .map_err(ApiError::database)?;
    let rows = statement
        .query_map([], |row| row.get(0))
        .map_err(ApiError::database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::database)
}

fn create(tx: &Transaction<'_>, scope: &Scope) -> Result<(), ApiError> {
    tx.execute_batch("CREATE TABLE crypto_meta (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1), format INTEGER NOT NULL CHECK(format = 1),
        service TEXT NOT NULL, account TEXT NOT NULL, revision TEXT NOT NULL,
        identity_json TEXT, conversation TEXT, provider BLOB, welcome TEXT,
        encryptions TEXT NOT NULL, decryptions TEXT NOT NULL,
        download_cursor TEXT NOT NULL, processing_cursor TEXT NOT NULL);
        CREATE TABLE crypto_reservation (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1), operation TEXT NOT NULL,
        attempt_id TEXT NOT NULL, input_hash TEXT NOT NULL, base_revision TEXT NOT NULL, base_provider_hash TEXT);
        CREATE TABLE crypto_outbox (
        attempt_id TEXT PRIMARY KEY NOT NULL, message_id TEXT NOT NULL UNIQUE, record_json TEXT NOT NULL);
        CREATE TABLE crypto_events (
        sequence TEXT PRIMARY KEY NOT NULL, event_id TEXT NOT NULL UNIQUE, record_json TEXT NOT NULL);
        CREATE TABLE crypto_messages (
        sequence TEXT PRIMARY KEY NOT NULL, event_id TEXT NOT NULL UNIQUE, message_id TEXT NOT NULL UNIQUE, record_json TEXT NOT NULL);
        CREATE TABLE crypto_receipts (event_id TEXT PRIMARY KEY NOT NULL, record_json TEXT NOT NULL);
        CREATE TABLE crypto_journal (
        revision TEXT PRIMARY KEY NOT NULL, operation TEXT NOT NULL, attempt_id TEXT NOT NULL,
        input_hash TEXT NOT NULL, provider_hash TEXT, result_hash TEXT NOT NULL);")
        .map_err(ApiError::database)?;
    tx.execute("INSERT INTO crypto_meta
        (singleton, format, service, account, revision, encryptions, decryptions, download_cursor, processing_cursor)
        VALUES (1, 1, ?1, ?2, '0', '0', '0', '0', '0')", params![scope.service, scope.account])
        .map_err(ApiError::database)?;
    Ok(())
}
