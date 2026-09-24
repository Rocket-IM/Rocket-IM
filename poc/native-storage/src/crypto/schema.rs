//! 独立原生密码实验格式；已有文件缺结构时只拒绝，不补建。
use rusqlite::{params, Transaction};

use super::contract::Scope;
use crate::model::{Error, Result};

const META_V1: &str = "CREATE TABLE crypto_meta (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), format TEXT NOT NULL, service TEXT NOT NULL, account TEXT NOT NULL, device TEXT NOT NULL, revision TEXT NOT NULL, identity_json TEXT, conversation TEXT, provider BLOB, provider_hash TEXT NOT NULL, encryptions TEXT NOT NULL)";
const PENDING: &str = "CREATE TABLE crypto_pending (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), request_id TEXT NOT NULL, operation TEXT NOT NULL, input_hash TEXT NOT NULL, base_revision TEXT NOT NULL, base_provider_hash TEXT NOT NULL)";
const RESULTS: &str = "CREATE TABLE crypto_results (request_id TEXT NOT NULL PRIMARY KEY, input_hash TEXT NOT NULL, kind TEXT NOT NULL, outcome_json TEXT NOT NULL)";
const OUTBOX: &str = "CREATE TABLE crypto_outbox (attempt_id TEXT NOT NULL PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, request_id TEXT NOT NULL, input_hash TEXT NOT NULL, envelope_json TEXT NOT NULL)";
const META_V2: &str = "CREATE TABLE crypto_meta (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), format TEXT NOT NULL, service TEXT NOT NULL, account TEXT NOT NULL, device TEXT NOT NULL, revision TEXT NOT NULL, identity_json TEXT, conversation TEXT, provider BLOB, provider_hash TEXT NOT NULL, encryptions TEXT NOT NULL, processed_cursor TEXT NOT NULL, decryptions TEXT NOT NULL)";
const META: &str = "CREATE TABLE crypto_meta (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), format TEXT NOT NULL, service TEXT NOT NULL, account TEXT NOT NULL, device TEXT NOT NULL, revision TEXT NOT NULL, identity_json TEXT, conversation TEXT, provider BLOB, provider_hash TEXT NOT NULL, encryptions TEXT NOT NULL, processed_cursor TEXT NOT NULL, decryptions TEXT NOT NULL, download_cursor TEXT NOT NULL)";
const INBOX: &str = "CREATE TABLE crypto_inbox (message_key TEXT NOT NULL PRIMARY KEY, first_sequence TEXT NOT NULL UNIQUE, message_id TEXT NOT NULL, sender_account TEXT NOT NULL, sender_device TEXT NOT NULL, envelope_hash TEXT NOT NULL, ciphertext_hash TEXT NOT NULL, text_hash TEXT NOT NULL, envelope_json TEXT NOT NULL, plaintext_json TEXT NOT NULL)";
const RECEIPTS: &str = "CREATE TABLE crypto_receipts (sequence TEXT NOT NULL PRIMARY KEY, message_key TEXT NOT NULL, request_id TEXT NOT NULL UNIQUE, input_hash TEXT NOT NULL)";
const DOWNLOADS: &str = "CREATE TABLE crypto_downloads (sequence TEXT NOT NULL PRIMARY KEY, envelope_hash TEXT NOT NULL, ciphertext_hash TEXT NOT NULL, envelope_json TEXT NOT NULL)";
pub(super) const FORMAT: &str = "Rockets-IM/native-crypto/sqlite/v3";
pub(super) const ANCHOR_FORMAT: &str = "Rockets-IM/native-crypto/sqlite/v4";
pub(super) const REBUILD_FORMAT: &str = "Rockets-IM/native-crypto/sqlite/v5";
pub(super) const ANCHOR_CONTROL: &str = "CREATE TABLE anchor_control (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL, gate_json TEXT, journal_json TEXT)";
pub(super) const REBUILD_CONTROL: &str = "CREATE TABLE rebuild_control (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), state_json TEXT NOT NULL)";

pub(super) fn corrupt() -> Error {
    Error::new("crypto_store_corrupt", true)
}

pub(super) fn create(tx: &Transaction<'_>, scope: &Scope) -> Result<()> {
    let objects: i64 = tx
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .map_err(Error::database)?;
    if objects != 0 {
        return Err(corrupt());
    }
    for sql in [META, PENDING, RESULTS, OUTBOX, INBOX, RECEIPTS, DOWNLOADS] {
        tx.execute_batch(sql).map_err(Error::database)?;
    }
    tx.execute("INSERT INTO crypto_meta(singleton,format,service,account,device,revision,provider_hash,encryptions,processed_cursor,decryptions,download_cursor) VALUES(1,?1,?2,?3,?4,'0','','0','0','0','0')", params![FORMAT, scope.service, scope.account, scope.device]).map_err(Error::database)?;
    tx.execute_batch("PRAGMA user_version=3")
        .map_err(Error::database)?;
    validate(tx)
}

pub(super) fn validate(tx: &Transaction<'_>) -> Result<()> {
    crate::schema::storage_mode(tx)?;
    let version: i64 = tx
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(Error::database)?;
    if !matches!(version, 1..=5) {
        return Err(corrupt());
    }
    let mut statement = tx
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name LIMIT 19")
        .map_err(Error::database)?;
    let objects = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    let mut expected = vec![
        (
            "index",
            "sqlite_autoindex_crypto_outbox_1",
            "crypto_outbox",
            None,
        ),
        (
            "index",
            "sqlite_autoindex_crypto_outbox_2",
            "crypto_outbox",
            None,
        ),
        (
            "index",
            "sqlite_autoindex_crypto_results_1",
            "crypto_results",
            None,
        ),
        (
            "table",
            "crypto_meta",
            "crypto_meta",
            Some(match version {
                1 => META_V1,
                2 => META_V2,
                _ => META,
            }),
        ),
        ("table", "crypto_outbox", "crypto_outbox", Some(OUTBOX)),
        ("table", "crypto_pending", "crypto_pending", Some(PENDING)),
        ("table", "crypto_results", "crypto_results", Some(RESULTS)),
    ];
    if version >= 2 {
        expected.extend([
            (
                "index",
                "sqlite_autoindex_crypto_inbox_1",
                "crypto_inbox",
                None,
            ),
            (
                "index",
                "sqlite_autoindex_crypto_inbox_2",
                "crypto_inbox",
                None,
            ),
            (
                "index",
                "sqlite_autoindex_crypto_receipts_1",
                "crypto_receipts",
                None,
            ),
            (
                "index",
                "sqlite_autoindex_crypto_receipts_2",
                "crypto_receipts",
                None,
            ),
            ("table", "crypto_inbox", "crypto_inbox", Some(INBOX)),
            (
                "table",
                "crypto_receipts",
                "crypto_receipts",
                Some(RECEIPTS),
            ),
        ]);
    }
    if version >= 3 {
        expected.extend([
            (
                "index",
                "sqlite_autoindex_crypto_downloads_1",
                "crypto_downloads",
                None,
            ),
            (
                "table",
                "crypto_downloads",
                "crypto_downloads",
                Some(DOWNLOADS),
            ),
        ]);
    }
    if version >= 4 {
        expected.push((
            "table",
            "anchor_control",
            "anchor_control",
            Some(ANCHOR_CONTROL),
        ));
    }
    if version == 5 {
        expected.push((
            "table",
            "rebuild_control",
            "rebuild_control",
            Some(REBUILD_CONTROL),
        ));
    }
    expected.sort_by_key(|v| (v.0, v.1));
    if objects.len() != expected.len()
        || !objects
            .iter()
            .zip(expected)
            .all(|((kind, name, table, sql), wanted)| {
                (kind.as_str(), name.as_str(), table.as_str(), sql.as_deref()) == wanted
            })
    {
        return Err(corrupt());
    }
    if version < 3 {
        let format = format!("Rockets-IM/native-crypto/sqlite/v{version}");
        let valid: i64 = tx
            .query_row(
                "SELECT count(*) FROM crypto_meta WHERE singleton=1 AND format=?1",
                [format],
                |r| r.get(0),
            )
            .map_err(Error::database)?;
        let total: i64 = tx
            .query_row("SELECT count(*) FROM crypto_meta", [], |r| r.get(0))
            .map_err(Error::database)?;
        if valid != 1 || total != 1 {
            return Err(corrupt());
        }
        return Err(Error::new("crypto_store_upgrade_required", false));
    }
    Ok(())
}

pub(super) fn version(tx: &Transaction<'_>) -> Result<i64> {
    tx.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(Error::database)
}
