//! 独立数据库线程中的只读落盘审计；只返回匹配计数和摘要，不返回秘密样本。
use super::SensitiveJson;
use crate::{
    model::{Error, Fault, Result},
    protection::{error, record::checked_path, Guard},
    transaction,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::PathBuf, thread};
use zeroize::Zeroizing;

struct Needle {
    category: &'static str,
    bytes: Zeroizing<Vec<u8>>,
}

pub(super) fn run(
    database: PathBuf,
    locator: String,
    purpose: Option<String>,
    paths: Vec<PathBuf>,
) -> Result<Value> {
    let caller = format!("{:?}", thread::current().id());
    let mut result = thread::Builder::new()
        .name("native-protection-audit".into())
        .spawn(move || inspect(database, locator, purpose, paths))
        .map_err(|_| error("protected_audit_thread"))?
        .join()
        .map_err(|_| error("protected_audit_thread"))?
        .map_err(|mut failure| {
            failure.paused = true;
            failure
        })?;
    result["caller_thread"] = json!(caller);
    Ok(result)
}

fn inspect(
    database: PathBuf,
    locator: String,
    purpose: Option<String>,
    paths: Vec<PathBuf>,
) -> Result<Value> {
    let guard = Guard::load(&database, &locator, purpose)?;
    let mut connection = Connection::open_with_flags(
        &database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Error::database)?;
    guard.install(&connection)?;
    let (mut needles, metadata) = transaction::run(
        &mut connection,
        TransactionBehavior::Deferred,
        Fault::None,
        |tx| {
            let version: String = tx
                .query_row("PRAGMA cipher_version", [], |row| row.get(0))
                .map_err(Error::database)?;
            let temp: i64 = tx
                .query_row("PRAGMA temp_store", [], |row| row.get(0))
                .map_err(Error::database)?;
            let format: i64 = tx
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(Error::database)?;
            if version.is_empty() || temp != 2 || !matches!(format, 3..=5) {
                return Err(error("protected_audit_format"));
            }
            let scope = guard.scope();
            let actual: (String, String, String) = tx
                .query_row(
                    "SELECT service,account,device FROM crypto_meta WHERE singleton=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(Error::database)?;
            if actual != (scope.service, scope.account, scope.device) {
                return Err(error("protected_audit_scope"));
            }
            let mut integrity = tx
                .prepare("PRAGMA cipher_integrity_check")
                .map_err(Error::database)?;
            let mut rows = integrity.query([]).map_err(Error::database)?;
            let mut errors = 0;
            while rows.next().map_err(Error::database)?.is_some() {
                errors += 1;
                if errors > 1024 {
                    return Err(error("protected_audit_integrity"));
                }
            }
            if errors != 0 {
                return Err(error("protected_audit_integrity"));
            }
            drop(rows);
            drop(integrity);
            let mut needles = Vec::new();
            read_column(
                tx,
                "SELECT provider FROM crypto_meta WHERE singleton=1 AND provider IS NOT NULL",
                "provider",
                &mut needles,
            )?;
            read_column(
                tx,
                "SELECT plaintext_json FROM crypto_inbox ORDER BY first_sequence LIMIT 8193",
                "processed_plaintext",
                &mut needles,
            )?;
            read_column(
                tx,
                "SELECT outcome_json FROM crypto_results ORDER BY request_id LIMIT 8193",
                "saved_result",
                &mut needles,
            )?;
            if format >= 4 {
                read_column(tx, "SELECT journal_json FROM anchor_control WHERE singleton=1 AND journal_json IS NOT NULL", "anchor_journal", &mut needles)?;
            }
            if format == 5 {
                read_column(
                    tx,
                    "SELECT state_json FROM rebuild_control WHERE singleton=1",
                    "rebuild_control",
                    &mut needles,
                )?;
            }
            Ok((
                needles,
                json!({"cipher_version":version,"temp_store":temp,"schema_version":format,"cipher_integrity_check":"passed"}),
            ))
        },
    )?;
    // 钥匙串访问及文件扫描发生在上述显式事务结束之后。
    guard.check()?;
    add(
        &mut needles,
        "storage_key_hex",
        guard.record.key.as_bytes().to_vec(),
    )?;
    let key = crate::crypto::anchor::protocol::decode_hex(&guard.record.key)?;
    add(&mut needles, "storage_key_raw", key.to_vec())?;
    if guard.has_config() {
        let config = guard.config()?;
        add(
            &mut needles,
            "anchor_client_seed",
            config.client_seed.as_bytes().to_vec(),
        )?;
        add(
            &mut needles,
            "anchor_client_seed_raw",
            crate::crypto::anchor::protocol::decode_hex(&config.client_seed)?.to_vec(),
        )?;
    }
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    let mut total_matches = 0usize;
    for path in paths {
        checked_path(&path)?;
        let file = File::open(&path).map_err(|_| error("protected_audit_file"))?;
        let length = file
            .metadata()
            .map_err(|_| error("protected_audit_file"))?
            .len();
        if length > 64 * 1024 * 1024 || total_bytes + length > 256 * 1024 * 1024 {
            return Err(error("protected_audit_file_limit"));
        }
        let mut content = Zeroizing::new(Vec::new());
        file.take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut content)
            .map_err(|_| error("protected_audit_file"))?;
        if content.len() as u64 != length {
            return Err(error("protected_audit_file_changed"));
        }
        let mut matches = Vec::new();
        for needle in &needles {
            if content
                .windows(needle.bytes.len())
                .any(|window| window == needle.bytes.as_slice())
            {
                matches.push(
                    json!({"category":needle.category,"needle_sha256":digest(&needle.bytes)}),
                );
            }
        }
        total_bytes += length;
        total_matches += matches.len();
        files.push(json!({"path":path,"bytes":length,"sha256":digest(&content),"matches":matches}));
    }
    guard.check()?;
    Ok(
        json!({"database_thread":format!("{:?}",thread::current().id()),"metadata":metadata,"needle_count":needles.len(),
        "needles":needles.iter().map(|n|json!({"category":n.category,"bytes":n.bytes.len(),"sha256":digest(&n.bytes)})).collect::<Vec<_>>(),
        "files":files,"scanned_bytes":total_bytes,"match_count":total_matches,"no_secret_matches":total_matches==0}),
    )
}

fn read_column(
    tx: &Transaction<'_>,
    query: &str,
    category: &'static str,
    needles: &mut Vec<Needle>,
) -> Result<()> {
    let mut statement = tx.prepare(query).map_err(Error::database)?;
    let mut rows = statement.query([]).map_err(Error::database)?;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(Error::database)? {
        count += 1;
        if count > 8192 {
            return Err(error("protected_audit_row_limit"));
        }
        let bytes = match row.get_ref(0).map_err(Error::database)? {
            rusqlite::types::ValueRef::Text(bytes) | rusqlite::types::ValueRef::Blob(bytes) => {
                bytes
            }
            _ => return Err(error("protected_audit_value")),
        };
        add(needles, category, bytes.to_vec())?;
        let parsed = SensitiveJson(
            serde_json::from_slice(bytes).map_err(|_| error("protected_audit_value"))?,
        );
        extract(&parsed.0, category, needles, 0)?;
    }
    Ok(())
}

fn extract(
    value: &Value,
    category: &'static str,
    needles: &mut Vec<Needle>,
    depth: usize,
) -> Result<()> {
    if depth > 32 {
        return Err(error("protected_audit_depth"));
    }
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(key.as_str(), "text" | "client_seed") {
                    if let Some(text) = value.as_str() {
                        // 短文本过易随机命中；仍由上层完整 JSON 样本覆盖。
                        if text.len() >= 8 {
                            add(
                                needles,
                                if key == "text" {
                                    "message_text"
                                } else {
                                    "rebuild_client_seed"
                                },
                                text.as_bytes().to_vec(),
                            )?;
                        }
                    }
                }
                if key == "statement_bytes" {
                    if let Some(encoded) = value.as_str() {
                        let bytes = Zeroizing::new(
                            STANDARD
                                .decode(encoded)
                                .map_err(|_| error("protected_audit_value"))?,
                        );
                        if bytes.len() > 2 * 1024 * 1024 {
                            return Err(error("protected_audit_value_limit"));
                        }
                        let nested = SensitiveJson(
                            serde_json::from_slice(&bytes)
                                .map_err(|_| error("protected_audit_value"))?,
                        );
                        extract(&nested.0, category, needles, depth + 1)?;
                    }
                }
                // provider entries 的值是 JSON 编码字节；只取带私密字段的实际记录。
                if key == "entries" && category == "provider" {
                    provider_entries(value, needles)?;
                }
                extract(value, category, needles, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                extract(value, category, needles, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn provider_entries(value: &Value, needles: &mut Vec<Needle>) -> Result<()> {
    let entries = value
        .as_array()
        .ok_or_else(|| error("protected_audit_provider"))?;
    for pair in entries {
        let encoded = pair
            .as_array()
            .and_then(|pair| pair.get(1))
            .ok_or_else(|| error("protected_audit_provider"))?;
        let raw: Vec<u8> = serde_json::from_value(encoded.clone())
            .map_err(|_| error("protected_audit_provider"))?;
        let raw = Zeroizing::new(raw);
        if let Ok(parsed) = serde_json::from_slice::<Value>(&raw) {
            let parsed = SensitiveJson(parsed);
            private_arrays(&parsed.0, needles, 0)?;
        }
    }
    Ok(())
}

fn private_arrays(value: &Value, needles: &mut Vec<Needle>, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err(error("protected_audit_depth"));
    }
    if let Value::Object(object) = value {
        for (name, value) in object {
            if name.contains("private") || name.contains("secret") {
                let encoded =
                    serde_json::to_vec(value).map_err(|_| error("protected_audit_provider"))?;
                add(needles, "provider_private_json", encoded)?;
                if let Ok(raw) = serde_json::from_value::<Vec<u8>>(value.clone()) {
                    add(needles, "provider_private_raw", raw)?;
                }
            }
            private_arrays(value, needles, depth + 1)?;
        }
    } else if let Value::Array(values) = value {
        for value in values {
            private_arrays(value, needles, depth + 1)?;
        }
    }
    Ok(())
}

fn add(needles: &mut Vec<Needle>, category: &'static str, bytes: Vec<u8>) -> Result<()> {
    let bytes = Zeroizing::new(bytes);
    if bytes.len() < 8 {
        return Ok(());
    }
    if bytes.len() > 2 * 1024 * 1024
        || needles.len() >= 32768
        || needles.iter().map(|n| n.bytes.len()).sum::<usize>() + bytes.len() > 32 * 1024 * 1024
    {
        return Err(error("protected_audit_needle_limit"));
    }
    if !needles.iter().any(|needle| *needle.bytes == *bytes) {
        needles.push(Needle { category, bytes });
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    crate::crypto::anchor::protocol::encode_hex(&Sha256::digest(bytes))
}
