//! 无系统钥匙串访问的边界与真实 SQLCipher 文件测试；仅使用本轮合成值。
use super::{
    record::{checked_path, Locator, Record, Trust},
    sqlcipher,
};
use crate::{
    crypto::{anchor::client::Config, contract::Scope},
    model::{Error, Fault, Result},
    transaction,
};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

static NEXT: AtomicU64 = AtomicU64::new(0);
const KEY: &str = "2929292929292929292929292929292929292929292929292929292929292929";
const WRONG_KEY: &str = "3030303030303030303030303030303030303030303030303030303030303030";
const SECRET: &str = "synthetic-protected-provider-and-body-do-not-log-7df82a";

struct Fixture {
    directory: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let directory = parent.join(format!(
            "rim-protection-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { directory }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }
    fn locator(&self) -> Value {
        json!({"keychain":self.path("lab-unit.keychain-db"), "item":"lab-unit",
            "service":"service", "account":"alice", "device":"device"})
    }
    fn record(&self) -> Record {
        Record {
            version: 1,
            database: self.path("state.db"),
            locator: Locator::parse(&self.path("state.db"), &self.locator().to_string()).unwrap(),
            purpose: None,
            key: Zeroizing::new(KEY.into()),
        }
    }
    fn config(&self) -> Value {
        let helper = self.path("helper");
        fs::write(&helper, b"synthetic fixed helper bytes version one").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = SigningKey::from_bytes(&[37; 32]);
        json!({"program":helper,"directory":self.directory,"scope":{
            "service":"service","account":"alice","device":"device",
            "identity_key":"31".repeat(32),"store_id":"32".repeat(32)},
            "anchor_public_key":crate::crypto::anchor::protocol::encode_hex(key.verifying_key().as_bytes()),
            "client_seed":"33".repeat(32)})
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn scope() -> Scope {
    Scope {
        service: "service".into(),
        account: "alice".into(),
        device: "device".into(),
    }
}
fn rejected<T>(result: Result<T>, code: &str) {
    match result {
        Ok(_) => panic!("expected rejection: {code}"),
        Err(error) => assert_eq!(error.code, code),
    }
}
fn transact<T>(
    connection: &mut Connection,
    body: impl FnOnce(&Transaction<'_>) -> Result<T>,
) -> Result<T> {
    transaction::run(
        connection,
        TransactionBehavior::Immediate,
        Fault::None,
        body,
    )
}
fn open(path: &Path, key: Option<&str>, create: bool) -> Connection {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags).unwrap();
    if let Some(key) = key {
        sqlcipher::install(&connection, key).unwrap();
    }
    connection
}
fn create(connection: &mut Connection, text: &str) {
    transact(connection, |tx| {
        tx.execute_batch(
            "CREATE TABLE protected_values(id INTEGER PRIMARY KEY, value TEXT NOT NULL)",
        )
        .map_err(Error::database)?;
        tx.execute(
            "INSERT INTO protected_values(id,value) VALUES(1,?1)",
            [text],
        )
        .map_err(Error::database)?;
        Ok(())
    })
    .unwrap();
}
fn read(connection: &mut Connection) -> Result<String> {
    transaction::run(
        connection,
        TransactionBehavior::Deferred,
        Fault::None,
        |tx| {
            tx.query_row("SELECT value FROM protected_values WHERE id=1", [], |row| {
                row.get(0)
            })
            .map_err(Error::database)
        },
    )
}
fn excludes(bytes: &[u8], secret: &[u8]) {
    assert!(
        !bytes.windows(secret.len()).any(|window| window == secret),
        "secret appeared in persisted bytes"
    );
}

#[test]
fn locator_accepts_explicit_lab_scope_and_rejects_unknown_or_oversized_input() {
    let f = Fixture::new();
    let value = f.locator();
    let location = Locator::parse(&f.path("state.db"), &value.to_string()).unwrap();
    assert_eq!(location.scope(), scope());
    assert_eq!(location.trust_item(), "lab-unit.trust");
    location.check_scope(&scope()).unwrap();
    let mut unknown = value;
    unknown["seed"] = json!("must-not-be-accepted");
    rejected(
        Locator::parse(&f.path("state.db"), &unknown.to_string()),
        "protected_locator_invalid",
    );
    rejected(
        Locator::parse(&f.path("state.db"), &" ".repeat(16385)),
        "protected_locator_invalid",
    );
}

#[test]
fn locator_checks_every_scope_dimension_and_item_bounds() {
    let f = Fixture::new();
    let location = Locator::parse(&f.path("state.db"), &f.locator().to_string()).unwrap();
    for index in 0..3 {
        let mut other = scope();
        match index {
            0 => other.service = "other".into(),
            1 => other.account = "other".into(),
            _ => other.device = "other".into(),
        }
        rejected(location.check_scope(&other), "protected_scope_mismatch");
    }
    for field in ["item", "service", "account", "device"] {
        for bad in [String::new(), "x".repeat(129), "embedded\0zero".into()] {
            let mut value = f.locator();
            value[field] = json!(bad);
            match Locator::parse(&f.path("state.db"), &value.to_string()) {
                Ok(_) => panic!("invalid locator field was accepted"),
                Err(error) => assert!(error.paused),
            }
        }
    }
    let mut boundary = f.locator();
    boundary["item"] = json!(format!("lab-{}", "x".repeat(124)));
    assert!(Locator::parse(&f.path("state.db"), &boundary.to_string()).is_ok());
}

#[test]
fn locator_refuses_non_lab_keychains_and_item_names() {
    let f = Fixture::new();
    for name in ["login.keychain-db", "lab-unit.keychain", "unit.keychain-db"] {
        let mut value = f.locator();
        value["keychain"] = json!(f.path(name));
        rejected(
            Locator::parse(&f.path("state.db"), &value.to_string()),
            "protected_lab_keychain_required",
        );
    }
    for item in ["real-user-item", "lab-unit.trust"] {
        let mut value = f.locator();
        value["item"] = json!(item);
        rejected(
            Locator::parse(&f.path("state.db"), &value.to_string()),
            "protected_lab_item_required",
        );
    }
}

#[test]
fn guard_create_rejects_existing_files_and_wrong_scope_before_system_access() {
    let f = Fixture::new();
    let path = f.path("existing.db");
    fs::write(&path, b"preserve-existing-unprotected-or-encrypted-file").unwrap();
    let original = fs::read(&path).unwrap();
    // 专用钥匙串文件根本不存在；这两类拒绝必须先于任何系统查询或建钥。
    assert!(!f.path("lab-unit.keychain-db").exists());
    rejected(
        super::Guard::create(&path, &scope(), &f.locator().to_string(), None),
        "protected_store_exists",
    );
    let mut wrong = scope();
    wrong.device = "other-device".into();
    rejected(
        super::Guard::create(&f.path("absent.db"), &wrong, &f.locator().to_string(), None),
        "protected_scope_mismatch",
    );
    assert!(fs::read(&path).unwrap() == original);
    assert!(!f.path("absent.db").exists());
    assert!(!f.path("lab-unit.keychain-db").exists());
}

#[test]
fn storage_paths_refuse_relative_traversal_missing_parents_and_directories() {
    let f = Fixture::new();
    for path in [
        PathBuf::from("state.db"),
        f.path("../state.db"),
        f.path("missing/state.db"),
        f.directory.clone(),
        f.path(&"x".repeat(4097)),
    ] {
        assert!(checked_path(&path).is_err());
    }
    assert!(checked_path(&f.path("new.db")).is_ok());
    fs::write(f.path("existing.db"), b"synthetic").unwrap();
    assert!(checked_path(&f.path("existing.db")).is_ok());
}

#[cfg(unix)]
#[test]
fn storage_paths_refuse_symlink_files_and_symlink_ancestors() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    fs::write(f.path("actual.db"), b"synthetic").unwrap();
    symlink(f.path("actual.db"), f.path("linked.db")).unwrap();
    assert!(checked_path(&f.path("linked.db")).is_err());
    fs::create_dir(f.path("actual")).unwrap();
    symlink(f.path("actual"), f.path("alias")).unwrap();
    assert!(checked_path(&f.path("alias/state.db")).is_err());
    symlink(f.path("actual.db"), f.path("lab-link.keychain-db")).unwrap();
    let mut value = f.locator();
    value["keychain"] = json!(f.path("lab-link.keychain-db"));
    assert!(Locator::parse(&f.path("state.db"), &value.to_string()).is_err());
}

#[test]
fn trust_roundtrip_binds_database_key_and_each_account_dimension() {
    let f = Fixture::new();
    let record = f.record();
    let trust = Trust::new(&f.config().to_string(), &record).unwrap();
    let encoded = serde_json::to_vec(&trust).unwrap();
    Trust::parse(&encoded, &record).unwrap();
    for index in 0..5 {
        let mut other = record.clone();
        match index {
            0 => other.database = f.path("other.db"),
            1 => other.key = Zeroizing::new(WRONG_KEY.into()),
            2 => other.locator.service = "other".into(),
            3 => other.locator.account = "other".into(),
            _ => other.locator.device = "other".into(),
        }
        rejected(Trust::parse(&encoded, &other), "protected_trust_binding");
    }
}

#[test]
fn trust_rejects_invalid_versions_unknown_fields_and_malformed_keys() {
    let f = Fixture::new();
    let record = f.record();
    let config = f.config();
    let trust = Trust::new(&config.to_string(), &record).unwrap();
    let mut encoded = serde_json::to_value(&trust).unwrap();
    encoded["version"] = json!(2);
    rejected(
        Trust::parse(&serde_json::to_vec(&encoded).unwrap(), &record),
        "protected_trust_binding",
    );
    encoded["version"] = json!(1);
    encoded["unknown"] = json!(true);
    rejected(
        Trust::parse(&serde_json::to_vec(&encoded).unwrap(), &record),
        "protected_trust_invalid",
    );
    for field in ["anchor_public_key", "client_seed"] {
        let mut bad = config.clone();
        bad[field] = json!("invalid-key");
        assert!(Trust::new(&bad.to_string(), &record).is_err());
    }
    let mut weak = config;
    weak["anchor_public_key"] = json!("00".repeat(32));
    assert!(Trust::new(&weak.to_string(), &record).is_err());
    rejected(
        Trust::new(&" ".repeat(16385), &record),
        "protected_trust_invalid",
    );
}

#[test]
fn trust_checks_actual_helper_bytes_and_retains_exact_configuration() {
    let f = Fixture::new();
    let record = f.record();
    let value = f.config();
    let expected: Config = serde_json::from_value(value.clone()).unwrap();
    let trust = Trust::new(&value.to_string(), &record).unwrap();
    assert!(serde_json::to_vec(&trust.config).unwrap() == serde_json::to_vec(&expected).unwrap());
    fs::write(
        f.path("helper"),
        b"synthetic replacement helper version two",
    )
    .unwrap();
    rejected(trust.check(&record), "protected_program_changed");
    fs::remove_file(f.path("helper")).unwrap();
    assert!(trust.check(&record).is_err());
}

#[test]
fn changed_configuration_cannot_reuse_previously_signed_recovery_control() {
    use crate::crypto::anchor::client::Client;
    let f = Fixture::new();
    let record = f.record();
    let config = f.config();
    let trust = Trust::new(&config.to_string(), &record).unwrap();
    let original = Client::new(trust.config).unwrap();
    let signed = original
        .sign_local(&json!({"stage":"prepared","input":"fixed-plan"}))
        .unwrap();
    assert!(original.verify_local::<Value>(&signed).is_ok());
    for index in 0..4 {
        let mut changed = config.clone();
        match index {
            0 => changed["client_seed"] = json!("34".repeat(32)),
            1 => {
                let key = SigningKey::from_bytes(&[38; 32]);
                changed["anchor_public_key"] = json!(crate::crypto::anchor::protocol::encode_hex(
                    key.verifying_key().as_bytes()
                ));
            }
            2 => changed["scope"]["identity_key"] = json!("35".repeat(32)),
            _ => changed["scope"]["store_id"] = json!("36".repeat(32)),
        }
        let replacement = Client::new(serde_json::from_value(changed).unwrap()).unwrap();
        assert!(replacement.verify_local::<Value>(&signed).is_err());
    }
}

#[test]
fn sqlcipher_persists_reopens_and_keeps_closed_backup_encrypted() {
    let f = Fixture::new();
    let path = f.path("cipher.db");
    let mut connection = open(&path, Some(KEY), true);
    create(&mut connection, SECRET);
    assert!(read(&mut connection).unwrap() == SECRET);
    connection.close().unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3\0"));
    excludes(&bytes, SECRET.as_bytes());
    excludes(&bytes, KEY.as_bytes());
    excludes(&bytes, &[0x29; 32]);
    fs::copy(&path, f.path("backup.db")).unwrap();
    assert!(fs::read(f.path("backup.db")).unwrap() == bytes);
    for name in ["cipher.db", "backup.db"] {
        let mut reopened = open(&f.path(name), Some(KEY), false);
        assert!(read(&mut reopened).unwrap() == SECRET);
        reopened.close().unwrap();
    }
}

#[test]
fn sqlcipher_rejects_wrong_or_absent_key_without_rewriting_database() {
    let f = Fixture::new();
    let path = f.path("cipher.db");
    let mut connection = open(&path, Some(KEY), true);
    create(&mut connection, SECRET);
    connection.close().unwrap();
    let before = fs::read(&path).unwrap();
    for key in [None, Some(WRONG_KEY)] {
        let mut wrong = open(&path, key, false);
        assert!(read(&mut wrong).is_err());
        assert!(wrong.is_autocommit());
        wrong.close().unwrap();
        assert!(
            fs::read(&path).unwrap() == before,
            "failed key changed database"
        );
    }
}

#[test]
fn sqlcipher_rejects_plaintext_database_without_migrating_it() {
    let f = Fixture::new();
    let path = f.path("plain.db");
    let mut connection = open(&path, None, true);
    create(&mut connection, SECRET);
    connection.close().unwrap();
    let before = fs::read(&path).unwrap();
    assert!(before.starts_with(b"SQLite format 3\0"));
    let mut protected = open(&path, Some(KEY), false);
    assert!(read(&mut protected).is_err());
    protected.close().unwrap();
    assert!(
        fs::read(&path).unwrap() == before,
        "plaintext database was rewritten"
    );
    let mut plain = open(&path, None, false);
    assert!(read(&mut plain).unwrap() == SECRET);
    plain.close().unwrap();
}

#[test]
fn sqlcipher_authentication_rejects_modified_encrypted_page() {
    let f = Fixture::new();
    let path = f.path("cipher.db");
    let mut connection = open(&path, Some(KEY), true);
    create(&mut connection, SECRET);
    connection.close().unwrap();
    let mut bytes = fs::read(&path).unwrap();
    assert!(bytes.len() > 4096);
    bytes[64] ^= 0x80;
    fs::write(&path, &bytes).unwrap();
    let mut corrupted = open(&path, Some(KEY), false);
    assert!(read(&mut corrupted).is_err());
    corrupted.close().unwrap();
    assert!(
        fs::read(&path).unwrap() == bytes,
        "damaged database was repaired silently"
    );
}

#[test]
fn sqlcipher_rollback_journal_has_no_provider_body_or_key_bytes() {
    let f = Fixture::new();
    let path = f.path("journal.db");
    let mut connection = open(&path, Some(KEY), true);
    let original = SECRET.repeat(1024);
    create(&mut connection, &original);
    let replacement = "synthetic-replacement-private-message-f15cda".repeat(1024);
    let mut inspected = false;
    let result: Result<()> = transact(&mut connection, |tx| {
        let mode: String = tx
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(Error::database)?;
        assert_eq!(mode, "delete");
        tx.execute(
            "UPDATE protected_values SET value=?1 WHERE id=?2",
            params![replacement, 1],
        )
        .map_err(Error::database)?;
        // 故障测试在事务尚未结束时仅取证真实旁文件；不在业务入口引入文件操作。
        let journal = fs::read(f.path("journal.db-journal")).unwrap();
        assert!(journal.len() > 512);
        excludes(&journal, SECRET.as_bytes());
        excludes(&journal, b"synthetic-replacement-private-message-f15cda");
        excludes(&journal, KEY.as_bytes());
        excludes(&journal, &[0x29; 32]);
        inspected = true;
        Err(Error::new("synthetic_abort", false))
    });
    rejected(result, "synthetic_abort");
    assert!(inspected);
    assert!(connection.is_autocommit());
    assert!(read(&mut connection).unwrap() == original);
    connection.close().unwrap();
    assert!(!f.path("journal.db-journal").exists());
    assert!(!f.path("journal.db-wal").exists());
    assert!(!f.path("journal.db-shm").exists());
}

#[test]
fn sqlcipher_uses_real_codec_and_memory_temporary_storage() {
    let f = Fixture::new();
    let mut connection = open(&f.path("temporary.db"), Some(KEY), true);
    let (version, temp, security): (String, i64, String) = transact(&mut connection, |tx| {
        let version = tx
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(Error::database)?;
        let temp = tx
            .query_row("PRAGMA temp_store", [], |row| row.get(0))
            .map_err(Error::database)?;
        let security = tx
            .query_row("PRAGMA cipher_memory_security", [], |row| row.get(0))
            .map_err(Error::database)?;
        tx.execute_batch("CREATE TEMP TABLE transient(value TEXT NOT NULL)")
            .map_err(Error::database)?;
        tx.execute("INSERT INTO transient(value) VALUES(?1)", [SECRET])
            .map_err(Error::database)?;
        let value: String = tx
            .query_row("SELECT value FROM transient", [], |row| row.get(0))
            .map_err(Error::database)?;
        assert!(value == SECRET);
        Ok((version, temp, security))
    })
    .unwrap();
    assert!(!version.is_empty());
    assert_eq!(temp, 2);
    assert!(matches!(security.as_str(), "1" | "on" | "ON"));
    connection.close().unwrap();
    let mut reopened = open(&f.path("temporary.db"), Some(KEY), false);
    let count: i64 = transact(&mut reopened, |tx| {
        tx.query_row("SELECT count(*) FROM sqlite_temp_schema", [], |row| {
            row.get(0)
        })
        .map_err(Error::database)
    })
    .unwrap();
    assert_eq!(count, 0);
    reopened.close().unwrap();
}
