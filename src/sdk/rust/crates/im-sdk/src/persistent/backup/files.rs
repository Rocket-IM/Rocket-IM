//! 备份文件只使用现有SQLCipher；元数据、原始候选及密码状态一起加密并验完整性。
use super::{
    super::{data::Saved, protection, store, types::*},
    Manifest,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
const BACKUP_APP: i64 = 0x52494231;
const MAX_FILE: u64 = 64 * 1024 * 1024;

pub(super) fn random_id() -> Result<String> {
    let mut random = [0; 32];
    getrandom::getrandom(&mut random).map_err(|_| Error::paused("random_unavailable"))?;
    Ok(hex(&random))
}
pub(super) fn validate_path(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("backup_path_invalid"))?;
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || fs::canonicalize(parent).ok().as_deref() != Some(parent)
        || path.extension().and_then(|v| v.to_str()) != Some("rimbackup")
        || fs::symlink_metadata(path).is_ok_and(|m| !m.is_file())
    {
        return Err(Error::new("backup_path_invalid"));
    }
    Ok(())
}
pub(super) struct Temporary(pub PathBuf);
impl Temporary {
    pub fn new(target: &Path, purpose: &str) -> Result<Self> {
        let path = target
            .parent()
            .ok_or_else(|| Error::new("backup_path_invalid"))?
            .join(format!(".rocket-{purpose}-{}.pending", random_id()?));
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| Error::new("backup_create_failed"))?;
        Ok(Self(path))
    }
    pub fn remove(&self) -> Result<()> {
        fs::remove_file(&self.0).map_err(|_| Error::new("backup_cleanup_failed"))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
pub(super) fn connection(path: &Path, key: &str, readonly: bool) -> Result<Connection> {
    let flags = if readonly {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    let connection = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    protection::install(&connection, key)?;
    connection.busy_timeout(std::time::Duration::from_millis(100))?;
    Ok(connection)
}
pub(super) fn write_backup(
    path: &Path,
    key: &str,
    saved: &Saved,
    manifest: &Manifest,
) -> Result<()> {
    let mut connection = connection(path, key, false)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(store::SCHEMA)?;
    tx.execute_batch("PRAGMA application_id=1380532785; PRAGMA user_version=1; CREATE TABLE backup_manifest(id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);")?;
    tx.execute(
        "INSERT INTO backup_manifest(id,value) VALUES(1,?1)",
        [encode(manifest)?],
    )?;
    store::write(&tx, saved)?;
    if saved.data.has_workset_history() {
        tx.execute_batch("PRAGMA user_version=4;")?;
    } else if saved.data.has_workset() {
        tx.execute_batch("PRAGMA user_version=3;")?;
    } else if saved.meta.reserve_version.is_some() {
        tx.execute_batch("PRAGMA user_version=2;")?;
    }
    #[cfg(feature = "persistent-test-hooks")]
    if std::env::var("ROCKET_IM_TEST_BACKUP_VERSION")
        .ok()
        .as_deref()
        == Some("5")
    {
        tx.execute_batch("PRAGMA user_version=5;")?;
    }
    tx.commit()?;
    drop(connection);
    if fs::metadata(path)
        .map_err(|_| Error::new("backup_io_failed"))?
        .len()
        > MAX_FILE
    {
        return Err(Error::new("backup_limit"));
    }
    Ok(())
}
pub(super) fn read(
    path: &Path,
    key: &str,
    database_path: &Path,
    scope: &Scope,
) -> Result<(Manifest, Saved)> {
    validate_path(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::new("backup_missing"))?;
    if metadata.len() == 0 || metadata.len() > MAX_FILE || metadata.len() % 4096 != 0 {
        return Err(Error::paused("backup_invalid"));
    }
    let result = (|| {
        let mut connection = connection(path, key, true)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let app: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if app != BACKUP_APP || !matches!(version, 1..=4) {
            return Err(Error::paused("backup_format_unsupported"));
        }
        let pages: i64 = tx.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        // SQLCipher在加密连接上覆盖SQLite的page_size，返回TEXT而不是INTEGER。
        let page_size: String = tx.query_row("PRAGMA cipher_page_size", [], |r| r.get(0))?;
        if pages <= 0
            || page_size != "4096"
            || pages.checked_mul(4096) != Some(metadata.len() as i64)
        {
            return Err(Error::paused("backup_invalid"));
        }
        let integrity: String = tx.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        let cipher_errors = tx
            .prepare("PRAGMA cipher_integrity_check")?
            .query([])?
            .next()?
            .is_some();
        let names: String = tx.query_row("SELECT group_concat(name, ',') FROM (SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name)", [], |r| r.get(0))?;
        let count: i64 = tx.query_row(
            "SELECT (SELECT count(*) FROM sdk_state)+(SELECT count(*) FROM backup_manifest)",
            [],
            |r| r.get(0),
        )?;
        if integrity != "ok" || cipher_errors || names != "backup_manifest,sdk_state" || count != 2
        {
            return Err(Error::paused("backup_invalid"));
        }
        let bytes: Vec<u8> =
            tx.query_row("SELECT value FROM backup_manifest WHERE id=1", [], |r| {
                r.get(0)
            })?;
        if bytes.len() > 16384 {
            return Err(Error::paused("backup_invalid"));
        }
        let manifest: Manifest = decode(&bytes)?;
        if manifest.info.format != version as u32 {
            return Err(Error::paused("backup_format_unsupported"));
        }
        if manifest.database_path != database_path || &manifest.info.scope != scope {
            return Err(Error::paused("backup_binding_mismatch"));
        }
        let saved = store::load(&tx, scope)?;
        if (version >= 2) != saved.meta.reserve_version.is_some()
            || (version >= 3) != saved.data.has_workset()
            || (version == 4) != saved.data.has_workset_history()
            || manifest.info.backup_id.len() != 64
            || manifest.info.snapshot != store::digest(&saved)?
            || manifest.info.revision != saved.data.state.revision
            || saved.meta.backup_guard.is_none()
        {
            return Err(Error::paused("backup_invalid"));
        }
        tx.commit()?;
        Ok((manifest, saved))
    })();
    result.map_err(|e: Error| {
        if matches!(e.code.as_str(), "storage_failure" | "store_invalid") {
            Error::paused("backup_invalid")
        } else {
            e
        }
    })
}
pub(super) fn sync_file(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::paused("backup_sync_failed"))
}
pub(super) fn sync_parent(path: &Path) -> Result<()> {
    sync_file(
        path.parent()
            .ok_or_else(|| Error::new("backup_path_invalid"))?,
    )
}
