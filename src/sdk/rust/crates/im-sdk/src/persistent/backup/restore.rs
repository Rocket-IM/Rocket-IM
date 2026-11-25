//! 无活连接时安装完整候选；不会把过旧密码状态拼接到当前库。
use super::super::{data::Saved, protection::Protection, store, types::*};
use super::{files, BackupInfo};
use rusqlite::TransactionBehavior;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) fn read_current(path: &Path, key: &str, scope: &Scope) -> Result<Saved> {
    let mut connection = files::connection(path, key, false)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let app: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if app != store::APP_ID || !matches!(version, 4..=8) {
        return Err(Error::paused("store_format_unsupported"));
    }
    let names: String = tx.query_row(
        "SELECT group_concat(name, ',') FROM sqlite_schema WHERE type='table'",
        [],
        |r| r.get(0),
    )?;
    if names != "sdk_state" {
        return Err(Error::paused("backup_current_conflict"));
    }
    let current = store::load(&tx, scope)?;
    if (version >= 6) != current.meta.reserve_version.is_some()
        || (version >= 7) != current.data.has_workset()
        || (version == 8) != current.data.has_workset_history()
        || (version < 6 && (version == 5) != current.data.has_rejections())
        || current.meta.backup_guard.is_none()
    {
        return Err(Error::paused("store_invalid"));
    }
    tx.commit()?;
    Ok(current)
}

pub(super) fn run(
    path: PathBuf,
    scope: Scope,
    keychain: PathBuf,
    backup: PathBuf,
) -> Result<BackupInfo> {
    files::validate_path(&backup)?;
    let mut protection = Protection::locator(path.clone(), scope.clone(), keychain)?;
    let _lease = protection.lease(true)?;
    let _access = protection.lock()?;
    let key = protection.prepare(false)?;
    let (manifest, saved) = files::read(&backup, &key, &path, &scope)?;
    let mut valid_current = false;
    // 当前完整库可准确结清最后一次提交预约；损坏/缺失库不猜测结果。
    if path.exists() {
        let current = read_current(&path, &key, &scope);
        match current {
            Ok(current) => {
                protection.check_progress(&current)?;
                // 先验证备份是否过旧，再检查当前库，失败不覆盖任何完整状态。
                protection.require_backup_head(&saved)?;
                if store::digest(&current)? != manifest.info.snapshot {
                    return Err(Error::paused("backup_current_conflict"));
                }
                valid_current = true;
            }
            Err(e) if matches!(e.code.as_str(), "storage_failure" | "store_invalid") => {}
            Err(e) => return Err(e),
        }
    }
    protection.require_backup_head(&saved)?;
    let journal = PathBuf::from(format!("{}-journal", path.display()));
    if valid_current && journal.exists() {
        if !fs::symlink_metadata(&journal).is_ok_and(|m| m.is_file()) {
            return Err(Error::paused("backup_store_sidecar"));
        }
        // 提交前退出可能留下非热journal，SQLite只读打开不会删除它。
        // 仅在当前完整状态=备份=外部最新进度时，交由SQLite做同状态写事务并清理，
        // 不由宿主或文件操作猜测/删除journal，也不改变密码状态或业务修订。
        let mut connection = files::connection(&path, &key, false)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if store::digest(&store::load(&tx, &scope)?)? != manifest.info.snapshot {
            return Err(Error::paused("backup_current_conflict"));
        }
        tx.execute("DELETE FROM sdk_state WHERE id=1", [])?;
        store::write(&tx, &saved)?;
        tx.commit()?;
    }
    super::super::checkpoint("backup_after_import_validate");
    let temp = files::Temporary::new(&path, "restore")?;
    let mut connection = files::connection(&temp.0, &key, false)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(store::SCHEMA)?;
    tx.execute_batch("PRAGMA application_id=1380536369; PRAGMA user_version=4;")?;
    store::write(&tx, &saved)?;
    super::super::checkpoint("backup_before_import_commit");
    tx.commit()?;
    super::super::checkpoint("backup_after_import_commit");
    // 对真正构造的候选进行完整读取验证，不用写入输入假装验证持久结果。
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    if store::digest(&store::load(&tx, &scope)?)? != manifest.info.snapshot {
        return Err(Error::paused("backup_invalid"));
    }
    tx.commit()?;
    drop(connection);
    files::sync_file(&temp.0)?;
    super::super::checkpoint("backup_after_import_sync");
    protection.check()?;
    protection.require_backup_head(&saved)?;
    // 成功打开当前库已恢复其热journal；残留的未知侧文件不能施加到新inode。
    for suffix in ["-journal", "-wal", "-shm"] {
        let side = PathBuf::from(format!("{}{suffix}", path.display()));
        if side.exists() {
            return Err(Error::paused("backup_store_sidecar"));
        }
    }
    fs::rename(&temp.0, &path).map_err(|_| Error::paused("backup_install_failed"))?;
    super::super::checkpoint("backup_after_install");
    files::sync_parent(&path)?;
    super::super::checkpoint("backup_after_install_sync");
    protection.check()?;
    Ok(manifest.info)
}
