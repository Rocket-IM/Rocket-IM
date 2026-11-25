//! 同机受控备份；系统秘密、最新进度与原规范路径均不在可回退的备份内。
mod files;
mod restore;
#[cfg(test)]
mod tests;
use super::{
    data::Saved,
    store::{self, Store},
    types::*,
    PersistentDevice,
};
use rusqlite::TransactionBehavior;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

/// 成功仅表示端侧完整快照已持久保存/安装；联网接受与送达仍由原网络同步核对。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupInfo {
    pub format: u32,
    pub backup_id: String,
    pub scope: Scope,
    pub revision: String,
    pub snapshot: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    info: BackupInfo,
    database_path: PathBuf,
}
impl PersistentDevice {
    /// 首次调用启用不可隐式撤销的本机进度保护（v3→v4），旧包随后拒绝此库。
    /// 目标为规范绝对路径的.rimbackup；相同路径和完整状态可精确重试。
    /// SQL读写与备份I/O由数据库线程执行；无网络等待。需先disconnect以取得稳定恢复点。
    pub fn create_backup(&self, path: PathBuf) -> Result<BackupInfo> {
        self.database.call(move |store| store.create_backup(path))
    }
    /// 仅原scope/路径/系统秘密且最新进度完全一致时安装。所有活实例必须先close。
    /// 在专属数据库线程校验/构造完整候选并原子切换，返回后须重新open/connect。
    pub fn restore_backup(
        path: PathBuf,
        scope: Scope,
        keychain: PathBuf,
        backup: PathBuf,
    ) -> Result<BackupInfo> {
        std::thread::Builder::new()
            .name("rocket-sdk-sqlite-restore".into())
            .spawn(move || restore::run(path, scope, keychain, backup))
            .map_err(|_| Error::paused("worker_start_failed"))?
            .join()
            .map_err(|_| Error::paused("worker_stopped"))?
    }
}
impl Store {
    fn enable_backup(&mut self) -> Result<Saved> {
        let p = self
            .protection
            .as_ref()
            .ok_or_else(|| Error::new("protection_required"))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut saved = store::load(&tx, &self.scope)?;
        p.check_progress(&saved)?;
        if saved.data.state.identity.is_none() {
            return Err(Error::new("initialize_required"));
        }
        if saved.meta.backup_guard.is_none() {
            let before = saved.clone();
            saved.meta.backup_guard = Some(files::random_id()?);
            // 外部预约先于可见库升级。崩溃后仅续接此准确候选。
            p.activate_progress(&before, &saved)?;
            tx.execute_batch("PRAGMA user_version=4;")?;
            store::write(&tx, &saved)?;
        }
        tx.commit()?;
        super::checkpoint("backup_after_activation_commit");
        p.check_progress(&saved)?;
        Ok(saved)
    }
    pub(super) fn create_backup(&mut self, path: PathBuf) -> Result<BackupInfo> {
        files::validate_path(&path)?;
        let saved = self.enable_backup()?;
        let p = self
            .protection
            .as_ref()
            .ok_or_else(|| Error::new("protection_required"))?;
        let key = p.encryption_key()?;
        let manifest = Manifest {
            info: BackupInfo {
                format: if saved.meta.reserve_version.is_some() {
                    2
                } else {
                    1
                },
                backup_id: files::random_id()?,
                scope: self.scope.clone(),
                revision: saved.data.state.revision.clone(),
                snapshot: store::digest(&saved)?,
            },
            database_path: p.database_path().to_path_buf(),
        };
        if path.exists() {
            let (existing, snapshot) = files::read(&path, &key, p.database_path(), &self.scope)?;
            if existing.info.snapshot != manifest.info.snapshot {
                return Err(Error::new("backup_exists"));
            }
            p.require_backup_head(&snapshot)?;
            files::sync_file(&path)?;
            files::sync_parent(&path)?;
            return Ok(existing.info);
        }
        let temp = files::Temporary::new(&path, "backup")?;
        files::write_backup(&temp.0, &key, &saved, &manifest)?;
        super::checkpoint("backup_after_snapshot_commit");
        files::sync_file(&temp.0)?;
        super::checkpoint("backup_after_snapshot_sync");
        p.check()?;
        p.require_backup_head(&saved)?;
        fs::hard_link(&temp.0, &path).map_err(|e| {
            Error::new(if e.kind() == std::io::ErrorKind::AlreadyExists {
                "backup_exists"
            } else {
                "backup_publish_failed"
            })
        })?;
        super::checkpoint("backup_after_publish");
        files::sync_parent(&path)?;
        // 临时副本是密文；只删除当前调用自己的临时文件，不处理旧进程残留。
        temp.remove()?;
        files::sync_parent(&path)?;
        super::checkpoint("backup_after_export_sync");
        Ok(manifest.info)
    }
}
