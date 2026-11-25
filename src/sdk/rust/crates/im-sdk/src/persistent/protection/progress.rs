//! 独立钥匙串进度：先预约、后SQL提交、再确认；最后一步前不允许密码计算或交付成功。
//! 仅抵御数据库单独回退；钥匙串与数据库共同回滚不在保证范围内。
use super::super::{data::Saved, store::digest, types::*};
use super::{keychain, Protection};
use serde::{Deserialize, Serialize};

const PURPOSE: &str = "org.rocket-im.sdk.backup-progress.v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    version: u32,
    binding: String,
    guard: String,
    head: String,
    next: Option<String>,
}
impl Protection {
    fn progress_record(&self) -> Result<Option<Progress>> {
        let bytes = match keychain::read(&self.keychain, PURPOSE, &self.item) {
            Ok(bytes) => bytes,
            Err(e) if e.code == "keychain_item_missing" => return Ok(None),
            Err(e) => return Err(e),
        };
        let record: Progress =
            decode(&bytes).map_err(|_| Error::paused("backup_progress_invalid"))?;
        if record.version != 1
            || record.binding != self.item
            || record.guard.len() != 64
            || record.head.len() != 64
            || record.next.as_ref().is_some_and(|h| h.len() != 64)
        {
            return Err(Error::paused("backup_progress_invalid"));
        }
        Ok(Some(record))
    }
    fn save_progress(&self, record: &Progress) -> Result<()> {
        keychain::replace(&self.keychain, PURPOSE, &self.item, &encode(record)?)
    }
    pub fn activate_progress(&self, before: &Saved, after: &Saved) -> Result<()> {
        if self.progress_record()?.is_some() {
            return Err(Error::paused("backup_activation_required"));
        }
        let record = Progress {
            version: 1,
            binding: self.item.clone(),
            guard: after
                .meta
                .backup_guard
                .clone()
                .ok_or_else(|| Error::paused("backup_progress_invalid"))?,
            head: digest(before)?,
            next: Some(digest(after)?),
        };
        keychain::add(&self.keychain, PURPOSE, &self.item, &encode(&record)?)?;
        super::super::checkpoint("backup_after_activation_reserve");
        Ok(())
    }
    /// 只续接首次备份已预约的同一个升级，不重新生成guard或允许普通写越过升级。
    pub fn resume_activation(&self, saved: &mut Saved) -> Result<bool> {
        if saved.meta.backup_guard.is_some() {
            return Ok(false);
        }
        let Some(record) = self.progress_record()? else {
            return Ok(false);
        };
        if digest(saved)? != record.head || record.next.is_none() {
            return Err(Error::paused("backup_progress_mismatch"));
        }
        saved.meta.backup_guard = Some(record.guard);
        if Some(digest(saved)?) != record.next {
            return Err(Error::paused("backup_progress_mismatch"));
        }
        Ok(true)
    }
    pub fn check_progress(&self, saved: &Saved) -> Result<()> {
        let Some(mut record) = self.progress_record()? else {
            return if saved.meta.backup_guard.is_none() {
                Ok(())
            } else {
                Err(Error::paused("backup_progress_missing"))
            };
        };
        if saved.meta.backup_guard.as_ref() != Some(&record.guard) {
            return Err(Error::paused("backup_progress_mismatch"));
        }
        let current = digest(saved)?;
        if current != record.head && record.next.as_ref() != Some(&current) {
            return Err(Error::paused("backup_progress_mismatch"));
        }
        if record.next.is_some() {
            record.head = current;
            record.next = None;
            self.save_progress(&record)?;
        }
        Ok(())
    }
    pub fn prepare_progress(&self, before: &Saved, after: &Saved) -> Result<()> {
        self.check_progress(before)?;
        if before.meta.backup_guard != after.meta.backup_guard {
            return Err(Error::paused("backup_progress_mismatch"));
        }
        let Some(mut record) = self.progress_record()? else {
            return Ok(());
        };
        let next = digest(after)?;
        if next != record.head {
            record.next = Some(next);
            self.save_progress(&record)?;
            super::super::checkpoint("backup_after_progress_reserve");
        }
        Ok(())
    }
    /// 缺失/损坏库不能推断未确认提交的结果，保留预约并明确拒绝。
    pub fn require_backup_head(&self, saved: &Saved) -> Result<()> {
        let record = self
            .progress_record()?
            .ok_or_else(|| Error::paused("backup_progress_missing"))?;
        if record.next.is_some() {
            return Err(Error::paused("backup_reconciliation_required"));
        }
        if saved.meta.backup_guard.as_ref() != Some(&record.guard) || digest(saved)? != record.head
        {
            return Err(Error::paused("backup_stale"));
        }
        Ok(())
    }
}
