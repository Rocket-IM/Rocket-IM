//! 候选保护项绑定新路径/设备与旧配置指纹；失去旧固定信任时不能只靠新库继续。
use super::*;
use crate::protection::Guard;

impl RebuildClient {
    /// 旧可信配置先由钥匙串核验；新候选从初始slot起加密且持续依赖旧固定信任。
    pub fn open_protected(
        old_path: PathBuf,
        old_locator: &str,
        path: PathBuf,
        new_locator: &str,
        device: &str,
    ) -> Result<Self> {
        validate_paths(&old_path, &path, device)?;
        let old = AnchoredClient::open_protected(old_path, old_locator)?;
        let mut this = Self::from_old(old, path, device)?;
        this.new_locator = Some(new_locator.into());
        if this.path.exists() {
            this.load_candidate(None)?;
        }
        Ok(this)
    }

    pub(super) fn open_candidate_database(&self, slot: Option<State>) -> Result<Database> {
        if let Some(locator) = &self.new_locator {
            let parent = self
                .old
                .inner
                .database
                .protection()
                .ok_or_else(|| error("protection_required"))?;
            parent.check()?;
            let purpose = Some(self.input.clone());
            let guard = if slot.is_some() {
                Guard::create(&self.path, &self.scope, locator, purpose)?
            } else {
                Guard::open(&self.path, &self.scope, locator, purpose)?
            }
            .with_parent(parent);
            return Database::open_protected_rebuild(
                self.path.clone(),
                self.scope.clone(),
                self.old.remote.clone(),
                slot,
                guard,
            );
        }
        Database::open_rebuild(
            self.path.clone(),
            self.scope.clone(),
            self.old.remote.clone(),
            slot,
        )
    }
}
