//! 执行栅栏与完整候选分开持久化。Executing 无候选时绝不从旧密码快照重做。
use super::{
    data::{Data, Saved},
    operations,
    types::*,
    PersistentDevice,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Candidate {
    pub data: Data,
    pub crypto: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Reserved,
    Executing,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub request: String,
    pub input: Action,
    pub phase: Phase,
    pub seed: Option<Vec<u8>>,
    pub candidate: Option<Candidate>,
}
impl PersistentDevice {
    /// 显式恢复原请求；必须提供完全相同输入。无候选的已执行操作返回 successor_required。
    pub fn recover_request(&mut self, request_id: String, action: Action) -> Result<Outcome> {
        id(&request_id)?;
        action.validate()?;
        let saved = self.database.call(|db| db.read(Ok))?;
        let record = saved
            .data
            .requests
            .get(&request_id)
            .ok_or_else(|| Error::new("request_missing"))?;
        if !operations::matches_input(&record.hash, &action)? {
            return Err(Error::new("request_conflict"));
        }
        match &record.result {
            RequestState::Complete { outcome } => {
                let mut value = outcome.clone();
                value.cached = true;
                self.check_access()?;
                return Ok(value);
            }
            RequestState::Failed { error } => return Err(error.clone()),
            RequestState::Retired { .. } => return Err(Error::new("request_retired")),
            RequestState::Pending => {}
            _ => return Err(Error::paused("store_invalid")),
        }
        if saved.meta.journal.is_none() && record.input.is_none() {
            let base = operations::fingerprint(&saved)?;
            let mut next = saved.clone();
            next.data
                .requests
                .get_mut(&request_id)
                .ok_or_else(|| Error::paused("store_invalid"))?
                .input = Some(action);
            self.compare_write(base, next, false)?;
            return Err(Error::paused("successor_required"));
        }
        self.run_reserved(saved, &request_id)
    }
    pub(super) fn run_reserved(&mut self, saved: Saved, request: &str) -> Result<Outcome> {
        if saved.meta.blocks_operations() {
            return Err(Error::paused("recovery_active"));
        }
        let journal = saved
            .meta
            .journal
            .clone()
            .ok_or_else(|| Error::paused("successor_required"))?;
        if journal.request != request {
            return Err(Error::paused("reservation_changed"));
        }
        if journal.candidate.is_some() {
            return self.install_candidate(saved, request);
        }
        // 初始化 seed 从未导出过，投影身份不消耗任何群密码状态。
        if journal.phase == Phase::Executing && journal.seed.is_none() {
            return Err(Error::paused("successor_required"));
        }
        let base = operations::fingerprint(&saved)?;
        let mut executing = saved;
        executing
            .meta
            .journal
            .as_mut()
            .ok_or_else(|| Error::paused("store_invalid"))?
            .phase = Phase::Executing;
        let next = executing.clone();
        self.compare_write(base, next, false)?;
        super::checkpoint("after_begin");
        let base = operations::fingerprint(&executing)?;
        let result = super::candidate::apply(Box::new(executing.clone()), request, &journal.input);
        let (candidate, outcome) = match result {
            Ok(value) => value,
            Err(error) => {
                if !error.paused {
                    let mut failed = executing;
                    failed
                        .data
                        .requests
                        .get_mut(request)
                        .ok_or_else(|| Error::paused("store_invalid"))?
                        .result = RequestState::Failed {
                        error: error.clone(),
                    };
                    failed.data.state.pending_request = None;
                    failed.meta.journal = None;
                    self.compare_write(base, failed, false)?;
                }
                return Err(error);
            }
        };
        super::checkpoint("after_crypto");
        super::checkpoint("before_candidate");
        let mut staged = executing;
        staged
            .meta
            .journal
            .as_mut()
            .ok_or_else(|| Error::paused("store_invalid"))?
            .candidate = Some(Candidate {
            data: candidate.data,
            crypto: candidate.crypto,
        });
        self.compare_write(base, staged.clone(), false)
            .map_err(|e| protection_error(e, "candidate_unknown"))?;
        super::checkpoint("after_candidate");
        let installed = self.install_candidate(staged, request)?;
        debug_assert_eq!(installed, outcome);
        Ok(installed)
    }
    fn install_candidate(&mut self, saved: Saved, request: &str) -> Result<Outcome> {
        let base = operations::fingerprint(&saved)?;
        let candidate = saved
            .meta
            .journal
            .as_ref()
            .and_then(|j| j.candidate.clone())
            .ok_or_else(|| Error::paused("successor_required"))?;
        let RequestState::Complete { outcome } = &candidate
            .data
            .requests
            .get(request)
            .ok_or_else(|| Error::paused("store_invalid"))?
            .result
        else {
            return Err(Error::paused("store_invalid"));
        };
        let outcome = outcome.clone();
        let next = installed(&saved)?;
        self.compare_write(base, next, true)
            .map_err(|e| protection_error(e, "commit_unknown"))?;
        Ok(outcome)
    }
    pub(super) fn compare_write(&self, base: String, next: Saved, committing: bool) -> Result<()> {
        self.database.call(move |db| {
            db.update(committing, |s| {
                if operations::fingerprint(s)? != base {
                    return Err(Error::paused("reservation_changed"));
                }
                *s = next;
                Ok(())
            })
        })
    }
}

fn protection_error(error: Error, fallback: &str) -> Error {
    if error.code.starts_with("keychain_")
        || error.code.starts_with("protection_")
        || error.code == "logged_out"
    {
        error
    } else {
        Error::paused(fallback)
    }
}

/// 与真实安装共用完整状态转换；只移动已持久候选，不执行原密码输入。
pub(super) fn installed(saved: &Saved) -> Result<Saved> {
    let candidate = saved
        .meta
        .journal
        .as_ref()
        .and_then(|j| j.candidate.as_ref())
        .ok_or_else(|| Error::paused("successor_required"))?;
    let mut next = Saved {
        data: candidate.data.clone(),
        crypto: candidate.crypto.clone(),
        meta: saved.meta.clone(),
    };
    next.meta.journal = None;
    Ok(next)
}
