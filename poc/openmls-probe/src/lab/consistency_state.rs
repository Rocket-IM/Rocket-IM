//! Q02 证据与实际验证的检查点同快照保存，容量满时不淘汰证据。
use super::{checked, ensure, permission_state, state::DeviceState, LabError, Operation};
use crate::{
    consistency::HeadStatement,
    permission::{
        receipts::{RecoveryRecord, SignedRecord},
        PermissionCheckpoint,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) const MAX_CHECKPOINTS: usize = 4096;
pub(super) const MAX_EVIDENCE: usize = 128;

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    #[default]
    NoKnownConflict,
    RollbackDetected,
    NeedsSync,
    ForkDetected,
}

#[derive(Serialize, Deserialize)]
pub(super) struct HeadEvidence {
    pub head: SignedRecord,
    pub statement: HeadStatement,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ForkEvidence {
    pub predecessor: PermissionCheckpoint,
    pub left: RecoveryRecord,
    pub right: RecoveryRecord,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct ConsistencyState {
    // Some 同时表示已持久检查闸；不存在可与 challenge 矛盾的 checking 标记。
    pub challenge: Option<String>,
    pub status: Status,
    pub reason: Option<String>,
    pub coverage_from: Option<String>,
    pub checkpoints: BTreeMap<u64, PermissionCheckpoint>,
    pub highest_observed: Option<PermissionCheckpoint>,
    pub heads: Vec<HeadEvidence>,
    pub forks: Vec<ForkEvidence>,
    pub checkpoint_conflicts: Vec<PermissionCheckpoint>,
}

impl ConsistencyState {
    pub fn pause(&mut self, status: Status, reason: &str) {
        if self.status != Status::ForkDetected {
            self.status = status;
            self.reason = Some(reason.into());
        }
    }
    pub fn paused(&self) -> bool {
        self.challenge.is_some() || self.status != Status::NoKnownConflict
    }
}

pub(super) fn version(cp: &PermissionCheckpoint) -> Result<u64, LabError> {
    Ok(crate::permission::types::decimal(
        &cp.authorization_version,
    )?)
}

/// 只读取当前真正生效的 MLS；公开入群链和 Service 观察均不调用它造历史。
/// 加载旧快照后第一次成功保存只建立当前覆盖起点，不倒推已遗失的检查点。
pub(super) fn record_current(state: &mut DeviceState) -> Result<(), LabError> {
    if state.permissions.recovery.relay_receipt_key.is_none()
        || state.permissions.recovery.access_removed
    {
        return Ok(());
    }
    let Some(cp) = state.permissions.checkpoint.clone() else {
        return Ok(());
    };
    permission_state::validate_current(state, &cp, &state.group()?)?;
    let version = version(&cp)?;
    let stored = &mut state.permissions.consistency;
    if let Some(previous) = stored.checkpoints.get(&version) {
        if previous != &cp {
            if !stored.checkpoint_conflicts.contains(&cp) {
                ensure(
                    stored.checkpoint_conflicts.len() < MAX_EVIDENCE,
                    "resource_exhausted",
                    "检查点冲突证据达到上限",
                )?;
                stored.checkpoint_conflicts.push(cp.clone());
            }
            stored.pause(Status::ForkDetected, "verified_checkpoint_conflict");
        }
    } else {
        ensure(
            stored.checkpoints.len() < MAX_CHECKPOINTS,
            "resource_exhausted",
            "可信检查点索引达到上限",
        )?;
        if stored.coverage_from.is_none() {
            stored.coverage_from = Some(cp.authorization_version.clone());
        }
        stored.checkpoints.insert(version, cp.clone());
    }
    if stored.heads.iter().any(|head| {
        head.statement.checkpoint.authorization_version == cp.authorization_version
            && head.statement.checkpoint != cp
    }) {
        stored.pause(Status::ForkDetected, "observed_checkpoint_conflict");
    } else if stored
        .checkpoints
        .last_key_value()
        .is_some_and(|(latest, _)| version < *latest)
    {
        stored.pause(Status::RollbackDetected, "local_checkpoint_below_verified");
    }
    Ok(())
}

/// 先于缓存和业务动作发现局部回退；只有独立验证成立的冲突才请求立即提交。
/// 新迁移索引仍由普通成功保存建立，不能因普通坏请求改变旧快照。
pub(super) fn preflight(state: &mut DeviceState) -> Result<bool, LabError> {
    if state.permissions.recovery.relay_receipt_key.is_none()
        || state.permissions.recovery.access_removed
    {
        return Ok(false);
    }
    let Some(cp) = state.permissions.checkpoint.as_ref() else {
        return Ok(false);
    };
    let version = version(cp)?;
    let stored = &state.permissions.consistency;
    let mismatch = stored
        .checkpoints
        .get(&version)
        .is_some_and(|known| known != cp)
        || stored
            .checkpoints
            .last_key_value()
            .is_some_and(|(latest, _)| version < *latest)
        || stored.heads.iter().any(|head| {
            head.statement.checkpoint.authorization_version == cp.authorization_version
                && head.statement.checkpoint != *cp
        });
    if !mismatch {
        return Ok(false);
    }
    let before = checked("state_encoding", serde_json::to_vec(stored))?;
    record_current(state)?;
    Ok(before
        != checked(
            "state_encoding",
            serde_json::to_vec(&state.permissions.consistency),
        )?)
}

pub(super) fn guard(state: &DeviceState, operation: &Operation) -> Result<(), LabError> {
    if !state.permissions.consistency.paused() {
        return Ok(());
    }
    ensure(
        matches!(
            operation,
            Operation::Inspect
                | Operation::WireInspect
                | Operation::WireReadPending
                | Operation::WireReadInspect
                | Operation::WireSlotInspect { .. }
                | Operation::PermissionInspect
                | Operation::HistoryInspect
                | Operation::ConsistencyInspect
                | Operation::ConsistencyExchangeBegin { .. }
                | Operation::ConsistencyExchangeExport { .. }
                | Operation::ConsistencyExchangeImport { .. }
                | Operation::ConsistencyExchangeCancel
                | Operation::ConsistencyExchangeInspect
                | Operation::ConsistencyChallenge
                | Operation::ConsistencyObserveHead { .. }
                | Operation::ConsistencyObserveFork { .. }
                | Operation::ConsistencyResume { .. }
                | Operation::WireAccept { .. }
                | Operation::WireCloseRequest { .. }
                | Operation::WireClose { .. }
                | Operation::WireReject { .. }
                | Operation::WireReceive { .. }
                | Operation::WireDownload { .. }
                | Operation::WireDownloadSigned { .. }
                | Operation::WireProcess
                | Operation::PermissionRecover { .. }
                | Operation::PermissionCloseRequest
                | Operation::HistoryCancel { .. }
        ),
        "consistency_paused",
        "一致性检查中或已发现冲突，暂停新密码输出；须验证证据并显式恢复",
    )
}

pub(super) fn inspect(state: &DeviceState) -> Value {
    let stored = &state.permissions.consistency;
    json!({"status":stored.status,"reason":stored.reason,"freshness":"unknown",
        "checking":stored.challenge.is_some(),"paused":stored.paused(),"challenge":stored.challenge,
        "coverage_from":stored.coverage_from,"verified_checkpoint_count":stored.checkpoints.len(),
        "highest_observed_checkpoint":stored.highest_observed,"head_evidence_count":stored.heads.len(),
        "fork_evidence_count":stored.forks.len(),"checkpoint_conflict_count":stored.checkpoint_conflicts.len()})
}
