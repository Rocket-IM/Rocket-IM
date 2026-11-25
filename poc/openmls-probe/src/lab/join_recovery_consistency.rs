//! 恢复原件接入同一 Q02 门禁；缺链可补，已证实冲突不可由重试或新 head 清除。
use super::{
    consistency_state::{self as consistency, Status, MAX_EVIDENCE},
    ensure,
    join_recovery_evidence::{self as evidence, Fact, Observation},
    join_recovery_state as stored,
    state::DeviceState,
    LabError,
};
use crate::{join_recovery as p, permission::PermissionCheckpoint};
use serde_json::{json, Value};

fn conflicting(left: &PermissionCheckpoint, right: &PermissionCheckpoint) -> bool {
    left.authorization_version == right.authorization_version && left != right
}

fn terminal_conflict(left: &Fact, right: &Fact) -> bool {
    if left.receipt == right.receipt {
        return false;
    }
    let (l, r) = (&left.statement, &right.statement);
    l.recovery_id == r.recovery_id
        || l.change_id == r.change_id
        || (left.predecessor.is_some()
            && right.predecessor.is_some()
            && l.root_admission == r.root_admission
            && l.current_admission == r.current_admission)
}

pub(super) fn observe(state: &mut DeviceState, observation: Observation) -> Result<(), LabError> {
    evidence::verify(state, &observation)?;
    let s = state
        .join_recovery
        .get_or_insert_with(stored::State::default);
    if !s.observations.contains(&observation) {
        ensure(
            s.observations.len() < MAX_EVIDENCE,
            "resource_exhausted",
            "恢复观察证据达到上限",
        )?;
        s.observations.push(observation);
    }
    if state.witness_state.is_none() {
        state.version = 2;
    }
    refresh(state)?;
    stored::budget(stored::get(state)?)
}

pub(super) fn refresh(state: &mut DeviceState) -> Result<(), LabError> {
    let facts = evidence::facts(state)?;
    if facts.is_empty() {
        return Ok(());
    }
    let current = stored::checkpoint(state)?.clone();
    let mut known: Vec<_> = state
        .permissions
        .consistency
        .checkpoints
        .values()
        .cloned()
        .collect();
    known.push(current);
    known.extend(
        state
            .permissions
            .consistency
            .heads
            .iter()
            .map(|h| h.statement.checkpoint.clone()),
    );
    let mut conflict = false;
    for (index, fact) in facts.iter().enumerate() {
        conflict |= facts[..index]
            .iter()
            .any(|old| terminal_conflict(old, fact));
        for cp in fact
            .predecessor
            .iter()
            .chain(std::iter::once(&fact.checkpoint))
        {
            conflict |= known.iter().any(|old| conflicting(old, cp));
            known.push(cp.clone());
        }
        let stored = &mut state.permissions.consistency;
        if stored
            .highest_observed
            .as_ref()
            .map(consistency::version)
            .transpose()?
            .is_none_or(|v| consistency::version(&fact.checkpoint).is_ok_and(|next| next > v))
        {
            stored.highest_observed = Some(fact.checkpoint.clone());
        }
    }
    if conflict {
        state
            .permissions
            .consistency
            .pause(Status::ForkDetected, "recovery_evidence_conflict");
    }
    // 旧快照可能只有已关闭原件；加载后也不能遗忘其更高水位。
    let current_version = consistency::version(stored::checkpoint(state)?)?;
    if facts.iter().any(|f| {
        f.predecessor.is_none()
            && consistency::version(&f.checkpoint).is_ok_and(|v| v > current_version)
    }) {
        state.permissions.consistency.pause(
            Status::NeedsSync,
            "recovery_close_ahead_of_verified_checkpoint",
        );
    }
    Ok(())
}

pub(super) fn missing(state: &mut DeviceState) -> Value {
    state
        .permissions
        .consistency
        .pause(Status::NeedsSync, "recovery_chain_missing");
    paused(state)
}

pub(super) fn paused(state: &DeviceState) -> Value {
    json!({"state":"consistency_paused", "consistency":consistency::inspect(state)})
}

pub(super) fn forked(state: &DeviceState) -> bool {
    state.permissions.consistency.status == Status::ForkDetected
}

/// 按每个完整观察检查点核对，而非仅比较最大版本号或最新一条引用。
pub(super) fn reached(state: &DeviceState) -> Result<bool, LabError> {
    let current = stored::checkpoint(state)?;
    let version = consistency::version(current)?;
    for fact in evidence::facts(state)? {
        let v = consistency::version(&fact.checkpoint)?;
        if v > version || !covers(state, &fact.checkpoint)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// 已入群覆盖区间必须由真实 MLS 核对；入群前只能使用已经连续验证的公共链，
/// 它不会增加 MLS 索引，也不能绕过首次 Welcome/R1 的发送门禁。
pub(super) fn covers(state: &DeviceState, cp: &PermissionCheckpoint) -> Result<bool, LabError> {
    let v = consistency::version(cp)?;
    let index = &state.permissions.consistency.checkpoints;
    if index.get(&v) == Some(cp) {
        return Ok(true);
    }
    if state.group_id.is_some() && index.first_key_value().is_none_or(|(first, _)| v >= *first) {
        return Ok(false);
    }
    let Some(s) = &state.join_recovery else {
        return Ok(false);
    };
    if s.public_head.as_ref() == Some(cp) {
        return Ok(true);
    }
    for a in s.records.values() {
        let f = evidence::accepted(state, &a.record)?;
        if a.predecessor == *cp || f.checkpoint == *cp {
            return Ok(true);
        }
    }
    for a in s.public_advances.values() {
        let f = evidence::accepted(state, &p::Evidence::Public(a.record.clone()))?;
        if a.predecessor == *cp || f.checkpoint == *cp {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn close_floor(
    state: &mut DeviceState,
    checkpoint: &PermissionCheckpoint,
) -> Result<(), LabError> {
    let current = stored::checkpoint(state)?;
    let v = consistency::version(checkpoint)?;
    let current_v = consistency::version(current)?;
    let known = &state.permissions.consistency;
    let highest = known
        .highest_observed
        .as_ref()
        .map(consistency::version)
        .transpose()?
        .unwrap_or(current_v);
    if v < current_v || v < highest {
        state.permissions.consistency.pause(
            Status::RollbackDetected,
            "recovery_close_below_known_checkpoint",
        );
    } else if v > current_v {
        state.permissions.consistency.pause(
            Status::NeedsSync,
            "recovery_close_ahead_of_verified_checkpoint",
        );
    }
    Ok(())
}

pub(super) fn accepted_observation(record: &p::Evidence) -> Observation {
    Observation::Accepted {
        record: record.public(),
    }
}
