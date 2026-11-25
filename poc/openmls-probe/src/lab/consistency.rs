//! 挑战绑定的观察与显式恢复；合法的暂停结果必须返回 Ok 以提交证据。
use super::{
    checked,
    consistency_state::{
        self as stored, ForkEvidence, ForkRecord, HeadEvidence, Status, MAX_EVIDENCE,
    },
    ensure,
    state::DeviceState,
    LabError,
};
use crate::{
    consistency,
    permission::{
        self,
        receipts::{self, Outcome, SignedRecord},
        Identity, PermissionCheckpoint,
    },
};
use serde_json::{json, Value};

fn context(state: &DeviceState) -> Result<(&PermissionCheckpoint, &str), LabError> {
    let cp = super::join_recovery_state::checkpoint(state)
        .map_err(|_| LabError::new("consistency_unavailable", "需要已验证的本群检查点"))?;
    let key = super::join_recovery_state::key(state)
        .map_err(|_| LabError::new("consistency_unavailable", "需要初始固定的 Service 公钥"))?;
    ensure(
        super::join_recovery_consistency::covers(state, cp)?,
        "consistency_coverage",
        "本机当前检查点不在实际验证的覆盖范围内",
    )?;
    Ok((cp, key))
}

pub(super) fn challenge(state: &mut DeviceState) -> Result<Value, LabError> {
    let (cp, _) = context(state)?;
    let service_id = cp.service_id.clone();
    let conversation_id = cp.conversation_id.clone();
    if state.permissions.consistency.challenge.is_none() {
        ensure(
            state.permissions.consistency.heads.len() < MAX_EVIDENCE,
            "resource_exhausted",
            "观察证据达到上限",
        )?;
        let mut random = [0u8; 32];
        checked("random", getrandom::getrandom(&mut random))?;
        let challenge = random.iter().map(|byte| format!("{byte:02x}")).collect();
        state.permissions.consistency.challenge = Some(challenge);
    }
    Ok(
        json!({"service_id":service_id,"conversation_id":conversation_id,"challenge":state.permissions.consistency.challenge}),
    )
}

fn result(state: &DeviceState, duplicate: bool) -> Value {
    let mut result = stored::inspect(state);
    result["duplicate"] = json!(duplicate);
    result
}

pub(super) fn observe_head(
    state: &mut DeviceState,
    head: SignedRecord,
    resume: bool,
) -> Result<Value, LabError> {
    super::join_recovery_consistency::refresh(state)?;
    let (current, key) = context(state)?;
    let current = current.clone();
    let statement = consistency::verify(key, &head)?;
    ensure(
        statement.service_id == current.service_id
            && statement.conversation_id == current.conversation_id
            && statement.actor
                == (Identity {
                    account_id: state.context.account.clone(),
                    device_id: state.context.device.clone(),
                }),
        "consistency_context",
        "观察不属于本机、实例或会话",
    )?;
    let recovery_reached = super::join_recovery_consistency::reached(state)?;
    let heads_reached = state
        .permissions
        .consistency
        .heads
        .iter()
        .map(|h| super::join_recovery_consistency::covers(state, &h.statement.checkpoint))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .all(|covered| covered);
    let observed_reached = state
        .permissions
        .consistency
        .highest_observed
        .as_ref()
        .map(|cp| super::join_recovery_consistency::covers(state, cp))
        .transpose()?
        .unwrap_or(true);
    let stored = &mut state.permissions.consistency;
    if stored.heads.iter().any(|previous| previous.head == head) {
        return Ok(result(state, true));
    }
    ensure(
        stored.challenge.as_deref() == Some(&statement.challenge),
        "consistency_challenge_required",
        "观察没有绑定未消费的持久挑战",
    )?;
    if stored.heads.len() >= MAX_EVIDENCE {
        return Ok(stored::capacity_pause(state, "consistency_head_capacity"));
    }
    let cp = &statement.checkpoint;
    let version = stored::version(cp)?;
    let current_version = stored::version(&current)?;
    let highest_observed = stored
        .highest_observed
        .as_ref()
        .map(stored::version)
        .transpose()?
        .unwrap_or(current_version);
    let highest_verified = stored
        .checkpoints
        .last_key_value()
        .map(|(v, _)| *v)
        .unwrap_or(current_version);
    let highest = highest_observed.max(highest_verified);
    let conflict = stored
        .checkpoints
        .get(&version)
        .is_some_and(|known| known != cp)
        || stored.heads.iter().any(|known| {
            known.statement.checkpoint.authorization_version == cp.authorization_version
                && known.statement.checkpoint != *cp
        });
    if conflict {
        stored.pause(Status::ForkDetected, "observed_checkpoint_conflict");
    } else if version < current_version || version < highest {
        stored.pause(Status::RollbackDetected, "head_below_known_checkpoint");
    } else if version > current_version {
        stored.pause(Status::NeedsSync, "head_ahead_of_verified_checkpoint");
    }
    if stored
        .highest_observed
        .as_ref()
        .map(stored::version)
        .transpose()?
        .is_none_or(|known| version > known)
    {
        stored.highest_observed = Some(cp.clone());
    }
    // 显式恢复只清 Q02；正常权限候选、未完成意图和已移除状态不在此修改。
    let reached_floor = recovery_reached
        && heads_reached
        && observed_reached
        && current_version >= highest_verified
        && stored
            .highest_observed
            .as_ref()
            .is_some_and(|floor| stored::version(floor).is_ok_and(|v| v <= current_version));
    if resume
        && !matches!(
            stored.status,
            Status::ForkDetected | Status::EvidenceCapacityExhausted
        )
        && cp == &current
        && reached_floor
    {
        stored.status = Status::NoKnownConflict;
        stored.reason = None;
    }
    stored.heads.push(HeadEvidence { head, statement });
    stored.challenge = None;
    super::join_recovery_consistency::refresh(state)?;
    Ok(result(state, false))
}

pub(super) fn observe_fork(
    state: &mut DeviceState,
    evidence: ForkEvidence,
) -> Result<Value, LabError> {
    let (current, key) = context(state)?;
    evidence.predecessor.validate()?;
    ensure(
        evidence.predecessor.service_id == current.service_id
            && evidence.predecessor.conversation_id == current.conversation_id,
        "consistency_context",
        "分叉前驱属于其他范围",
    )?;
    ensure(
        state
            .permissions
            .consistency
            .checkpoints
            .get(&stored::version(&evidence.predecessor)?)
            == Some(&evidence.predecessor),
        "consistency_coverage",
        "分叉前驱不在本机可信完整检查点索引中",
    )?;
    let mut successors = Vec::with_capacity(2);
    for record in [&evidence.left, &evidence.right] {
        successors.push(match record {
            ForkRecord::Permission(record) => {
                let (receipt, _) = receipts::verify_receipt(key, record)?;
                ensure(
                    receipt.outcome == Outcome::Accepted,
                    "invalid_consistency",
                    "未接受提案或 closed 不构成分叉证据",
                )?;
                permission::verify(&evidence.predecessor, &record.change)?.0
            }
            ForkRecord::Recovery { recovery, root } => {
                let intent = crate::join_recovery::parse_intent(&recovery.bundle.intent)?;
                ensure(
                    state
                        .group_id
                        .as_ref()
                        .is_some_and(|id| super::codec::encode(id) == intent.scope.group_id),
                    "consistency_context",
                    "恢复分叉原件不属于本机群",
                )?;
                crate::join_recovery::accepted_public(&evidence.predecessor, root, key, recovery)?.0
            }
        });
    }
    ensure(
        successors[0] != successors[1],
        "invalid_consistency",
        "需要同一可信前驱的两个不同已接受后继",
    )?;
    let stored = &mut state.permissions.consistency;
    if stored.forks.iter().any(|previous| {
        previous == &evidence
            || (previous.predecessor == evidence.predecessor
                && previous.left == evidence.right
                && previous.right == evidence.left)
    }) {
        return Ok(result(state, true));
    }
    ensure(
        stored.challenge.is_some(),
        "consistency_challenge_required",
        "先持久化检查会话再导入分叉证据",
    )?;
    if stored.forks.len() >= MAX_EVIDENCE {
        return Ok(stored::capacity_pause(state, "consistency_fork_capacity"));
    }
    stored.forks.push(evidence);
    stored.pause(Status::ForkDetected, "accepted_successor_fork");
    stored.challenge = None;
    Ok(result(state, false))
}

pub(super) fn preflight(state: &DeviceState, operation: &super::Operation) -> Result<(), LabError> {
    use super::Operation;
    if matches!(operation, Operation::ConsistencyChallenge) {
        context(state)?;
        ensure(
            state.permissions.consistency.challenge.is_some()
                || state.permissions.consistency.heads.len() < MAX_EVIDENCE,
            "resource_exhausted",
            "观察证据达到上限",
        )?;
        return Ok(());
    }
    if !matches!(
        operation,
        Operation::ConsistencyObserveHead { .. }
            | Operation::ConsistencyResume { .. }
            | Operation::ConsistencyObserveFork { .. }
    ) {
        return Ok(());
    }
    let raw = checked("state_encoding", serde_json::to_vec(state))?;
    let mut metadata = checked("state_encoding", serde_json::from_slice(&raw))?;
    match operation {
        Operation::ConsistencyObserveHead { head } => {
            observe_head(&mut metadata, head.clone(), false)?;
        }
        Operation::ConsistencyResume { head } => {
            observe_head(&mut metadata, head.clone(), true)?;
        }
        Operation::ConsistencyObserveFork {
            predecessor,
            left,
            right,
        } => {
            observe_fork(
                &mut metadata,
                ForkEvidence {
                    predecessor: predecessor.clone(),
                    left: left.clone(),
                    right: right.clone(),
                },
            )?;
        }
        _ => {}
    }
    Ok(())
}
