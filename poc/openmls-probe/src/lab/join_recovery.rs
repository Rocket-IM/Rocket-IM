//! 专用恢复入口：公开旧 Add 可进入恢复视图，但不产生任何旧 MLS/R1。
use super::{
    checked, codec, ensure, join_recovery_state as stored, state::DeviceState, CrashPoint,
    LabError, Operation,
};
use crate::{
    join_recovery as protocol,
    permission::{self, admission::JoinMaterial, receipts::RecoveryRecord},
};
use serde_json::{json, Value};
use stored::Command;

pub(super) fn now() -> Result<u64, LabError> {
    Ok(checked(
        "clock",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH),
    )?
    .as_secs())
}
pub(super) fn inspect(state: &DeviceState) -> Value {
    json!({"roots":state.join_recovery.as_ref().map(|s|s.roots.iter().map(|(id,r)|(id,&r.current)).collect::<std::collections::BTreeMap<_,_>>()),
        "pending":state.join_recovery.as_ref().and_then(|s|s.pending.as_ref().map(|p|&p.bundle)),
        "checkpoint":state.permissions.checkpoint,"public_head":state.join_recovery.as_ref().and_then(|s|s.public_head.as_ref()),
        "installed_count":state.join_recovery.as_ref().map_or(0,|s|s.records.values().filter(|r|r.installed).count())})
}
pub(super) fn preflight(state: &DeviceState, op: &Operation) -> Result<(), LabError> {
    #[cfg(feature = "key-package-probe")]
    if matches!(
        op,
        Operation::JoinRecoverySignProbe { .. }
            | Operation::JoinRecoveryChangeProbe { .. }
            | Operation::JoinRecoveryWitnessSignProbe { .. }
    ) {
        return Ok(());
    }
    let pending = state.join_recovery.as_ref().is_some_and(|s| {
        s.pending.is_some()
            || (state.group_id.is_some()
                && s.records.iter().any(|(id, r)| {
                    !r.installed && s.roots.values().any(|root| root.current.change_id == *id)
                }))
    });
    if pending
        && !matches!(
            op,
            Operation::JoinRecovery { .. }
                | Operation::Inspect
                | Operation::PermissionInspect
                | Operation::IdentityTrustInspect { .. }
                | Operation::IdentityTrustObserve { .. }
                | Operation::IdentityTrustPrepare {
                    purpose: crate::identity_trust::Purpose::Verify,
                    ..
                }
                | Operation::IdentityTrustConfirm { .. }
                | Operation::PermissionPinMember { .. }
                | Operation::WireInspect
                | Operation::ConsistencyInspect
                | Operation::ConsistencyChallenge
                | Operation::ConsistencyObserveHead { .. }
                | Operation::ConsistencyObserveFork { .. }
                | Operation::ConsistencyResume { .. }
                | Operation::AnchorInspect
                | Operation::AnchorResume
                | Operation::WireAccept { .. }
                | Operation::WireClose { .. }
                | Operation::WireCloseRequest { .. }
                | Operation::WireReject { .. }
        )
    {
        return Err(LabError::new(
            "recovery_pending",
            "恢复候选结果未知，先查询原件或验证关闭",
        ));
    }
    let Operation::JoinRecovery { command } = op else {
        return Ok(());
    };
    if !matches!(
        command,
        Command::Inspect
            | Command::WitnessInspect
            | Command::Resolve { .. }
            | Command::Observe { .. }
            | Command::WitnessObserve { .. }
    ) {
        ensure(
            !state.permissions.recovery.access_removed
                && state.permissions.pending.is_none()
                && state.permissions.recovery.intent.is_none(),
            "permission_pending",
            "原权限操作尚未确定或已移除",
        )?;
    }
    if let Command::Sign { request, intent } = command {
        super::join_recovery_request::check(state, request, intent.as_ref())?;
    }
    if let Command::Apply { record } = command {
        super::join_recovery_preflight::check(state, record)?;
    }
    if let Command::Prepare {
        intent,
        claim,
        allocation,
        key_package,
    } = command
    {
        super::join_recovery_mls::check(state, intent, claim, allocation, key_package)?;
    }
    super::join_recovery_witness::preflight(state, command)?;
    if matches!(
        command,
        Command::Root { .. }
            | Command::Advance { .. }
            | Command::AdvancePublic { .. }
            | Command::Observe { .. }
            | Command::WitnessObserve { .. }
            | Command::Resolve { .. }
    ) {
        // 元数据上预演公共校验；不会恢复 provider，也不会安装 MLS 或发出成功。
        let raw = checked("recovery_encoding", serde_json::to_vec(state))?;
        let mut metadata: DeviceState = checked("recovery_encoding", serde_json::from_slice(&raw))?;
        let command = checked(
            "recovery_encoding",
            serde_json::from_slice(&checked("recovery_encoding", serde_json::to_vec(command))?),
        )?;
        execute(&mut metadata, command, CrashPoint::None)?;
    }
    Ok(())
}
pub(super) fn execute(
    state: &mut DeviceState,
    command: Command,
    point: CrashPoint,
) -> Result<Value, LabError> {
    match command {
        Command::WitnessActivate => super::join_recovery_witness_config::activate(state),
        Command::WitnessRequest {
            record,
            request_id,
            ttl,
        } => super::join_recovery_witness::request(state, record, request_id, ttl),
        Command::WitnessRespond { record, request } => {
            super::join_recovery_witness_response::respond(state, record, request)
        }
        Command::WitnessApply {
            record,
            request,
            delivery,
        } => super::join_recovery_witness_apply::apply(state, record, request, delivery, point),
        Command::WitnessObserve { delivery } => {
            super::join_recovery_witness_evidence::observe(state, delivery)
        }
        Command::WitnessCancel { request_id } => {
            super::join_recovery_witness::cancel(state, request_id)
        }
        Command::WitnessInspect => Ok(super::join_recovery_witness::inspect(state)),
        Command::Root { record, join } => root(state, record, join),
        Command::Advance { record } => advance(state, record),
        Command::AdvancePublic { record } => {
            super::join_recovery_capacity::accept(state, |candidate| {
                super::join_recovery_public::advance(candidate, record)
            })
        }
        Command::Sign { request, intent } => {
            super::join_recovery_request::sign(state, request, intent)
        }
        Command::Prepare {
            intent,
            claim,
            allocation,
            key_package,
        } => super::join_recovery_mls::prepare(state, intent, claim, allocation, key_package),
        Command::Observe { record } => {
            super::join_recovery_capacity::accept(state, |candidate| observe(candidate, record))
        }
        Command::Apply { record } => super::join_recovery_apply::apply(state, record, point),
        Command::Resolve { intent, receipt } => {
            super::join_recovery_capacity::accept(state, |candidate| {
                super::join_recovery_request::resolve(candidate, intent, receipt)
            })
        }
        Command::Inspect => Ok(inspect(state)),
    }
}
fn root(
    state: &mut DeviceState,
    record: RecoveryRecord,
    join: JoinMaterial,
) -> Result<Value, LabError> {
    let key = stored::key(state)?.to_owned();
    let (reference, target, _, _) = protocol::root(&record, &key)?;
    if let Some(old) = state
        .join_recovery
        .as_ref()
        .and_then(|s| s.roots.get(&reference.change_id))
    {
        ensure(
            old.record == record && old.join == join,
            "idempotency_conflict",
            "原接受不可改变",
        )?;
        return Ok(json!({"reference":reference,"duplicate":true}));
    }
    let statement = permission::Statement::parse(&codec::decode(&record.change.statement_bytes)?)?;
    permission::admission::verify_binding(&statement, &join)?;
    let allocation = join
        .allocation
        .as_ref()
        .ok_or_else(|| LabError::new("recovery_invalid", "缺少原分配"))?;
    crate::key_package::verify_receipt(&key, &allocation.receipt)?;
    let cp = if state.group_id.is_none() {
        ensure(
            target == super::key_package_state::own(state),
            "permission_denied",
            "无群目标只能投影自身旧 Add",
        )?;
        let pool = state
            .key_packages
            .as_ref()
            .ok_or_else(|| LabError::new("key_package_missing", "缺少原材料账本"))?;
        ensure(
            pool.packages
                .values()
                .any(|p| p.encoded == join.key_package && !p.consumed),
            "key_package_missing",
            "原材料缺失或已经消费",
        )?;
        let (next, statement) = super::permission_join::verify_next(state, &record)?;
        state.permissions.used_nonces.insert(statement.nonce);
        state
            .permissions
            .admission
            .public_records
            .insert(statement.change_id, record.clone());
        state
            .permissions
            .admission
            .anchor
            .as_mut()
            .ok_or_else(|| LabError::new("trust_required", "缺少独立锚"))?
            .checkpoint = next.clone();
        next
    } else {
        ensure(
            state.permissions.recovery.records.get(&reference.change_id) == Some(&record),
            "recovery_chain_missing",
            "原 Add 尚未实际补链",
        )?;
        stored::checkpoint(state)?.clone()
    };
    if state.join_recovery.is_none() {
        state.join_recovery = Some(stored::State::default());
        if state.witness_state.is_none() {
            state.version = 2;
        }
    }
    let s = stored::get_mut(state)?;
    s.public_head = Some(cp);
    s.roots.insert(
        reference.change_id.clone(),
        stored::Root {
            record,
            join: join.clone(),
            current: reference.clone(),
            package_sha256: permission::commit_digest(&codec::decode(&join.key_package)?),
        },
    );
    stored::budget(s)?;
    Ok(json!({"reference":reference,"duplicate":false}))
}
fn advance(state: &mut DeviceState, record: RecoveryRecord) -> Result<Value, LabError> {
    ensure(
        state.group_id.is_none(),
        "already_grouped",
        "幸存者必须应用真实 Commit",
    )?;
    let (receipt, statement) = permission::receipts::verify_receipt(stored::key(state)?, &record)?;
    ensure(
        receipt.outcome == permission::receipts::Outcome::Accepted,
        "recovery_invalid",
        "公共链必须已接受",
    )?;
    if let Some(old) = state
        .permissions
        .admission
        .public_records
        .get(&statement.change_id)
    {
        ensure(old == &record, "receipt_conflict", "历史原件冲突")?;
        return Ok(json!({"duplicate":true}));
    }
    let (next, statement) = permission::verify(stored::checkpoint(state)?, &record.change)?;
    ensure(
        !state.permissions.used_nonces.contains(&statement.nonce),
        "permission_replay",
        "nonce 已使用",
    )?;
    // 缺少 Add 的独立身份事实时沿原门禁拒绝；旧自己 Add 只允许 Root 入口。
    if matches!(
        statement.action,
        permission::Action::AddMember { .. } | permission::Action::AddDevice { .. }
    ) {
        super::permission_admission::check_new_member(state, &statement.action)?;
    }
    state.permissions.used_nonces.insert(statement.nonce);
    state
        .permissions
        .admission
        .public_records
        .insert(statement.change_id, record);
    stored::get_mut(state)?.public_head = Some(next.clone());
    state
        .permissions
        .admission
        .anchor
        .as_mut()
        .ok_or_else(|| LabError::new("trust_required", "缺少锚"))?
        .checkpoint = next;
    Ok(json!({"duplicate":false}))
}
pub(super) fn observe(
    state: &mut DeviceState,
    record: protocol::Evidence,
) -> Result<Value, LabError> {
    let public = record.public();
    let i = protocol::parse_intent(&public.bundle.intent)?;
    if let Some(reference) = &i.policy_ref {
        let envelope = super::join_recovery_witness_state::policy(state, reference)?;
        protocol::witness::validate_intent_policy(&i, envelope)?;
        super::join_recovery_witness_config::pin(state, &i)?;
    }
    let fact = super::join_recovery_evidence::accepted(state, &record)?;
    super::join_recovery_consistency::observe(
        state,
        super::join_recovery_consistency::accepted_observation(&record),
    )?;
    if super::join_recovery_consistency::forked(state) {
        return Ok(super::join_recovery_consistency::paused(state));
    }
    let s = stored::get(state)?;
    if let Some(old) = s.records.get(&i.change_id) {
        ensure(
            old.record.public() == record.public(),
            "receipt_conflict",
            "同 ID 恢复原件冲突",
        )?;
        if let (Some(previous), Some(next)) = (old.record.full(), record.full()) {
            ensure(
                previous == next,
                "idempotency_conflict",
                "完整恢复材料不可改变",
            )?;
        }
        if old.record.full().is_none() && record.full().is_some() {
            let root = s
                .roots
                .get(&i.root_admission.change_id)
                .ok_or_else(|| LabError::new("recovery_chain_missing", "根缺失"))?;
            protocol::accepted_evidence(
                &old.predecessor,
                &root.record,
                stored::key(state)?,
                &record,
            )?;
            stored::get_mut(state)?
                .records
                .get_mut(&i.change_id)
                .ok_or_else(|| LabError::new("recovery_state", "记录缺失"))?
                .record = record;
            return Ok(json!({"duplicate":false,"material_attached":true}));
        }
        return Ok(json!({"duplicate":true,"installed":old.installed}));
    }
    let root = s
        .roots
        .get(&i.root_admission.change_id)
        .ok_or_else(|| LabError::new("recovery_chain_missing", "尚无原接受入口"))?;
    let cp = stored::checkpoint(state)?.clone();
    if root.current != i.current_admission || fact.predecessor.as_ref() != Some(&cp) {
        return Ok(super::join_recovery_consistency::missing(state));
    }
    let (next, statement, _) =
        protocol::accepted_evidence(&cp, &root.record, stored::key(state)?, &record)?;
    ensure(
        !state.permissions.used_nonces.contains(&statement.nonce),
        "permission_replay",
        "nonce 已使用",
    )?;
    let own_target = i.signer == super::key_package_state::own(state);
    if own_target {
        ensure(
            state.group_id.is_none(),
            "already_grouped",
            "禁止覆盖健康群",
        )?;
    }
    let current = protocol::admission_ref(&i.change_id, &public.bundle.change, &public.receipt)?;
    let s = stored::get_mut(state)?;
    let root = s
        .roots
        .get_mut(&i.root_admission.change_id)
        .ok_or_else(|| LabError::new("recovery_chain_missing", "缺少根"))?;
    root.current = current;
    root.package_sha256 = i.key_package_sha256.clone();
    if own_target {
        s.public_head = Some(next);
    }
    s.records.insert(
        i.change_id,
        stored::Accepted {
            predecessor: cp,
            record,
            installed: false,
        },
    );
    stored::budget(s)?;
    Ok(json!({"duplicate":false,"installed":false}))
}
