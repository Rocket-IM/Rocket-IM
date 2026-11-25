//! Apply 的确定性元数据拒绝先于独立锚预约；不恢复 provider 或执行 MLS。
use super::{ensure, join_recovery_state as stored, state::DeviceState, LabError};
use crate::{join_recovery as p, permission::PermissionCheckpoint};

pub(super) struct Ready {
    pub change_id: String,
    pub previous: PermissionCheckpoint,
    pub next: PermissionCheckpoint,
    pub statement: p::Statement,
    pub own_target: bool,
}

pub(super) fn check(state: &DeviceState, record: &p::Evidence) -> Result<Option<Ready>, LabError> {
    check_inner(state, record, false)
}
pub(super) fn check_witness(
    state: &DeviceState,
    record: &p::Evidence,
) -> Result<Option<Ready>, LabError> {
    check_inner(state, record, true).map_err(|e| {
        let code = match e.code {
            "recovery_superseded" | "recovery_predecessor_changed" => "w1_superseded",
            "already_grouped" => "w1_already_grouped",
            "key_package_expired" => "w1_material_expired",
            _ => return e,
        };
        LabError::new(code, format!("{}: {}", e.code, e.message))
    })
}
fn check_inner(
    state: &DeviceState,
    record: &p::Evidence,
    witness_authorized: bool,
) -> Result<Option<Ready>, LabError> {
    let public = record.public();
    let i = p::parse_intent(&public.bundle.intent)?;
    let stored = stored::get(state)?;
    let observed = stored.records.get(&i.change_id).ok_or_else(|| {
        LabError::new(
            "recovery_observe_required",
            "先持久保存并验证 R0 原件，再安装 MLS",
        )
    })?;
    ensure(
        observed.record.public() == public,
        "receipt_conflict",
        "已观察的接受原件不匹配",
    )?;
    if let (Some(old), Some(new)) = (observed.record.full(), record.full()) {
        ensure(
            old == new,
            "idempotency_conflict",
            "完整接受材料只能按原字节重试",
        )?;
    }
    if observed.installed {
        return Ok(None);
    }
    let root = stored
        .roots
        .get(&i.root_admission.change_id)
        .ok_or_else(|| LabError::new("recovery_chain_missing", "根缺失"))?;
    ensure(
        root.current == p::admission_ref(&i.change_id, &public.bundle.change, &public.receipt)?,
        "recovery_superseded",
        "恢复已被更晚端点替代",
    )?;
    let previous = observed.predecessor.clone();
    let (next, s, _) = p::accepted_evidence(&previous, &root.record, stored::key(state)?, record)?;
    super::join_recovery_request::trusted_members(state)?;
    let own_target = i.signer == super::key_package_state::own(state);
    if own_target && state.witness_state.is_some() {
        ensure(
            i.policy_ref.is_some(),
            "w1_policy_upgrade_required",
            "旧接受仅保留原件，禁止首次安装旧 Welcome",
        )?;
        ensure(
            witness_authorized,
            "w1_witness_not_installed",
            "首次安装必须通过当前见证门禁",
        )?;
    }
    if let Some(reference) = &i.policy_ref {
        let envelope = super::join_recovery_witness_state::policy(state, reference)?;
        p::witness::validate_intent_policy(&i, envelope)?;
    }
    if own_target {
        ensure(
            stored.public_head.as_ref() == Some(&next),
            "recovery_predecessor_changed",
            "必须处理已知更高链，不能安装旧 Welcome",
        )?;
    } else {
        ensure(
            state.permissions.checkpoint.as_ref() == Some(&previous),
            "recovery_predecessor_changed",
            "缺少准确实际前驱",
        )?;
    }
    if own_target {
        let full = record.full().ok_or_else(|| {
            LabError::new("recovery_material_required", "目标准确 Welcome 尚未读取")
        })?;
        ensure(
            state.group_id.is_none() && state.permissions.admission.joined_record.is_none(),
            "already_grouped",
            "禁止覆盖现有健康群",
        )?;
        let package = state
            .key_packages
            .as_ref()
            .and_then(|pool| pool.packages.get(&s.action.key_package_sha256))
            .ok_or_else(|| LabError::new("key_package_missing", "本机缺少新 bundle"))?;
        ensure(
            !package.consumed && package.encoded == full.bundle.key_package,
            "key_package_consumed",
            "材料已消费或不匹配",
        )?;
        crate::key_package::material::current(&package.material, super::join_recovery::now()?)?;
    } else if let Some(pending) = &stored.pending {
        ensure(
            p::PublicBundle::from(&pending.bundle) == public.bundle,
            "pending_conflict",
            "未决候选不匹配",
        )?;
    } else {
        ensure(
            s.actor != super::key_package_state::own(state),
            "recovery_candidate_missing",
            "本机发送者缺少原候选，不能重做",
        )?;
    }
    Ok(Some(Ready {
        change_id: i.change_id,
        previous,
        next,
        statement: s,
        own_target,
    }))
}
