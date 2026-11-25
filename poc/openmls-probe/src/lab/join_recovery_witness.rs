//! W1 操作沿原恢复与独立锚入口提交；挑战待见证状态不由 Q02 resume 清除。
use super::{
    checked, ensure, join_recovery_state as recovery, join_recovery_witness_config as config,
    join_recovery_witness_state as stored, state::DeviceState, LabError,
};
use crate::join_recovery::{self as p, witness as w};
use serde_json::{json, Value};

pub(super) fn inspect(state: &DeviceState) -> Value {
    json!({"version":state.version,"witness_state":state.witness_state,
        "waiting_for_witness":state.witness_state.as_ref().is_some_and(|s|s.challenges.values().any(|c|c.status == stored::ChallengeStatus::Active))})
}
pub(super) fn context(
    state: &DeviceState,
    record: &p::PublicRecord,
) -> Result<(p::Intent, p::Statement), LabError> {
    let i = p::parse_intent(&record.bundle.intent)?;
    let observed = recovery::get(state)?
        .records
        .get(&i.change_id)
        .ok_or_else(|| LabError::new("recovery_observe_required", "先保存准确 R0"))?;
    ensure(
        observed.record.public() == *record,
        "w1_binding_mismatch",
        "见证必须绑定本机已验证的准确接受原件",
    )?;
    let root = recovery::get(state)?
        .roots
        .get(&i.root_admission.change_id)
        .ok_or_else(|| LabError::new("recovery_chain_missing", "缺原入口"))?;
    let (_, s, _) = p::accepted_evidence(
        &observed.predecessor,
        &root.record,
        recovery::key(state)?,
        &p::Evidence::Public(record.clone()),
    )?;
    Ok((i, s))
}
pub(super) fn binding(
    r: &w::WitnessRequest,
    i: &p::Intent,
    s: &p::Statement,
    record: &p::PublicRecord,
) -> Result<(), LabError> {
    ensure(
        r.scope == i.scope
            && r.actor == i.actor
            && r.target == i.signer
            && r.root_admission == i.root_admission
            && r.current_admission == i.current_admission
            && r.recovery_id == i.request_id
            && r.change_id == i.change_id
            && Some(&r.policy_ref) == i.policy_ref.as_ref()
            && r.accepted_ref
                == p::admission_ref(&i.change_id, &record.bundle.change, &record.receipt)?
            && r.commit_sha256 == s.commit_sha256
            && r.welcome_sha256 == s.action.welcome_sha256
            && r.key_package_sha256 == i.key_package_sha256
            && r.key_package_ref == s.action.key_package_ref,
        "w1_binding_mismatch",
        "请求未逐项绑定准确接受与材料原件",
    )
}
pub(super) fn live(start: &str, end: &str) -> Result<(), LabError> {
    let now = super::join_recovery::now()?;
    ensure(
        start.parse::<u64>().is_ok_and(|v| v <= now) && end.parse::<u64>().is_ok_and(|v| now < v),
        "w1_deadline_expired",
        "见证请求或响应已过期",
    )
}
pub(super) fn request(
    state: &mut DeviceState,
    record: p::Record,
    id: String,
    ttl: String,
) -> Result<Value, LabError> {
    crate::permission::types::id(&id)?;
    let ttl_value = crate::permission::types::decimal(&ttl)?;
    ensure(
        (1..=60).contains(&ttl_value),
        "w1_deadline_expired",
        "请求窗口须为 1—60 秒",
    )?;
    let public = p::Evidence::Full(record.clone()).public();
    let (i, s) = context(state, &public)?;
    ensure(
        i.signer == super::key_package_state::own(state),
        "w1_permission_denied",
        "只有准确目标可请求见证",
    )?;
    if let Some(old) = stored::get(state)?.challenges.get(&id) {
        let request = w::parse_witness_request(&old.request)?;
        binding(&request, &i, &s, &public)?;
        ensure(
            old.requested_ttl == ttl,
            "w1_request_id_conflict",
            "同一请求 ID 不可改变窗口",
        )?;
        return Ok(json!({"request":old.request,"duplicate":true}));
    }
    super::join_recovery_preflight::check_witness(state, &p::Evidence::Full(record))?
        .ok_or_else(|| LabError::new("w1_challenge_inactive", "已安装端点无需新挑战"))?;
    config::intent(state, &i)?;
    let reference = i
        .policy_ref
        .clone()
        .ok_or_else(|| LabError::new("w1_policy_upgrade_required", "旧候选不能换签为 W1"))?;
    let policy = w::parse_policy(stored::policy(state, &reference)?)?;
    let package = state
        .key_packages
        .as_ref()
        .and_then(|p| p.packages.get(&i.key_package_sha256))
        .ok_or_else(|| LabError::new("key_package_missing", "新包缺失"))?;
    let now = super::join_recovery::now()?;
    let expiry = package
        .material
        .not_after
        .parse::<u64>()
        .map_err(|_| LabError::new("recovery_state", "期限损坏"))?
        .min(
            now.checked_add(ttl_value)
                .ok_or_else(|| LabError::new("clock", "时间溢出"))?,
        );
    ensure(now < expiry, "w1_material_expired", "新包已过期")?;
    let count = stored::get(state)?
        .challenges
        .values()
        .filter(|c| w::parse_witness_request(&c.request).is_ok_and(|r| r.change_id == i.change_id))
        .count();
    ensure(
        count < 16,
        "w1_resource_exhausted",
        "每候选最多 16 个不同挑战",
    )?;
    // 完整最大请求、响应、安装记录及附件最低预留，发布前拒绝。
    stored::budget(state, 8192 + 16384 + 65536)?;
    let r = w::WitnessRequest {
        protocol_version: "rim-recovery-witness-request-1".into(),
        witness_profile: w::PROFILE.into(),
        policy_ref: reference,
        validation_rules_version: w::RULES_VERSION.into(),
        scope: i.scope.clone(),
        actor: i.actor.clone(),
        target: i.signer.clone(),
        witness: policy.witness,
        root_admission: i.root_admission.clone(),
        current_admission: i.current_admission.clone(),
        recovery_id: i.request_id.clone(),
        change_id: i.change_id.clone(),
        accepted_ref: p::admission_ref(&i.change_id, &public.bundle.change, &public.receipt)?,
        commit_sha256: s.commit_sha256,
        welcome_sha256: s.action.welcome_sha256,
        key_package_sha256: i.key_package_sha256,
        key_package_ref: s.action.key_package_ref,
        request_id: id.clone(),
        challenge: super::rollback_io::random_hex()?,
        issued_at_unix_secs: now.to_string(),
        expires_at_unix_secs: expiry.to_string(),
    };
    let proof = p::sign(&r, w::REQUEST_DOMAIN, &state.signer()?)?;
    w::verify_witness_request(stored::policy(state, &r.policy_ref)?, &proof)?;
    let ws = stored::get_mut(state)?;
    for old in ws
        .challenges
        .values_mut()
        .filter(|c| c.status == stored::ChallengeStatus::Active)
    {
        let old_request = w::parse_witness_request(&old.request)?;
        if old_request.scope == r.scope && old_request.current_admission == r.current_admission {
            old.status = stored::ChallengeStatus::Replaced;
        }
    }
    ws.challenges.insert(
        id,
        stored::Challenge {
            request: proof.clone(),
            requested_ttl: ttl,
            status: stored::ChallengeStatus::Active,
        },
    );
    stored::budget(state, 0)?;
    Ok(json!({"request":proof,"duplicate":false}))
}
pub(super) fn cancel(state: &mut DeviceState, id: String) -> Result<Value, LabError> {
    let old = stored::get_mut(state)?
        .challenges
        .get_mut(&id)
        .ok_or_else(|| LabError::new("w1_challenge_inactive", "请求不存在"))?;
    if old.status != stored::ChallengeStatus::Active {
        return Ok(json!({"duplicate":true}));
    }
    old.status = stored::ChallengeStatus::Cancelled;
    Ok(json!({"duplicate":false}))
}
pub(super) fn preflight(state: &DeviceState, command: &recovery::Command) -> Result<(), LabError> {
    use recovery::Command;
    match command {
        Command::WitnessApply {
            record,
            request,
            delivery,
        } => {
            super::join_recovery_witness_apply::check(state, record, request, delivery).map(|_| ())
        }
        Command::WitnessRespond { record, request } => {
            super::join_recovery_witness_response::check(state, record, request).map(|_| ())
        }
        Command::WitnessActivate
        | Command::WitnessRequest { .. }
        | Command::WitnessCancel { .. } => {
            let raw = checked("w1_persistence_failed", serde_json::to_vec(state))?;
            let mut temporary: DeviceState =
                checked("w1_persistence_failed", serde_json::from_slice(&raw))?;
            match command {
                Command::WitnessActivate => config::activate(&mut temporary).map(|_| ()),
                Command::WitnessCancel { request_id } => {
                    cancel(&mut temporary, request_id.clone()).map(|_| ())
                }
                // request 的签名只在实际事务执行；此处检验原件和容量，不恢复 provider。
                Command::WitnessRequest {
                    record,
                    request_id,
                    ttl,
                } => {
                    crate::permission::types::id(request_id)?;
                    let ttl = crate::permission::types::decimal(ttl)?;
                    ensure((1..=60).contains(&ttl), "w1_deadline_expired", "窗口超限")?;
                    let public = p::Evidence::Full(record.clone()).public();
                    let (i, s) = context(state, &public)?;
                    ensure(
                        i.signer == super::key_package_state::own(state),
                        "w1_permission_denied",
                        "只有准确目标可请求见证",
                    )?;
                    if let Some(old) = stored::get(state)?.challenges.get(request_id) {
                        let request = w::parse_witness_request(&old.request)?;
                        binding(&request, &i, &s, &public)?;
                        ensure(
                            crate::permission::types::decimal(&old.requested_ttl)? == ttl,
                            "w1_request_id_conflict",
                            "同一请求 ID 不可改变窗口",
                        )?;
                    } else {
                        config::intent(state, &i)?;
                        super::join_recovery_preflight::check_witness(
                            state,
                            &p::Evidence::Full(record.clone()),
                        )?;
                        // 新 ID 的确定性上限拒绝须在独立锚预约之前完成。
                        // 计入全部历史挑战，与实际 request 路径一致；精确重试走上方分支。
                        let count = stored::get(state)?
                            .challenges
                            .values()
                            .filter(|c| {
                                w::parse_witness_request(&c.request)
                                    .is_ok_and(|r| r.change_id == i.change_id)
                            })
                            .count();
                        ensure(
                            count < 16,
                            "w1_resource_exhausted",
                            "每候选最多 16 个不同挑战",
                        )?;
                        stored::budget(state, 8192 + 16384 + 65536)?;
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    }
}
