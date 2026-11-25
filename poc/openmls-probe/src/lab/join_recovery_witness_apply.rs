//! 目标门禁只授权当前一次临时 Welcome 校验；成功关联随原群快照共同提交。
use super::{
    checked, ensure, join_recovery_witness as flow, join_recovery_witness_state as stored,
    state::DeviceState, CrashPoint, LabError,
};
use crate::{
    join_recovery::{self as p, witness as w},
    permission::receipts::SignedRecord,
};
use serde_json::{json, Value};

pub(super) fn check(
    state: &DeviceState,
    record: &p::Record,
    request: &SignedRecord,
    delivery: &w::WitnessDelivery,
) -> Result<Option<w::WitnessResponse>, LabError> {
    let public = p::Evidence::Full(record.clone()).public();
    let original = p::parse_intent(&public.bundle.intent)?;
    if original.signer == super::key_package_state::own(state)
        && (state.group_id.is_some() || state.permissions.admission.joined_record.is_some())
        && !state
            .witness_state
            .as_ref()
            .is_some_and(|s| s.installed.contains_key(&original.change_id))
    {
        return Err(LabError::new(
            "w1_already_grouped",
            "旧真实群不能被新 Welcome 覆盖",
        ));
    }
    let (i, s) = flow::context(state, &public)?;
    ensure(
        i.signer == super::key_package_state::own(state),
        "w1_permission_denied",
        "见证安装仅用于准确目标",
    )?;
    let ledger = stored::get(state)?;
    if let Some(old) = ledger.installed.get(&i.change_id) {
        ensure(
            old.request == *request
                && old.response == delivery.response
                && old.accepted_ref
                    == p::admission_ref(&i.change_id, &public.bundle.change, &public.receipt)?,
            "w1_request_id_conflict",
            "已有安装仅允许准确原件重试",
        )?;
        super::join_recovery_preflight::check_witness(state, &p::Evidence::Full(record.clone()))?;
        return Ok(None);
    }
    let r = w::parse_witness_request(request)?;
    flow::binding(&r, &i, &s, &public)?;
    let envelope = stored::policy(state, &r.policy_ref)?;
    let policy = w::parse_policy(envelope)?;
    w::verify_witness_request(envelope, request)?;
    if let Some(challenge) = ledger.challenges.get(&r.request_id) {
        ensure(
            challenge.request == *request,
            "w1_request_id_conflict",
            "请求 ID 已绑定不同原字节",
        )?;
    }
    let response = w::verify_witness_response(envelope, request, &delivery.response)?;
    super::join_recovery_witness_config::eligible(state, &r.policy_ref, &policy, &i.actor)?;
    let ready =
        super::join_recovery_preflight::check_witness(state, &p::Evidence::Full(record.clone()))?
            .ok_or_else(|| LabError::new("w1_binding_mismatch", "真实已装状态缺少 W1 关联"))?;
    let challenge = ledger
        .challenges
        .get(&r.request_id)
        .ok_or_else(|| LabError::new("w1_challenge_inactive", "缺少已持久本机挑战"))?;
    ensure(
        challenge.request == *request,
        "w1_request_id_conflict",
        "请求 ID 原字节冲突",
    )?;
    ensure(
        challenge.status == stored::ChallengeStatus::Active,
        "w1_challenge_inactive",
        "挑战已经取消、替换或消费",
    )?;
    // 准确绑定成立之后，材料先于同时到期的请求/响应，保留具体因果。
    let package = state
        .key_packages
        .as_ref()
        .and_then(|p| p.packages.get(&r.key_package_sha256))
        .ok_or_else(|| LabError::new("key_package_missing", "本机新包缺失"))?;
    crate::key_package::material::current(&package.material, super::join_recovery::now()?)
        .map_err(|e| {
            LabError::new(
                "w1_material_expired",
                format!("{}; 请求与响应可能同时到期", e),
            )
        })?;
    flow::live(&r.issued_at_unix_secs, &r.expires_at_unix_secs)?;
    flow::live(
        &response.issued_at_unix_secs,
        &response.expires_at_unix_secs,
    )?;
    ensure(
        crate::permission::types::decimal(&r.expires_at_unix_secs)?
            <= crate::permission::types::decimal(&package.material.not_after)?,
        "w1_binding_mismatch",
        "挑战不能延长材料",
    )?;
    super::join_recovery_witness_evidence::check(state, delivery, &response)?;
    let epoch = crate::permission::types::decimal(&s.action.previous_epoch)?;
    ensure(
        response.previous
            == (w::CompleteCheckpoint {
                group_id: s.scope.group_id.clone(),
                epoch: epoch.to_string(),
                checkpoint: ready.previous,
            })
            && response.next
                == (w::CompleteCheckpoint {
                    group_id: s.scope.group_id,
                    epoch: epoch
                        .checked_add(1)
                        .ok_or_else(|| LabError::new("w1_binding_mismatch", "epoch 溢出"))?
                        .to_string(),
                    checkpoint: ready.next,
                }),
        "w1_binding_mismatch",
        "见证前后完整检查点与准确 R0 不符",
    )?;
    stored::budget(state, 65536)?;
    Ok(Some(response))
}
pub(super) fn apply(
    state: &mut DeviceState,
    record: p::Record,
    request: SignedRecord,
    delivery: w::WitnessDelivery,
    point: CrashPoint,
) -> Result<Value, LabError> {
    let Some(response) = check(state, &record, &request, &delivery)? else {
        return Ok(
            json!({"duplicate":true,"installed":true,"checkpoint":state.permissions.checkpoint}),
        );
    };
    let result =
        super::join_recovery_apply::apply_witness(state, p::Evidence::Full(record), point)?;
    // MLS 已在临时 provider 完整验证，尚未保存或发布；最终时钟复核失败不会持久任何候选。
    let package = state
        .key_packages
        .as_ref()
        .and_then(|p| p.packages.get(&response.key_package_sha256))
        .ok_or_else(|| LabError::new("key_package_missing", "材料缺失"))?;
    crate::key_package::material::current(&package.material, super::join_recovery::now()?)
        .map_err(|e| LabError::new("w1_material_expired", e.to_string()))?;
    flow::live(
        &response.issued_at_unix_secs,
        &response.expires_at_unix_secs,
    )?;
    let request_value = w::parse_witness_request(&request)?;
    flow::live(
        &request_value.issued_at_unix_secs,
        &request_value.expires_at_unix_secs,
    )?;
    let mut value = checked("w1_binding_mismatch", serde_json::to_value(&request_value))?;
    for field in [
        "request_id",
        "challenge",
        "issued_at_unix_secs",
        "expires_at_unix_secs",
    ] {
        value
            .as_object_mut()
            .ok_or_else(|| LabError::new("w1_binding_mismatch", "对象无效"))?
            .remove(field);
    }
    value["protocol_version"] = json!("rim-recovery-witness-installation-record-1");
    value["request"] = json!(request);
    value["response"] = json!(delivery.response);
    let group = state.group()?;
    value["actual_next"] = json!({"group_id":super::codec::encode(group.group_id().as_slice()),
        "epoch":group.epoch().as_u64().to_string(),"checkpoint":state.permissions.checkpoint});
    value["challenge_consumed"] = json!(true);
    value["key_package_consumed"] = json!(true);
    value["installed_at_unix_secs"] = json!(super::join_recovery::now()?.to_string());
    let installed: w::InstalledRecord =
        checked("w1_binding_mismatch", serde_json::from_value(value))?;
    w::validate_installed(&installed)?;
    ensure(
        installed.actual_next == response.next,
        "w1_binding_mismatch",
        "实际 Welcome 后继与见证不符",
    )?;
    let ledger = stored::get_mut(state)?;
    ledger
        .challenges
        .get_mut(&request_value.request_id)
        .ok_or_else(|| LabError::new("w1_challenge_inactive", "挑战缺失"))?
        .status = stored::ChallengeStatus::Consumed;
    ledger.installed.insert(response.change_id, installed);
    state.witness_deadline = Some(crate::permission::types::decimal(
        &response.expires_at_unix_secs,
    )?);
    stored::budget(state, 0)?;
    Ok(result)
}
