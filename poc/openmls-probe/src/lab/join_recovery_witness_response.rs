//! 独立幸存者只对已经共同持久的真实 R1 出具原字节见证；不重放 Commit。
use super::{
    checked, codec, ensure, join_recovery_witness as flow, join_recovery_witness_state as stored,
    state::DeviceState, LabError,
};
use crate::{
    join_recovery::{self as p, witness as w},
    permission::{receipts::SignedRecord, PermissionCheckpoint},
};
use serde_json::{json, Value};

pub(super) fn installed(
    state: &mut DeviceState,
    record: &p::PublicRecord,
    s: &p::Statement,
    previous: &PermissionCheckpoint,
    next: &PermissionCheckpoint,
) -> Result<(), LabError> {
    let Some(reference) = &s.policy_ref else {
        return Ok(());
    };
    let policy = w::parse_policy(stored::policy(state, reference)?)?;
    if policy.witness != super::key_package_state::own(state) {
        return Ok(());
    }
    ensure(
        s.actor != policy.witness
            && s.action.target != policy.witness
            && super::join_recovery_state::get(state)?.pending.is_none(),
        "w1_witness_ineligible",
        "批准者 pending 或目标分支不能成为 W",
    )?;
    super::join_recovery_witness_config::eligible(state, reference, &policy, &s.actor)?;
    let epoch = crate::permission::types::decimal(&s.action.previous_epoch)?;
    let fact = w::InstallationFact {
        protocol_version: "rim-recovery-witness-installation-1".into(),
        witness_profile: w::PROFILE.into(),
        policy_ref: reference.clone(),
        validation_rules_version: w::RULES_VERSION.into(),
        scope: s.scope.clone(),
        actor: s.actor.clone(),
        target: s.action.target.clone(),
        witness: policy.witness,
        accepted_ref: p::admission_ref(&s.change_id, &record.bundle.change, &record.receipt)?,
        commit_sha256: s.commit_sha256.clone(),
        welcome_sha256: s.action.welcome_sha256.clone(),
        key_package_sha256: s.action.key_package_sha256.clone(),
        key_package_ref: s.action.key_package_ref.clone(),
        previous: w::CompleteCheckpoint {
            group_id: s.scope.group_id.clone(),
            epoch: epoch.to_string(),
            checkpoint: previous.clone(),
        },
        next: w::CompleteCheckpoint {
            group_id: s.scope.group_id.clone(),
            epoch: epoch
                .checked_add(1)
                .ok_or_else(|| LabError::new("recovery_commit", "epoch 溢出"))?
                .to_string(),
            checkpoint: next.clone(),
        },
        installed_at_unix_secs: super::join_recovery::now()?.to_string(),
    };
    w::validate_installation(&fact)?;
    let raw = codec::encode(&checked(
        "w1_persistence_failed",
        serde_json::to_vec(&fact),
    )?);
    let ledger = stored::get_mut(state)?;
    ensure(
        !ledger.installation_facts.contains_key(&s.change_id),
        "w1_binding_mismatch",
        "安装事实不可覆盖",
    )?;
    ledger.installation_facts.insert(s.change_id.clone(), raw);
    stored::budget(state, 0)
}
pub(super) fn check(
    state: &DeviceState,
    record: &p::PublicRecord,
    request: &SignedRecord,
) -> Result<w::WitnessRequest, LabError> {
    let r = w::parse_witness_request(request)?;
    let envelope = stored::policy(state, &r.policy_ref)?;
    w::verify_witness_request(envelope, request)?;
    let policy = w::parse_policy(envelope)?;
    ensure(
        r.witness == super::key_package_state::own(state),
        "w1_witness_ineligible",
        "只有准确 W 可响应",
    )?;
    super::join_recovery_witness_config::eligible(state, &r.policy_ref, &policy, &r.actor)?;
    let (i, s) = flow::context(state, record)?;
    flow::binding(&r, &i, &s, record)?;
    if let Some(old) = stored::get(state)?.responses.get(&r.request_id) {
        ensure(
            old.request == *request,
            "w1_request_id_conflict",
            "响应请求 ID 对应不同原字节",
        )?;
        return Ok(r);
    }
    flow::live(&r.issued_at_unix_secs, &r.expires_at_unix_secs)?;
    ensure(
        stored::get(state)?
            .responses
            .values()
            .filter(|old| {
                w::parse_witness_request(&old.request).is_ok_and(|q| q.change_id == r.change_id)
            })
            .count()
            < 16,
        "w1_resource_exhausted",
        "W 对同一候选最多保存 16 个不同挑战响应",
    )?;
    let raw = stored::get(state)?
        .installation_facts
        .get(&r.change_id)
        .ok_or_else(|| LabError::new("w1_witness_not_installed", "W 尚无共同持久的真实安装事实"))?;
    let fact: w::InstallationFact = p::raw(raw)?;
    w::validate_installation(&fact)?;
    ensure(
        fact.accepted_ref == r.accepted_ref
            && fact.policy_ref == r.policy_ref
            && fact.witness == r.witness
            && fact.commit_sha256 == r.commit_sha256
            && fact.welcome_sha256 == r.welcome_sha256
            && fact.key_package_sha256 == r.key_package_sha256
            && fact.key_package_ref == r.key_package_ref,
        "w1_binding_mismatch",
        "W 安装事实不匹配",
    )?;
    ensure(
        super::join_recovery_state::get(state)?
            .records
            .get(&r.change_id)
            .is_some_and(|a| a.installed),
        "w1_witness_not_installed",
        "缺少真实 R1 标记",
    )?;
    stored::budget(state, 16384 + 65536)?;
    Ok(r)
}
pub(super) fn respond(
    state: &mut DeviceState,
    record: p::PublicRecord,
    request: SignedRecord,
) -> Result<Value, LabError> {
    let r = check(state, &record, &request)?;
    // 真实 provider 只在事务内加载；同一 R1 已推进时使用历史事实并披露更高公开证据。
    let cp = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("w1_witness_not_installed", "没有实际群"))?;
    super::permission_state::validate_current(state, cp, &state.group()?)?;
    if let Some(old) = stored::get(state)?.responses.get(&r.request_id) {
        let mut delivery = old.delivery.clone();
        delivery.supplemental_evidence =
            super::join_recovery_witness_evidence::export(state, &delivery.known_evidence)?;
        return Ok(json!({"delivery":delivery,"duplicate":true}));
    }
    let raw = stored::get(state)?.installation_facts[&r.change_id].clone();
    let fact: w::InstallationFact = p::raw(&raw)?;
    let evidence = super::join_recovery_witness_evidence::export(state, &[])?;
    let highest = super::join_recovery_witness_evidence::highest(state, &fact.next, &evidence)?;
    let mut value = checked("w1_binding_mismatch", serde_json::to_value(&r))?;
    value["protocol_version"] = json!("rim-recovery-witness-response-1");
    value["request_sha256"] = json!(p::signed_digest(&request)?);
    value["previous"] = json!(fact.previous);
    value["next"] = json!(fact.next);
    value["installation_ref"] = json!({"source_id":r.change_id,"source_sha256":crate::permission::commit_digest(&codec::decode(&raw)?)});
    value["highest_known"] = json!(highest);
    value["known_evidence_refs"] = json!(evidence.iter().map(|e| &e.reference).collect::<Vec<_>>());
    value["issued_at_unix_secs"] = json!(super::join_recovery::now()?.to_string());
    let response: w::WitnessResponse =
        checked("w1_binding_mismatch", serde_json::from_value(value))?;
    flow::live(
        &response.issued_at_unix_secs,
        &response.expires_at_unix_secs,
    )?;
    let proof = p::sign(&response, w::RESPONSE_DOMAIN, &state.signer()?)?;
    w::verify_witness_response(stored::policy(state, &r.policy_ref)?, &request, &proof)?;
    let delivery = w::WitnessDelivery {
        response: proof,
        known_evidence: evidence,
        supplemental_evidence: Vec::new(),
    };
    stored::get_mut(state)?.responses.insert(
        r.request_id,
        stored::Response {
            request,
            delivery: delivery.clone(),
        },
    );
    stored::budget(state, 0)?;
    Ok(json!({"delivery":delivery,"duplicate":false}))
}
