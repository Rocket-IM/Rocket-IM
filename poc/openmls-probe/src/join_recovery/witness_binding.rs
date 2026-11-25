//! 原件摘要、独立签名域和明确 P 绑定。调用方仍须验证可信配置与真实状态。
use super::{witness::*, *};
use crate::permission::{receipts, types as scalar, PermissionError};
use sha2::{Digest, Sha256};

pub fn parse_policy_bytes(encoded: &str) -> Result<(Policy, PolicyRef), PermissionError> {
    let p: Policy = decode(encoded, 8192)?;
    validate_policy(&p)?;
    let bytes = scalar::bytes(encoded, 8192)?;
    let mut h = Sha256::new();
    h.update(POLICY_DOMAIN);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    let r = PolicyRef {
        policy_id: p.policy_id.clone(),
        policy_version: p.policy_version.clone(),
        policy_sha256: format!("{:x}", h.finalize()),
    };
    Ok((p, r))
}
pub fn parse_policy(envelope: &PolicyEnvelope) -> Result<Policy, PermissionError> {
    envelope.policy_ref.validate()?;
    let (p, r) = parse_policy_bytes(&envelope.policy_bytes)?;
    require(r == envelope.policy_ref, "w1_policy_mismatch")?;
    Ok(p)
}
pub fn parse_witness_request(proof: &SignedRecord) -> Result<WitnessRequest, PermissionError> {
    super::witness_format::signed_budget(proof, REQUEST_WIRE_LIMIT)?;
    let value: WitnessRequest = decode(&proof.statement_bytes, 16384)?;
    validate_witness_request(&value)?;
    receipts::signature(
        &value.target.signature_key,
        super::witness::REQUEST_DOMAIN,
        &scalar::bytes(&proof.statement_bytes, 16384)?,
        &proof.signature_bytes,
    )?;
    Ok(value)
}
pub fn parse_witness_response(proof: &SignedRecord) -> Result<WitnessResponse, PermissionError> {
    super::witness_format::signed_budget(proof, RESPONSE_WIRE_LIMIT)?;
    let value: WitnessResponse = decode(&proof.statement_bytes, 16384)?;
    validate_witness_response(&value)?;
    receipts::signature(
        &value.witness.signature_key,
        RESPONSE_DOMAIN,
        &scalar::bytes(&proof.statement_bytes, 16384)?,
        &proof.signature_bytes,
    )?;
    Ok(value)
}
pub fn verify_witness_request(
    policy: &PolicyEnvelope,
    proof: &SignedRecord,
) -> Result<WitnessRequest, PermissionError> {
    let p = parse_policy(policy)?;
    let v = parse_witness_request(proof)?;
    require(v.policy_ref == policy.policy_ref, "w1_policy_mismatch")?;
    require(
        v.scope == p.scope && v.target == p.target && v.witness == p.witness,
        "w1_binding_mismatch",
    )?;
    Ok(v)
}
pub(super) fn response_binding(
    q: &WitnessRequest,
    proof: &SignedRecord,
    r: &WitnessResponse,
) -> Result<(), PermissionError> {
    require(q.policy_ref == r.policy_ref, "w1_policy_mismatch")?;
    require(q.witness == r.witness, "w1_witness_ineligible")?;
    require(
        q.scope == r.scope
            && q.actor == r.actor
            && q.target == r.target
            && q.root_admission == r.root_admission
            && q.current_admission == r.current_admission
            && q.recovery_id == r.recovery_id
            && q.change_id == r.change_id
            && q.accepted_ref == r.accepted_ref
            && q.commit_sha256 == r.commit_sha256
            && q.welcome_sha256 == r.welcome_sha256
            && q.key_package_sha256 == r.key_package_sha256
            && q.key_package_ref == r.key_package_ref
            && q.request_id == r.request_id
            && q.challenge == r.challenge
            && signed_digest(proof)? == r.request_sha256
            && scalar::decimal(&r.issued_at_unix_secs)? >= scalar::decimal(&q.issued_at_unix_secs)?
            && scalar::decimal(&r.expires_at_unix_secs)?
                <= scalar::decimal(&q.expires_at_unix_secs)?,
        "w1_binding_mismatch",
    )
}
pub fn verify_witness_response(
    policy: &PolicyEnvelope,
    request: &SignedRecord,
    response: &SignedRecord,
) -> Result<WitnessResponse, PermissionError> {
    let q = verify_witness_request(policy, request)?;
    let r = parse_witness_response(response)?;
    response_binding(&q, request, &r)?;
    Ok(r)
}
/// 意图包含准确 A/T/W 账号集合；具体目录原件/版本须由受信目录层核验。
pub fn validate_intent_policy(
    intent: &Intent,
    policy: &PolicyEnvelope,
) -> Result<(), PermissionError> {
    Request::Intent(Box::new(intent.clone())).validate()?;
    let p = parse_policy(policy)?;
    require(
        intent.policy_ref.as_ref() == Some(&policy.policy_ref),
        "w1_policy_mismatch",
    )?;
    require(
        intent.witness_profile.as_deref() == Some(PROFILE)
            && intent.scope == p.scope
            && intent.signer == p.target,
        "w1_binding_mismatch",
    )?;
    super::witness_validate::distinct_witness(&intent.actor, &p.witness)?;
    let mut accounts = vec![
        intent.actor.account_id.as_str(),
        intent.signer.account_id.as_str(),
        p.witness.account_id.as_str(),
    ];
    accounts.sort();
    accounts.dedup();
    require(
        intent
            .directory_refs
            .iter()
            .map(|d| d.account_id.as_str())
            .collect::<Vec<_>>()
            == accounts,
        "w1_binding_mismatch",
    )
}

/// 附件 SHA-256 只绑定原件；证据的权限含义须经既有公开记录验证器处理。
pub fn validate_delivery(delivery: &WitnessDelivery) -> Result<WitnessResponse, PermissionError> {
    let response = parse_witness_response(&delivery.response)?;
    require(
        delivery.known_evidence.len() <= 64 && delivery.supplemental_evidence.len() <= 64,
        "resource_exhausted",
    )?;
    let mut seen = std::collections::BTreeSet::new();
    for attachment in delivery
        .known_evidence
        .iter()
        .chain(&delivery.supplemental_evidence)
    {
        attachment.reference.validate()?;
        let raw = scalar::bytes(&attachment.evidence_bytes, 921600)?;
        require(
            crate::permission::commit_digest(&raw) == attachment.reference.source_sha256
                && seen.insert((
                    &attachment.reference.source_id,
                    &attachment.reference.source_sha256,
                )),
            "recovery_invalid",
        )?;
    }
    require(
        response
            .known_evidence_refs
            .iter()
            .all(|r| delivery.known_evidence.iter().any(|a| &a.reference == r))
            && delivery
                .known_evidence
                .iter()
                .all(|a| response.known_evidence_refs.contains(&a.reference)),
        "recovery_invalid",
    )?;
    Ok(response)
}
