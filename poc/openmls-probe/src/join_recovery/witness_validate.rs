//! 只校验自足结构及公开后继关系；时效、授权、锚和实际 MLS 安装由调用方核验。
use super::{require, witness::*, *};
use crate::permission::{types as scalar, Member, PermissionError};
use std::collections::BTreeSet;

impl SourceRef {
    pub fn validate(&self) -> Result<(), PermissionError> {
        scalar::id(&self.source_id)?;
        scalar::hash(&self.source_sha256)
    }
}
impl PolicyRef {
    pub fn validate(&self) -> Result<(), PermissionError> {
        scalar::id(&self.policy_id)?;
        require(
            scalar::decimal(&self.policy_version)? > 0,
            "recovery_invalid",
        )?;
        scalar::hash(&self.policy_sha256)
    }
}
pub(super) fn distinct(a: &Member, b: &Member) -> Result<(), PermissionError> {
    crate::key_package::member(a)?;
    crate::key_package::member(b)?;
    require(
        a.identity() != b.identity() && a.signature_key != b.signature_key,
        "recovery_invalid",
    )
}
pub(super) fn distinct_witness(a: &Member, w: &Member) -> Result<(), PermissionError> {
    crate::key_package::member(a)?;
    crate::key_package::member(w)?;
    require(
        a.identity() != w.identity() && a.signature_key != w.signature_key,
        "w1_witness_ineligible",
    )
}
pub(super) fn rules(profile: &str, rules: &str) -> Result<(), PermissionError> {
    require(
        profile == PROFILE && rules == RULES_VERSION,
        "recovery_invalid",
    )
}
pub fn validate_policy(p: &Policy) -> Result<(), PermissionError> {
    require(
        p.protocol_version == "rim-recovery-witness-policy-1",
        "recovery_invalid",
    )?;
    rules(&p.witness_profile, &p.validation_rules_version)?;
    scalar::id(&p.policy_id)?;
    require(scalar::decimal(&p.policy_version)? > 0, "recovery_invalid")?;
    p.scope.validate()?;
    distinct_witness(&p.target, &p.witness)?;
    p.trust_source_ref.validate()?;
    p.change_authority_ref.validate()?;
    p.independence.confirmation_source_ref.validate()?;
    scalar::id(&p.independence.control_domain_id)?;
    require(
        p.independence.assumption == "honest_uncompromised_not_controlled_by_actor_or_target",
        "recovery_invalid",
    )
}
pub fn validate_activation(a: &Activation) -> Result<(), PermissionError> {
    require(
        a.protocol_version == "rim-recovery-witness-activation-1"
            && a.witness_profile == PROFILE
            && a.legacy_uninstalled_target == "deny_first_install"
            && a.legacy_installed == "retain_scoped",
        "recovery_invalid",
    )?;
    scalar::id(&a.activation_id)?;
    require(
        scalar::decimal(&a.activation_version)? > 0,
        "recovery_invalid",
    )?;
    a.scope.validate()?;
    crate::key_package::member(&a.target)?;
    if let Some(p) = &a.policy_ref {
        p.validate()?;
    }
    a.trusted_authorization_ref.validate()?;
    scalar::decimal(&a.activated_at_unix_secs)?;
    Ok(())
}
pub fn parse_activation(encoded: &str) -> Result<Activation, PermissionError> {
    let a: Activation = decode(encoded, 16384)?;
    validate_activation(&a)?;
    Ok(a)
}
impl CompleteCheckpoint {
    pub fn validate(&self, scope: &Scope) -> Result<(), PermissionError> {
        scalar::bytes(&self.group_id, 256)?;
        scalar::decimal(&self.epoch)?;
        self.checkpoint.validate()?;
        require(
            self.group_id == scope.group_id
                && self.checkpoint.service_id == scope.service_id
                && self.checkpoint.conversation_id == scope.conversation_id,
            "w1_binding_mismatch",
        )
    }
}
pub(super) fn interval60(start: &str, end: &str) -> Result<(), PermissionError> {
    require(
        scalar::decimal(end)?
            .checked_sub(scalar::decimal(start)?)
            .is_some_and(|n| (1..=60).contains(&n)),
        "recovery_invalid",
    )
}
pub(super) fn transition(
    previous: &CompleteCheckpoint,
    next: &CompleteCheckpoint,
    scope: &Scope,
    actor: &Member,
    target: &Member,
    witness: &Member,
) -> Result<(), PermissionError> {
    previous.validate(scope)?;
    next.validate(scope)?;
    let p = &previous.checkpoint;
    let n = &next.checkpoint;
    require(
        scalar::decimal(&previous.epoch)?.checked_add(1) == Some(scalar::decimal(&next.epoch)?)
            && scalar::decimal(&p.authorization_version)?.checked_add(1)
                == Some(scalar::decimal(&n.authorization_version)?)
            && p.crypto_state_ref != n.crypto_state_ref
            && p.owner_account_id == n.owner_account_id
            && p.members == n.members
            && [actor, target].iter().all(|m| p.members.contains(m)),
        "w1_binding_mismatch",
    )?;
    require(p.members.contains(witness), "w1_witness_ineligible")
}
macro_rules! common {
    ($v:expr) => {{
        let v = $v;
        rules(&v.witness_profile, &v.validation_rules_version)?;
        v.policy_ref.validate()?;
        v.scope.validate()?;
        distinct(&v.actor, &v.target)?;
        distinct_witness(&v.actor, &v.witness)?;
        distinct_witness(&v.target, &v.witness)?;
        v.accepted_ref.validate()?;
        for h in [&v.commit_sha256, &v.welcome_sha256, &v.key_package_sha256] {
            scalar::hash(h)?;
        }
        require(
            scalar::bytes(&v.key_package_ref, 32)?.len() == 32,
            "recovery_invalid",
        )?;
    }};
}
macro_rules! chain {
    ($v:expr) => {{
        let v = $v;
        v.root_admission.validate()?;
        v.current_admission.validate()?;
        scalar::id(&v.recovery_id)?;
        scalar::id(&v.change_id)?;
        require(v.accepted_ref.change_id == v.change_id, "recovery_invalid")?;
    }};
}
pub fn validate_witness_request(v: &WitnessRequest) -> Result<(), PermissionError> {
    require(
        v.protocol_version == "rim-recovery-witness-request-1",
        "recovery_invalid",
    )?;
    common!(v);
    chain!(v);
    scalar::id(&v.request_id)?;
    scalar::hash(&v.challenge)?;
    interval60(&v.issued_at_unix_secs, &v.expires_at_unix_secs)
}
pub fn validate_witness_response(v: &WitnessResponse) -> Result<(), PermissionError> {
    require(
        v.protocol_version == "rim-recovery-witness-response-1",
        "recovery_invalid",
    )?;
    common!(v);
    chain!(v);
    scalar::id(&v.request_id)?;
    scalar::hash(&v.challenge)?;
    scalar::hash(&v.request_sha256)?;
    interval60(&v.issued_at_unix_secs, &v.expires_at_unix_secs)?;
    v.installation_ref.validate()?;
    transition(
        &v.previous,
        &v.next,
        &v.scope,
        &v.actor,
        &v.target,
        &v.witness,
    )?;
    v.highest_known.validate(&v.scope)?;
    require(
        scalar::decimal(&v.highest_known.checkpoint.authorization_version)?
            >= scalar::decimal(&v.next.checkpoint.authorization_version)?,
        "w1_binding_mismatch",
    )?;
    if v.highest_known.checkpoint.authorization_version == v.next.checkpoint.authorization_version {
        require(v.highest_known == v.next, "w1_binding_mismatch")?;
    }
    require(v.known_evidence_refs.len() <= 64, "resource_exhausted")?;
    let mut refs = BTreeSet::new();
    for r in &v.known_evidence_refs {
        r.validate()?;
        require(
            refs.insert((&r.source_id, &r.source_sha256)),
            "recovery_invalid",
        )?;
    }
    Ok(())
}
pub fn validate_installation(v: &InstallationFact) -> Result<(), PermissionError> {
    require(
        v.protocol_version == "rim-recovery-witness-installation-1",
        "recovery_invalid",
    )?;
    common!(v);
    transition(
        &v.previous,
        &v.next,
        &v.scope,
        &v.actor,
        &v.target,
        &v.witness,
    )?;
    scalar::decimal(&v.installed_at_unix_secs)?;
    Ok(())
}
pub fn validate_installed(v: &InstalledRecord) -> Result<(), PermissionError> {
    require(
        v.protocol_version == "rim-recovery-witness-installation-record-1"
            && v.challenge_consumed
            && v.key_package_consumed,
        "recovery_invalid",
    )?;
    common!(v);
    chain!(v);
    let request = parse_witness_request(&v.request)?;
    let response = parse_witness_response(&v.response)?;
    super::witness_binding::response_binding(&request, &v.request, &response)?;
    require(
        v.policy_ref == request.policy_ref
            && v.scope == request.scope
            && v.actor == request.actor
            && v.target == request.target
            && v.witness == request.witness
            && v.root_admission == request.root_admission
            && v.current_admission == request.current_admission
            && v.recovery_id == request.recovery_id
            && v.change_id == request.change_id
            && v.accepted_ref == request.accepted_ref
            && v.commit_sha256 == request.commit_sha256
            && v.welcome_sha256 == request.welcome_sha256
            && v.key_package_sha256 == request.key_package_sha256
            && v.key_package_ref == request.key_package_ref
            && v.actual_next == response.next
            && scalar::decimal(&v.installed_at_unix_secs)?
                >= scalar::decimal(&response.issued_at_unix_secs)?
            && scalar::decimal(&v.installed_at_unix_secs)?
                < scalar::decimal(&response.expires_at_unix_secs)?,
        "recovery_invalid",
    )
}
