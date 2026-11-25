//! W1 的可信启用、原件与消费账本归原加密快照所有；旧程序不得忽略此字段。
use super::{checked, ensure, state::DeviceState, LabError};
use crate::{
    join_recovery::{self as p, witness as w},
    permission::{receipts::SignedRecord, Member},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod associations;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlDomain {
    pub member: Member,
    pub control_domain_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivationRecord {
    pub activation_bytes: String,
    pub config_sha256: String,
    pub control_domains: Vec<ControlDomain>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ChallengeStatus {
    Active,
    Cancelled,
    Replaced,
    Consumed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Challenge {
    pub request: SignedRecord,
    pub requested_ttl: String,
    pub status: ChallengeStatus,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Response {
    pub request: SignedRecord,
    pub delivery: w::WitnessDelivery,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub activations: Vec<ActivationRecord>,
    pub policies: BTreeMap<String, w::PolicyEnvelope>,
    // 候选第一次引用的 P 永久固定；启用修订只影响未来新意图。
    pub candidate_policies: BTreeMap<String, w::PolicyRef>,
    pub challenges: BTreeMap<String, Challenge>,
    pub responses: BTreeMap<String, Response>,
    pub installation_facts: BTreeMap<String, String>,
    pub installed: BTreeMap<String, w::InstalledRecord>,
}
pub(super) fn get(state: &DeviceState) -> Result<&State, LabError> {
    state
        .witness_state
        .as_ref()
        .ok_or_else(|| LabError::new("w1_policy_missing", "尚未可信启用 W1"))
}
pub(super) fn get_mut(state: &mut DeviceState) -> Result<&mut State, LabError> {
    state
        .witness_state
        .as_mut()
        .ok_or_else(|| LabError::new("w1_policy_missing", "尚未可信启用 W1"))
}
pub(super) fn activation(state: &DeviceState) -> Result<w::Activation, LabError> {
    let record = get(state)?
        .activations
        .last()
        .ok_or_else(|| LabError::new("w1_activation_unauthorized", "缺少持久启用原件"))?;
    let activation: w::Activation = p::raw(&record.activation_bytes)?;
    w::validate_activation(&activation)?;
    Ok(activation)
}
pub(super) fn policy<'a>(
    state: &'a DeviceState,
    reference: &w::PolicyRef,
) -> Result<&'a w::PolicyEnvelope, LabError> {
    let policy = get(state)?
        .policies
        .get(&reference.policy_sha256)
        .ok_or_else(|| LabError::new("w1_policy_mismatch", "缺少固定策略原件"))?;
    ensure(
        policy.policy_ref == *reference,
        "w1_policy_mismatch",
        "策略引用不匹配",
    )?;
    w::parse_policy(policy)?;
    Ok(policy)
}
pub(super) fn budget(state: &DeviceState, reserve: usize) -> Result<(), LabError> {
    if state.witness_state.is_none() {
        return Ok(());
    }
    let own = checked(
        "w1_persistence_failed",
        serde_json::to_vec(&state.witness_state),
    )?
    .len();
    let recovery = checked(
        "w1_persistence_failed",
        serde_json::to_vec(&state.join_recovery),
    )?
    .len();
    let pending = get(state)?
        .challenges
        .values()
        .filter(|c| c.status == ChallengeStatus::Active)
        .count();
    let reserved = pending
        .checked_mul(16384 + 65536)
        .and_then(|v| v.checked_add(reserve))
        .ok_or_else(|| LabError::new("w1_resource_exhausted", "预留容量溢出"))?;
    ensure(
        own.checked_add(recovery)
            .and_then(|v| v.checked_add(reserved))
            .is_some_and(|v| v <= 8 * 1024 * 1024),
        "w1_resource_exhausted",
        "见证与恢复账本预算不足，禁止删历史腾位",
    )
}
pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    let Some(s) = &state.witness_state else {
        return ensure(
            state.version != 3,
            "w1_policy_upgrade_required",
            "v3 缺少强制见证状态",
        );
    };
    ensure(
        state.version == 3 && !s.activations.is_empty(),
        "w1_policy_upgrade_required",
        "见证状态版本或启用原件缺失",
    )?;
    let mut previous = 0;
    for record in &s.activations {
        let a: w::Activation = p::raw(&record.activation_bytes)?;
        w::validate_activation(&a)?;
        let revision = a
            .activation_version
            .parse::<u64>()
            .map_err(|_| LabError::new("w1_activation_rollback", "修订号无效"))?;
        ensure(
            revision > previous && a.scope.service_id == state.context.service,
            "w1_activation_rollback",
            "启用历史不单调或实例不符",
        )?;
        previous = revision;
        if let Some(reference) = &a.policy_ref {
            let policy = w::parse_policy(policy(state, reference)?)?;
            ensure(
                policy.scope == a.scope && policy.target == a.target,
                "w1_policy_mismatch",
                "启用与策略范围不符",
            )?;
        }
    }
    associations::activation_history(state, s)?;
    associations::candidates(state, s)?;
    for (id, challenge) in &s.challenges {
        let request = w::parse_witness_request(&challenge.request)?;
        ensure(
            request.request_id == *id && request.target == super::key_package_state::own(state),
            "w1_binding_mismatch",
            "挑战归属不符",
        )?;
        policy(state, &request.policy_ref)?;
    }
    let mut active = std::collections::BTreeSet::new();
    for challenge in s
        .challenges
        .values()
        .filter(|c| c.status == ChallengeStatus::Active)
    {
        let r = w::parse_witness_request(&challenge.request)?;
        ensure(
            active.insert((
                r.scope.service_id,
                r.scope.conversation_id,
                r.current_admission.change_id,
            )),
            "w1_challenge_inactive",
            "同一端点存在多个活动挑战",
        )?;
    }
    for (id, response) in &s.responses {
        let request = w::parse_witness_request(&response.request)?;
        let r = w::verify_witness_response(
            policy(state, &request.policy_ref)?,
            &response.request,
            &response.delivery.response,
        )?;
        ensure(
            *id == r.request_id && r.witness == super::key_package_state::own(state),
            "w1_binding_mismatch",
            "响应归属不符",
        )?;
        let raw = s
            .installation_facts
            .get(&r.change_id)
            .ok_or_else(|| LabError::new("w1_witness_not_installed", "响应缺少持久安装事实"))?;
        ensure(
            crate::permission::commit_digest(&super::codec::decode(raw)?)
                == r.installation_ref.source_sha256,
            "w1_binding_mismatch",
            "安装事实原字节不匹配",
        )?;
    }
    for (id, encoded) in &s.installation_facts {
        let fact: w::InstallationFact = p::raw(encoded)?;
        w::validate_installation(&fact)?;
        ensure(
            fact.accepted_ref.change_id == *id
                && fact.witness == super::key_package_state::own(state)
                && super::join_recovery_state::get(state)?
                    .records
                    .get(id)
                    .is_some_and(|r| r.installed),
            "w1_witness_not_installed",
            "事实没有对应真实已安装记录",
        )?;
        policy(state, &fact.policy_ref)?;
    }
    for (id, record) in &s.installed {
        w::validate_installed(record)?;
        w::verify_witness_response(
            policy(state, &record.policy_ref)?,
            &record.request,
            &record.response,
        )?;
        ensure(
            record.change_id == *id
                && record.target == super::key_package_state::own(state)
                && super::join_recovery_state::get(state)?
                    .records
                    .get(id)
                    .is_some_and(|r| r.installed)
                && state
                    .key_packages
                    .as_ref()
                    .and_then(|p| p.packages.get(&record.key_package_sha256))
                    .is_some_and(|p| p.consumed)
                && s.challenges
                    .values()
                    .any(|c| c.request == record.request && c.status == ChallengeStatus::Consumed),
            "w1_binding_mismatch",
            "目标安装关联或消费事实不完整",
        )?;
    }
    associations::artifacts(state, s)?;
    budget(state, 0)
}
