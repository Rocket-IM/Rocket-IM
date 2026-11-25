//! 合成可信启动边界：准确配置摘要由宿主独立固定，不接收网络授权参数。
use super::{checked, ensure, join_recovery_witness_state as stored, state::DeviceState, LabError};
use crate::{
    join_recovery::{self as p, witness as w},
    permission::Member,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    activation_bytes: String,
    policy_bytes: Option<String>,
    control_domains: Vec<stored::ControlDomain>,
}
pub(super) fn activate(state: &mut DeviceState) -> Result<Value, LabError> {
    let path = std::env::var_os("RIM_RECOVERY_WITNESS_CONFIG")
        .map(PathBuf::from)
        .ok_or_else(|| LabError::new("w1_activation_unauthorized", "缺可信启动配置"))?;
    ensure(
        path.is_absolute(),
        "w1_activation_unauthorized",
        "配置路径须绝对路径",
    )?;
    let bytes = super::rollback_io::read_file(&path, 65536)?;
    let hash = crate::permission::commit_digest(&bytes);
    let pin = std::env::var("RIM_RECOVERY_WITNESS_CONFIG_SHA256")
        .map_err(|_| LabError::new("w1_activation_unauthorized", "缺独立固定配置摘要"))?;
    ensure(
        pin == hash,
        "w1_activation_unauthorized",
        "配置未获宿主准确原字节授权",
    )?;
    let config: Config = checked("w1_activation_unauthorized", serde_json::from_slice(&bytes))?;
    let activation: w::Activation = p::raw(&config.activation_bytes)?;
    w::validate_activation(&activation)?;
    ensure(
        activation.scope.service_id == state.context.service
            && super::join_recovery_state::checkpoint(state)
                .is_ok_and(|cp| cp.conversation_id == activation.scope.conversation_id),
        "w1_binding_mismatch",
        "启用范围不符",
    )?;
    let policy = match config.policy_bytes {
        Some(encoded) => {
            let (policy, reference) = w::parse_policy_bytes(&encoded)?;
            ensure(
                activation.policy_ref.as_ref() == Some(&reference)
                    && policy.scope == activation.scope
                    && policy.target == activation.target,
                "w1_policy_mismatch",
                "可信启用、策略或授权出处不符",
            )?;
            Some(w::PolicyEnvelope {
                policy_ref: reference,
                policy_bytes: encoded,
            })
        }
        None => {
            ensure(
                activation.policy_ref.is_none(),
                "w1_policy_mismatch",
                "缺策略原件",
            )?;
            None
        }
    };
    let revision = activation
        .activation_version
        .parse::<u64>()
        .map_err(|_| LabError::new("w1_activation_rollback", "修订号无效"))?;
    if let Some(old) = state
        .witness_state
        .as_ref()
        .and_then(|s| s.activations.last())
    {
        let previous: w::Activation = p::raw(&old.activation_bytes)?;
        if revision == previous.activation_version.parse::<u64>().unwrap_or(0) {
            ensure(
                old.activation_bytes == config.activation_bytes && old.config_sha256 == hash,
                "w1_activation_rollback",
                "相同修订不可替换原件",
            )?;
            return Ok(json!({"duplicate":true,"version":3,"activation":previous}));
        }
        ensure(
            revision
                > previous
                    .activation_version
                    .parse::<u64>()
                    .unwrap_or(u64::MAX)
                && activation.scope == previous.scope
                && activation.target == previous.target,
            "w1_activation_rollback",
            "启用修订回退或范围变化",
        )?;
    }
    let mut members = std::collections::BTreeSet::new();
    for domain in &config.control_domains {
        crate::key_package::member(&domain.member)?;
        crate::permission::types::id(&domain.control_domain_id)?;
        ensure(
            members.insert((
                domain.member.account_id.clone(),
                domain.member.device_id.clone(),
            )),
            "w1_activation_unauthorized",
            "控制域身份重复",
        )?;
    }
    if let (Some(reference), Some(previous)) = (&activation.policy_ref, &state.witness_state) {
        for record in &previous.activations {
            let old: w::Activation = p::raw(&record.activation_bytes)?;
            if old.policy_ref.as_ref() == Some(reference) {
                // 控制域是 P 的可信资格出处；不能借新启用修订静默替换旧 P 的含义。
                ensure(
                    record.control_domains == config.control_domains,
                    "w1_policy_mismatch",
                    "相同 P 的控制域出处不可改写",
                )?;
            }
        }
    }
    let s = state
        .witness_state
        .get_or_insert_with(stored::State::default);
    if let Some(policy) = policy {
        if let Some(old) = s.policies.get(&policy.policy_ref.policy_sha256) {
            ensure(*old == policy, "w1_policy_mismatch", "策略摘要对应原件改变")?;
        }
        s.policies
            .insert(policy.policy_ref.policy_sha256.clone(), policy);
    }
    s.activations.push(stored::ActivationRecord {
        activation_bytes: config.activation_bytes,
        config_sha256: hash,
        control_domains: config.control_domains,
    });
    state.version = 3;
    stored::validate(state)?;
    Ok(json!({"duplicate":false,"version":3,"activation":activation}))
}
pub(super) fn eligible(
    state: &DeviceState,
    reference: &w::PolicyRef,
    policy: &w::Policy,
    actor: &Member,
) -> Result<(), LabError> {
    let target = &policy.target;
    let witness = &policy.witness;
    ensure(
        witness != actor
            && witness != target
            && witness.signature_key != actor.signature_key
            && witness.signature_key != target.signature_key
            && (witness.account_id != actor.account_id || witness.device_id != actor.device_id)
            && (witness.account_id != target.account_id || witness.device_id != target.device_id),
        "w1_witness_ineligible",
        "W 不能是 A/T 或复用其签名钥",
    )?;
    // 用引用该策略的启用原件保留当时控制域，不让新配置改写旧候选的信任声明。
    let activation = stored::get(state)?
        .activations
        .iter()
        .find(|a| {
            p::raw::<w::Activation>(&a.activation_bytes)
                .is_ok_and(|a| a.policy_ref.as_ref() == Some(reference))
        })
        .ok_or_else(|| LabError::new("w1_policy_mismatch", "策略无可信启用出处"))?;
    let domain = |member: &Member| {
        activation
            .control_domains
            .iter()
            .find(|d| d.member == *member)
            .map(|d| d.control_domain_id.as_str())
    };
    let wd = domain(witness)
        .ok_or_else(|| LabError::new("w1_witness_ineligible", "W 无独立控制域确认"))?;
    let ad =
        domain(actor).ok_or_else(|| LabError::new("w1_witness_ineligible", "A 无控制域确认"))?;
    let td =
        domain(target).ok_or_else(|| LabError::new("w1_witness_ineligible", "T 无控制域确认"))?;
    ensure(
        wd != ad && wd != td && wd == policy.independence.control_domain_id,
        "w1_witness_ineligible",
        "W 与 A/T 控制域不独立",
    )?;
    ensure(
        super::join_recovery_state::checkpoint(state)?
            .members
            .contains(witness),
        "w1_witness_ineligible",
        "W 不是当前准确幸存者",
    )?;
    super::key_packages::target_ready(state, witness)?;
    super::identity_gate::require(
        state,
        &super::identity_state::object(
            &policy.scope.service_id,
            &witness.account_id,
            &witness.device_id,
            &witness.signature_key,
        ),
    )
}
pub(super) fn intent(state: &DeviceState, i: &p::Intent) -> Result<(), LabError> {
    if state.witness_state.is_none() {
        return ensure(
            i.policy_ref.is_none(),
            "w1_policy_missing",
            "W1 新链必须先可信启用",
        );
    }
    let activation = stored::activation(state)?;
    let s = stored::get(state)?;
    let expected = s
        .candidate_policies
        .get(&i.change_id)
        .or(activation.policy_ref.as_ref())
        .ok_or_else(|| LabError::new("w1_policy_missing", "W1 已启用但尚无指定 W"))?;
    let reference = i
        .policy_ref
        .as_ref()
        .ok_or_else(|| LabError::new("w1_policy_upgrade_required", "启用后禁止新建旧版恢复"))?;
    ensure(
        expected == reference,
        "w1_policy_mismatch",
        "候选固定 P 不可换绑",
    )?;
    let envelope = stored::policy(state, reference)?;
    let policy = w::parse_policy(envelope)?;
    ensure(
        super::join_recovery_state::checkpoint(state)?
            .members
            .contains(&policy.witness),
        "w1_no_eligible_witness",
        "候选创建前没有指定的准确幸存者",
    )?;
    w::validate_intent_policy(i, envelope)?;
    eligible(state, reference, &policy, &i.actor)
}
pub(super) fn pin(state: &mut DeviceState, i: &p::Intent) -> Result<(), LabError> {
    if let Some(reference) = &i.policy_ref {
        let s = stored::get_mut(state)?;
        if let Some(old) = s.candidate_policies.get(&i.change_id) {
            ensure(
                old == reference,
                "w1_policy_mismatch",
                "已知候选 P 永久不可改写",
            )?;
        } else {
            s.candidate_policies
                .insert(i.change_id.clone(), reference.clone());
        }
    }
    Ok(())
}
