//! 加载时从保存的准确 R0 重建公开关联，不把 installed 布尔值当作执行证明。
use super::*;
use crate::lab::{join_recovery_state as recovery, join_recovery_witness as flow};
use std::collections::BTreeSet;

pub(super) fn activation_history(state: &DeviceState, s: &State) -> Result<(), LabError> {
    let mut fixed = BTreeMap::new();
    let mut previous: Option<w::Activation> = None;
    for record in &s.activations {
        let a = w::parse_activation(&record.activation_bytes)?;
        crate::permission::types::hash(&record.config_sha256)?;
        if let Some(old) = previous {
            ensure(
                a.scope == old.scope && a.target == old.target,
                "w1_activation_rollback",
                "启用历史范围或目标改变",
            )?;
        }
        previous = Some(a.clone());
        let mut members = BTreeSet::new();
        for domain in &record.control_domains {
            crate::key_package::member(&domain.member)?;
            crate::permission::types::id(&domain.control_domain_id)?;
            ensure(
                members.insert(domain.member.identity()),
                "w1_activation_unauthorized",
                "持久控制域身份重复",
            )?;
        }
        if let Some(reference) = a.policy_ref {
            if let Some(old) =
                fixed.insert(reference.policy_sha256.clone(), &record.control_domains)
            {
                ensure(
                    old == &record.control_domains,
                    "w1_policy_mismatch",
                    "相同 P 的历史控制域出处不一致",
                )?;
            }
        }
    }
    for (hash, envelope) in &s.policies {
        ensure(
            *hash == envelope.policy_ref.policy_sha256 && fixed.contains_key(hash),
            "w1_policy_mismatch",
            "策略原件缺准确可信启用出处",
        )?;
        policy(state, &envelope.policy_ref)?;
    }
    Ok(())
}

pub(super) fn candidates(state: &DeviceState, s: &State) -> Result<(), LabError> {
    let mut found = BTreeSet::new();
    let mut bind = |id: &str, reference: Option<&w::PolicyRef>| -> Result<(), LabError> {
        if let Some(reference) = reference {
            ensure(
                s.candidate_policies.get(id) == Some(reference),
                "w1_policy_mismatch",
                "原请求或终态未绑定永久候选 P",
            )?;
            policy(state, reference)?;
            found.insert(id.to_owned());
        } else {
            ensure(
                !s.candidate_policies.contains_key(id),
                "w1_policy_mismatch",
                "旧候选不能追补新 P",
            )?;
        }
        Ok(())
    };
    if let Some(r) = &state.join_recovery {
        for proof in r.requests.values() {
            match p::parse_request(proof)? {
                p::Request::Intent(i) => {
                    bind(&i.change_id, i.policy_ref.as_ref())?;
                    if let Some(reference) = &i.policy_ref {
                        w::validate_intent_policy(&i, policy(state, reference)?)?;
                    }
                }
                p::Request::Control(c) => bind(&c.change_id, c.policy_ref.as_ref())?,
            }
        }
        for accepted in r.records.values() {
            let i = p::parse_intent(&accepted.record.public().bundle.intent)?;
            bind(&i.change_id, i.policy_ref.as_ref())?;
        }
        for receipt in r.closed.values() {
            let value = p::verify_receipt(recovery::key(state)?, receipt)?;
            bind(&value.change_id, value.policy_ref.as_ref())?;
        }
        if let Some(pending) = &r.pending {
            let i = p::parse_intent(&pending.bundle.intent)?;
            bind(&i.change_id, i.policy_ref.as_ref())?;
        }
        // 冲突观察可能保留未进入实际链的候选；只用于证明已有 pin 有对应原件。
        for observation in &r.observations {
            let proof = match observation {
                crate::lab::join_recovery_evidence::Observation::Accepted { record } => {
                    &record.bundle.intent
                }
                crate::lab::join_recovery_evidence::Observation::Closed { intent, .. } => intent,
            };
            let i = p::parse_intent(proof)?;
            if i.policy_ref
                .as_ref()
                .is_some_and(|p| s.candidate_policies.get(&i.change_id) == Some(p))
            {
                found.insert(i.change_id);
            }
        }
    }
    for (id, reference) in &s.candidate_policies {
        policy(state, reference)?;
        ensure(
            found.contains(id),
            "w1_binding_mismatch",
            "候选 P 缺少保存的原请求或终态",
        )?;
    }
    Ok(())
}

struct AcceptedContext {
    intent: p::Intent,
    statement: p::Statement,
    public: p::PublicRecord,
    reference: p::AdmissionRef,
    previous: w::CompleteCheckpoint,
    next: w::CompleteCheckpoint,
}
fn accepted(state: &DeviceState, id: &str, installed: bool) -> Result<AcceptedContext, LabError> {
    let saved = recovery::get(state)?
        .records
        .get(id)
        .ok_or_else(|| LabError::new("w1_binding_mismatch", "缺少保存的准确 R0"))?;
    ensure(
        !installed || saved.installed,
        "w1_witness_not_installed",
        "R0 尚未实际安装",
    )?;
    let public = saved.record.public();
    // 复用完整公开验签/绑定；这里只读，不恢复 provider 或重新处理 Commit。
    let (intent, statement) = flow::context(state, &public)?;
    let reference = intent
        .policy_ref
        .as_ref()
        .ok_or_else(|| LabError::new("w1_policy_mismatch", "W1 关联不能绑定旧候选"))?;
    w::validate_intent_policy(&intent, policy(state, reference)?)?;
    ensure(
        get(state)?.candidate_policies.get(id) == Some(reference),
        "w1_policy_mismatch",
        "安装候选缺少永久 P",
    )?;
    let epoch = crate::permission::types::decimal(&statement.action.previous_epoch)?;
    let previous = w::CompleteCheckpoint {
        group_id: statement.scope.group_id.clone(),
        epoch: epoch.to_string(),
        checkpoint: saved.predecessor.clone(),
    };
    let mut next = previous.clone();
    next.epoch = epoch
        .checked_add(1)
        .ok_or_else(|| LabError::new("w1_binding_mismatch", "epoch 溢出"))?
        .to_string();
    next.checkpoint.authorization_version = statement.authorization_version.clone();
    next.checkpoint.crypto_state_ref = statement.to_state_ref.clone();
    Ok(AcceptedContext {
        reference: p::admission_ref(id, &public.bundle.change, &public.receipt)?,
        intent,
        statement,
        public,
        previous,
        next,
    })
}
fn fact_binding(
    fact: &w::InstallationFact,
    c: &AcceptedContext,
    witness: &Member,
) -> Result<(), LabError> {
    ensure(
        Some(&fact.policy_ref) == c.intent.policy_ref.as_ref()
            && fact.scope == c.intent.scope
            && fact.actor == c.intent.actor
            && fact.target == c.intent.signer
            && fact.witness == *witness
            && fact.accepted_ref == c.reference
            && fact.commit_sha256 == c.statement.commit_sha256
            && fact.welcome_sha256 == c.statement.action.welcome_sha256
            && fact.key_package_sha256 == c.statement.action.key_package_sha256
            && fact.key_package_ref == c.statement.action.key_package_ref
            && fact.previous == c.previous
            && fact.next == c.next,
        "w1_binding_mismatch",
        "安装事实与准确 R0 的材料或完整前后检查点不符",
    )
}
pub(super) fn artifacts(state: &DeviceState, s: &State) -> Result<(), LabError> {
    for challenge in s.challenges.values() {
        let r = w::verify_witness_request(
            policy(
                state,
                &w::parse_witness_request(&challenge.request)?.policy_ref,
            )?,
            &challenge.request,
        )?;
        let c = accepted(state, &r.change_id, false)?;
        flow::binding(&r, &c.intent, &c.statement, &c.public)?;
        let ttl = crate::permission::types::decimal(&challenge.requested_ttl)?;
        let duration = crate::permission::types::decimal(&r.expires_at_unix_secs)?
            - crate::permission::types::decimal(&r.issued_at_unix_secs)?;
        ensure(
            (1..=60).contains(&ttl) && duration <= ttl,
            "w1_binding_mismatch",
            "挑战与原请求窗口不符",
        )?;
        if challenge.status == ChallengeStatus::Consumed {
            ensure(
                s.installed
                    .get(&r.change_id)
                    .is_some_and(|i| i.request == challenge.request),
                "w1_binding_mismatch",
                "已消费挑战缺少准确安装关联",
            )?;
        }
    }
    for (id, encoded) in &s.installation_facts {
        let fact: w::InstallationFact = p::raw(encoded)?;
        let c = accepted(state, id, true)?;
        let configured = w::parse_policy(policy(state, &fact.policy_ref)?)?;
        fact_binding(&fact, &c, &configured.witness)?;
    }
    for response in s.responses.values() {
        w::validate_delivery(&response.delivery)?;
        let q = w::parse_witness_request(&response.request)?;
        let r = w::verify_witness_response(
            policy(state, &q.policy_ref)?,
            &response.request,
            &response.delivery.response,
        )?;
        let c = accepted(state, &r.change_id, true)?;
        flow::binding(&q, &c.intent, &c.statement, &c.public)?;
        let fact: w::InstallationFact = p::raw(
            s.installation_facts
                .get(&r.change_id)
                .ok_or_else(|| LabError::new("w1_witness_not_installed", "响应缺安装原件"))?,
        )?;
        ensure(
            r.previous == c.previous
                && r.next == c.next
                && r.installation_ref.source_id == r.change_id
                && crate::permission::types::decimal(&fact.installed_at_unix_secs)?
                    <= crate::permission::types::decimal(&r.issued_at_unix_secs)?,
            "w1_binding_mismatch",
            "响应未绑定安装原件及完整检查点",
        )?;
    }
    for (id, installed) in &s.installed {
        let c = accepted(state, id, true)?;
        let q = w::parse_witness_request(&installed.request)?;
        flow::binding(&q, &c.intent, &c.statement, &c.public)?;
        let r = w::parse_witness_response(&installed.response)?;
        let package = state
            .key_packages
            .as_ref()
            .and_then(|p| p.packages.get(&installed.key_package_sha256))
            .ok_or_else(|| LabError::new("w1_binding_mismatch", "安装缺准确本机材料"))?;
        ensure(
            installed.actual_next == c.next
                && r.previous == c.previous
                && r.next == c.next
                && package.material.key_package_ref == installed.key_package_ref
                && package.material.key_package_sha256 == installed.key_package_sha256,
            "w1_binding_mismatch",
            "目标实际安装、见证或材料与 R0 不符",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn installation_fact_rechecks_every_material_and_checkpoint_binding() {
        // 只取冻结公开字段做关联投影；不解析或执行占位 Commit/Welcome。
        let v: Value = serde_json::from_str(include_str!(
            "../../../../../api/realtime/join-recovery-witness-vectors.json"
        ))
        .unwrap();
        let fact: w::InstallationFact = p::raw(
            v["unsigned_objects"]["installation_fact"]["raw_bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let proof = |name: &str| {
            serde_json::from_value(v["format_envelopes"][name]["envelope"].clone()).unwrap()
        };
        let c = AcceptedContext {
            intent: serde_json::from_value(v["format_envelopes"]["intent"]["decoded"].clone())
                .unwrap(),
            statement: serde_json::from_value(
                v["format_envelopes"]["candidate"]["decoded"].clone(),
            )
            .unwrap(),
            public: p::PublicRecord {
                bundle: p::PublicBundle {
                    intent: proof("intent"),
                    claim: proof("claim"),
                    allocation: proof("allocation"),
                    change: serde_json::from_value(v["candidate_proof"].clone()).unwrap(),
                },
                receipt: proof("accepted"),
            },
            reference: fact.accepted_ref.clone(),
            previous: fact.previous.clone(),
            next: fact.next.clone(),
        };
        fact_binding(&fact, &c, &fact.witness).unwrap();
        for (field, replacement) in [
            ("commit_sha256", json!("31".repeat(32))),
            ("welcome_sha256", json!("32".repeat(32))),
            ("key_package_sha256", json!("33".repeat(32))),
            ("key_package_ref", json!("AQ==")),
            ("actor", json!(fact.target)),
            ("target", json!(fact.actor)),
            ("witness", json!(fact.actor)),
            (
                "accepted_ref",
                json!({"change_id":"another","record_sha256":"34".repeat(32)}),
            ),
            ("previous", json!(fact.next)),
            ("next", json!(fact.previous)),
        ] {
            let mut changed = serde_json::to_value(&fact).unwrap();
            changed[field] = replacement;
            let changed: w::InstallationFact = serde_json::from_value(changed).unwrap();
            assert_eq!(
                fact_binding(&changed, &c, &fact.witness).unwrap_err().code,
                "w1_binding_mismatch",
                "{field}"
            );
        }
    }
}
