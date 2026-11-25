//! 仅检查公开持久原件；冻结格式向量中的占位 MLS 从不进入处理器。
use super::*;
use crate::lab::{codec, Context};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../api/realtime/join-recovery-witness-vectors.json"
    ))
    .unwrap()
}
fn enabled() -> DeviceState {
    let v = vectors();
    let bytes = v["unsigned_objects"]["policy"]["raw_bytes"]
        .as_str()
        .unwrap();
    let (policy, reference) = w::parse_policy_bytes(bytes).unwrap();
    let activation: w::Activation = w::parse_activation(
        v["unsigned_objects"]["activation"]["raw_bytes"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut state = DeviceState::new(Context {
        service: policy.scope.service_id.clone(),
        account: policy.target.account_id.clone(),
        device: policy.target.device_id.clone(),
    })
    .unwrap();
    state.version = 3;
    state.witness_state = Some(State {
        activations: vec![ActivationRecord {
            activation_bytes: codec::encode(&serde_json::to_vec(&activation).unwrap()),
            config_sha256: "11".repeat(32),
            control_domains: vec![ControlDomain {
                member: policy.witness,
                control_domain_id: policy.independence.control_domain_id,
            }],
        }],
        policies: [(
            reference.policy_sha256.clone(),
            w::PolicyEnvelope {
                policy_ref: reference,
                policy_bytes: bytes.into(),
            },
        )]
        .into(),
        ..State::default()
    });
    state
}
#[test]
fn loading_rejects_orphan_candidate_policy_without_mutating_state() {
    let mut state = enabled();
    validate(&state).unwrap();
    let ledger = state.witness_state.as_mut().unwrap();
    let reference = ledger.policies.values().next().unwrap().policy_ref.clone();
    ledger
        .candidate_policies
        .insert("orphan_candidate".into(), reference);
    let before = serde_json::to_vec(&state).unwrap();
    assert_eq!(validate(&state).unwrap_err().code, "w1_binding_mismatch");
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}
#[test]
fn loading_rejects_same_policy_with_changed_control_domains() {
    let mut state = enabled();
    let ledger = state.witness_state.as_mut().unwrap();
    let mut revision = ledger.activations[0].clone();
    let mut activation = w::parse_activation(&revision.activation_bytes).unwrap();
    activation.activation_version = "2".into();
    revision.activation_bytes = codec::encode(&serde_json::to_vec(&activation).unwrap());
    revision.control_domains[0].control_domain_id = "different_control_domain".into();
    ledger.activations.push(revision);
    assert_eq!(validate(&state).unwrap_err().code, "w1_policy_mismatch");
}
