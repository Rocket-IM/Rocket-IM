use super::{codec, store::LockedDevice, wire_tests::Fixture, Context};
use crate::permission::{self, PermissionCheckpoint, Proof, SIGNING_DOMAIN};
use openmls_traits::signatures::Signer;
use serde_json::{json, Value};
use std::fs;

#[path = "permission_boundary_tests.rs"]
mod boundary;
#[path = "recovery_tests.rs"]
mod recovery;

fn checkpoint(f: &Fixture) -> PermissionCheckpoint {
    let members: Vec<_> = f
        .identities
        .iter()
        .map(|identity| {
            json!({"account_id":identity["account"],
        "device_id":identity["device"],"signature_key":identity["signature_key"]})
        })
        .collect();
    serde_json::from_value(json!({"service_id":"S1","conversation_id":"G1","authorization_version":"1",
        "crypto_state_ref":f.call("A",json!({"operation":"wire_inspect"}))["crypto_state_ref"],"owner_account_id":"A","members":members})).unwrap()
}

fn bootstrap(f: &Fixture, checkpoint: &PermissionCheckpoint) {
    for device in ["A", "B", "C"] {
        f.call(
            device,
            json!({"operation":"permission_bootstrap","checkpoint":checkpoint}),
        );
    }
}

fn prepare(f: &Fixture, device: &str, id: &str) -> Proof {
    serde_json::from_value(
        f.call(
            device,
            json!({"operation":"permission_prepare","change_id":id,
        "action":{"kind":"remove_member","account_id":"C"}}),
        )["change"]
            .clone(),
    )
    .unwrap()
}

fn resign(f: &Fixture, device: &str, proof: &mut Proof, statement: &Value) {
    let locked = LockedDevice::open(&f.root.join(device)).unwrap();
    let state = locked
        .load(&Context {
            service: "S1".into(),
            account: device.into(),
            device: device.into(),
        })
        .unwrap()
        .unwrap();
    let raw = serde_json::to_vec(statement).unwrap();
    let mut signed = SIGNING_DOMAIN.to_vec();
    signed.extend(&raw);
    proof.statement_bytes = codec::encode(&raw);
    proof.signature_bytes = codec::encode(&state.signer().unwrap().sign(&signed).unwrap());
}

#[test]
fn signed_permission_prepare_is_persistent_and_apply_advances_both_peers() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    bootstrap(&f, &cp);
    f.fails(
        "A",
        json!({"operation":"permission_bootstrap","checkpoint":cp}),
        "permission_conflict",
    );
    f.fails("B",json!({"operation":"permission_prepare","change_id":"bad","action":{"kind":"remove_member","account_id":"C"}}),"permission_denied");
    let proof = prepare(&f, "A", "change1");
    assert_eq!(proof, prepare(&f, "A", "change1"));
    assert_eq!(
        f.call("A", json!({"operation":"wire_inspect"}))["crypto_state_ref"],
        cp.crypto_state_ref
    );
    f.fails("A",json!({"operation":"wire_send","logical_message_id":"blocked","attempt_id":"P1","payload":"test"}),"permission_pending");
    let (next, _) = permission::verify(&cp, &proof).unwrap();
    for device in ["A", "B"] {
        let applied = f.call(
            device,
            json!({"operation":"permission_apply","change":proof}),
        );
        assert_eq!(applied["checkpoint"], serde_json::to_value(&next).unwrap());
        assert_eq!(
            f.call(
                device,
                json!({"operation":"permission_apply","change":proof})
            )["duplicate"],
            true
        );
        assert_eq!(
            f.call(device, json!({"operation":"wire_inspect"}))["configuration"]
                ["authorization_version"],
            "2"
        );
    }
    // 已验证设备签名仍不能替代 Service 回执信任，默认发送门明确拒绝。
    f.fails(
        "A",
        json!({"operation":"wire_send","logical_message_id":"after_signed_change",
        "attempt_id":"P1","payload":"test"}),
        "receipt_pin_required",
    );
    f.fails(
        "B",
        json!({"operation":"wire_configure","conversation_id":"G1","authorization_version":"99"}),
        "signed_permission_required",
    );
    let mut conflict = proof.clone();
    conflict.signature_bytes = codec::encode(&[0; 64]);
    f.fails(
        "B",
        json!({"operation":"permission_apply","change":conflict}),
        "permission_conflict",
    );
}

#[test]
fn signed_permission_verifier_rejects_changes_to_every_authenticated_component() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    bootstrap(&f, &cp);
    let proof = prepare(&f, "A", "change1");
    let mut changed = proof.clone();
    changed.signature_bytes = codec::encode(&[0; 64]);
    assert_eq!(
        permission::verify(&cp, &changed).unwrap_err().code,
        "permission_signature"
    );
    let mut changed = proof.clone();
    changed.commit_bytes = codec::encode(&[1, 2, 3]);
    assert_eq!(
        permission::verify(&cp, &changed).unwrap_err().code,
        "permission_commit"
    );
    let mut changed = proof.clone();
    let raw = codec::decode(&changed.statement_bytes).unwrap();
    let mut whitespace = vec![b' '];
    whitespace.extend(raw.clone());
    changed.statement_bytes = codec::encode(&whitespace);
    assert_eq!(
        permission::verify(&cp, &changed).unwrap_err().code,
        "permission_signature"
    );
    let mut statement: Value = serde_json::from_slice(&raw).unwrap();
    statement["actor"] = json!({"account_id":"B","device_id":"B"});
    let mut changed = proof.clone();
    resign(&f, "B", &mut changed, &statement);
    assert_eq!(
        permission::verify(&cp, &changed).unwrap_err().code,
        "permission_denied"
    );
    let mut statement: Value = serde_json::from_slice(&raw).unwrap();
    statement["authorization_version"] = json!("3");
    resign(&f, "A", &mut changed, &statement);
    assert_eq!(
        permission::verify(&cp, &changed).unwrap_err().code,
        "permission_version"
    );
    statement["authorization_version"] = json!("2");
    statement["issued_at_unix_secs"] = json!("1");
    statement["expires_at_unix_secs"] = json!("301");
    resign(&f, "A", &mut changed, &statement);
    permission::verify(&cp, &changed).unwrap();
    statement["expires_at_unix_secs"] = json!("302");
    resign(&f, "A", &mut changed, &statement);
    assert_eq!(
        permission::verify(&cp, &changed).unwrap_err().code,
        "invalid_permission"
    );
}

#[test]
fn signed_permission_pending_conflict_preserves_candidate_and_blocks_legacy() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    bootstrap(&f, &cp);
    let proof = prepare(&f, "A", "change1");
    let mut other = proof.clone();
    let mut statement: Value =
        serde_json::from_slice(&codec::decode(&proof.statement_bytes).unwrap()).unwrap();
    statement["change_id"] = json!("other");
    resign(&f, "A", &mut other, &statement);
    let before = fs::read(f.root.join("A/state.enc")).unwrap();
    f.fails(
        "A",
        json!({"operation":"permission_apply","change":other}),
        "pending_conflict",
    );
    f.fails("A",json!({"operation":"permission_prepare","change_id":"other","action":{"kind":"remove_member","account_id":"C"}}),"pending_conflict");
    f.fails(
        "A",
        json!({"operation":"remove","id":"x","member":"C"}),
        "signed_permission_required",
    );
    f.fails(
        "A",
        json!({"operation":"wire_process"}),
        "permission_pending",
    );
    assert_eq!(before, fs::read(f.root.join("A/state.enc")).unwrap());
    assert_eq!(
        f.call("A", json!({"operation":"permission_inspect"}))["pending_change"],
        serde_json::to_value(&proof).unwrap()
    );
}

#[test]
fn signed_permission_unsigned_control_is_isolated_before_valid_permission_apply() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    let removal = f.call(
        "A",
        json!({"operation":"remove","id":"legacy","member":"C"}),
    );
    let to = f.call("A", json!({"operation":"wire_inspect"}))["crypto_state_ref"].clone();
    f.call(
        "B",
        json!({"operation":"permission_bootstrap","checkpoint":cp}),
    );
    let control = json!({"control_id":"legacy","from_state_ref":cp.crypto_state_ref,"to_state_ref":to,"payload_bytes":removal["commit"]});
    f.download(vec![json!({"stream_id":"B_stream","event_seq":"1","event_id":"E1","availability":"available",
        "event":{"type":"crypto_control","control":control}})],1);
    let processed = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(processed["sync"]["quarantined_count"], 1);
    assert_eq!(
        f.call("B", json!({"operation":"wire_inspect"}))["crypto_state_ref"],
        cp.crypto_state_ref
    );
    let mut proof = Proof {
        statement_bytes: String::new(),
        signature_bytes: String::new(),
        commit_bytes: removal["commit"].as_str().unwrap().into(),
    };
    let statement = json!({"protocol_version":"rim-permission-1","change_id":"signed_legacy","service_id":"S1","conversation_id":"G1",
        "actor":{"account_id":"A","device_id":"A"},"previous_authorization_version":"1","authorization_version":"2",
        "from_state_ref":cp.crypto_state_ref,"to_state_ref":to,"action":{"kind":"remove_member","account_id":"C"},
        "commit_sha256":permission::commit_digest(&codec::decode(&proof.commit_bytes).unwrap()),"nonce":"11".repeat(32),
        "issued_at_unix_secs":"1","expires_at_unix_secs":"301"});
    resign(&f, "A", &mut proof, &statement);
    f.call("B", json!({"operation":"permission_apply","change":proof}));
    assert_eq!(
        f.call("B", json!({"operation":"wire_inspect"}))["crypto_state_ref"],
        to
    );
}
