use super::{bootstrap, checkpoint, prepare, resign, Fixture};
use crate::{
    lab::codec,
    permission::{self, Proof},
};
use serde_json::{json, Value};
use std::fs;

fn proof_for_commit(
    f: &Fixture,
    cp: &permission::PermissionCheckpoint,
    commit: &str,
    to: Value,
    actor: &str,
) -> Proof {
    let mut proof = Proof {
        statement_bytes: String::new(),
        signature_bytes: String::new(),
        commit_bytes: commit.into(),
    };
    let statement = json!({"protocol_version":"rim-permission-1","change_id":"boundary","service_id":"S1","conversation_id":"G1",
        "actor":{"account_id":actor,"device_id":actor},"previous_authorization_version":"1","authorization_version":"2",
        "from_state_ref":cp.crypto_state_ref,"to_state_ref":to,"action":{"kind":"remove_member","account_id":"C"},
        "commit_sha256":permission::commit_digest(&codec::decode(commit).unwrap()),"nonce":"33".repeat(32),
        "issued_at_unix_secs":"1","expires_at_unix_secs":"301"});
    resign(f, actor, &mut proof, &statement);
    proof
}

#[test]
fn permission_apply_checks_real_mls_actor_even_when_public_signature_is_valid() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    let removal = f.call(
        "B",
        json!({"operation":"remove","id":"legacyB","member":"C"}),
    );
    let to = f.call("B", json!({"operation":"wire_inspect"}))["crypto_state_ref"].clone();
    f.call(
        "A",
        json!({"operation":"permission_bootstrap","checkpoint":cp}),
    );
    let proof = proof_for_commit(&f, &cp, removal["commit"].as_str().unwrap(), to, "A");
    permission::verify(&cp, &proof).unwrap();
    let before = fs::read(f.root.join("A/state.enc")).unwrap();
    f.fails(
        "A",
        json!({"operation":"permission_apply","change":proof}),
        "permission_commit",
    );
    assert_eq!(before, fs::read(f.root.join("A/state.enc")).unwrap());
    let valid = prepare(&f, "A", "valid");
    f.call("A", json!({"operation":"permission_apply","change":valid}));
}

#[test]
fn permission_apply_checks_exact_removal_and_not_only_commit_hash() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    let removal = f.call(
        "A",
        json!({"operation":"remove","id":"removeB","member":"B"}),
    );
    let to = f.call("A", json!({"operation":"wire_inspect"}))["crypto_state_ref"].clone();
    f.call(
        "C",
        json!({"operation":"permission_bootstrap","checkpoint":cp}),
    );
    let proof = proof_for_commit(&f, &cp, removal["commit"].as_str().unwrap(), to, "A");
    permission::verify(&cp, &proof).unwrap();
    let before = fs::read(f.root.join("C/state.enc")).unwrap();
    f.fails(
        "C",
        json!({"operation":"permission_apply","change":proof}),
        "permission_commit",
    );
    assert_eq!(before, fs::read(f.root.join("C/state.enc")).unwrap());
    let mut valid = proof.clone();
    let mut statement: Value =
        serde_json::from_slice(&codec::decode(&proof.statement_bytes).unwrap()).unwrap();
    statement["action"] = json!({"kind":"remove_member","account_id":"B"});
    resign(&f, "A", &mut valid, &statement);
    f.call("C", json!({"operation":"permission_apply","change":valid}));
}

#[test]
fn permission_apply_checks_actual_next_context_without_consuming_good_commit() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    bootstrap(&f, &cp);
    let proof = prepare(&f, "A", "change1");
    let mut changed = proof.clone();
    let mut statement: Value =
        serde_json::from_slice(&codec::decode(&proof.statement_bytes).unwrap()).unwrap();
    statement["to_state_ref"] = json!("00".repeat(32));
    resign(&f, "A", &mut changed, &statement);
    permission::verify(&cp, &changed).unwrap();
    let before = fs::read(f.root.join("B/state.enc")).unwrap();
    f.fails(
        "B",
        json!({"operation":"permission_apply","change":changed}),
        "permission_commit",
    );
    assert_eq!(before, fs::read(f.root.join("B/state.enc")).unwrap());
    f.call("B", json!({"operation":"permission_apply","change":proof}));
}

#[test]
fn permission_public_rules_cover_revoke_owner_key_reuse_and_u64_overflow() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    bootstrap(&f, &cp);
    let proof = prepare(&f, "A", "change1");
    let mut duplicate_key = cp.clone();
    duplicate_key.members[1].signature_key = duplicate_key.members[0].signature_key.clone();
    assert_eq!(
        permission::verify(&duplicate_key, &proof).unwrap_err().code,
        "invalid_permission"
    );
    let mut same_account = cp.clone();
    same_account.members[1].account_id = "A".into();
    let mut statement: Value =
        serde_json::from_slice(&codec::decode(&proof.statement_bytes).unwrap()).unwrap();
    statement["action"] = json!({"kind":"revoke_device","account_id":"A","device_id":"B"});
    let mut changed = proof.clone();
    resign(&f, "A", &mut changed, &statement);
    assert_eq!(
        permission::verify(&same_account, &changed)
            .unwrap()
            .0
            .members
            .len(),
        2
    );
    statement["action"] = json!({"kind":"revoke_device","account_id":"C","device_id":"C"});
    resign(&f, "A", &mut changed, &statement);
    assert_eq!(
        permission::verify(&same_account, &changed)
            .unwrap_err()
            .code,
        "permission_denied"
    );
    statement["action"] = json!({"kind":"remove_member","account_id":"A"});
    resign(&f, "A", &mut changed, &statement);
    assert_eq!(
        permission::verify(&cp, &changed).unwrap_err().code,
        "permission_denied"
    );
    let mut maximum = cp.clone();
    maximum.authorization_version = u64::MAX.to_string();
    statement["action"] = json!({"kind":"remove_member","account_id":"C"});
    statement["previous_authorization_version"] = json!(u64::MAX.to_string());
    statement["authorization_version"] = json!("0");
    resign(&f, "A", &mut changed, &statement);
    assert_eq!(
        permission::verify(&maximum, &changed).unwrap_err().code,
        "permission_version"
    );
}

#[test]
fn permission_verifier_json_and_cached_control_cannot_bypass_policy() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    bootstrap(&f, &cp);
    let proof = prepare(&f, "A", "change1");
    let request = json!({"checkpoint":cp,"change":proof}).to_string();
    permission::execute(&request).unwrap();
    let duplicate = request.replacen('{', "{\"checkpoint\":{},", 1);
    assert_eq!(
        permission::execute(&duplicate).unwrap_err().code,
        "invalid_permission"
    );
    let mut statement: Value =
        serde_json::from_slice(&codec::decode(&proof.statement_bytes).unwrap()).unwrap();
    statement["extra"] = json!(true);
    let mut changed = proof.clone();
    resign(&f, "A", &mut changed, &statement);
    assert_eq!(
        permission::verify(&cp, &changed).unwrap_err().code,
        "invalid_permission"
    );
    let peers:Vec<_>=f.identities[1..].iter().map(|p|json!({"account":p["account"],"device":p["device"],"signature_key":p["signature_key"],"key_package":p["key_package"]})).collect();
    f.fails(
        "A",
        json!({"operation":"create","peers":peers}),
        "signed_permission_required",
    );
}
