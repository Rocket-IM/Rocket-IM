//! 真正 Add/Welcome、失败后的同份材料重试与候选封口的库级回归。
use super::{
    accepted, closed, fail_atomic, recover, resign, setup, statement, Context, Fixture,
    LockedDevice, Proof,
};
use crate::lab::{codec, CrashPoint};
use crate::permission::{self, admission::JoinMaterial};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

fn fixture() -> (Fixture, SigningKey, Value) {
    let (f, key) = setup();
    let identity = f.call("D", json!({"operation":"init"}));
    let member =
        json!({"account_id":"D","device_id":"D","signature_key":identity["signature_key"]});
    for device in ["A", "B", "C"] {
        f.call(
            device,
            json!({"operation":"permission_pin_member","member":member}),
        );
    }
    f.call(
        "D",
        json!({"operation":"permission_join_anchor","checkpoint":super::checkpoint(&f),
        "relay_receipt_key":codec::encode(key.verifying_key().as_bytes())}),
    );
    (f, key, identity)
}
fn prepare_add(f: &Fixture, identity: &Value, id: &str) -> Value {
    f.call(
        "A",
        json!({"operation":"permission_prepare_add","change_id":id,
        "member":{"account_id":"D","device_id":"D","signature_key":identity["signature_key"]},
        "key_package":identity["key_package"],"history_policy":"from_join"}),
    )
}
fn proof(result: &Value) -> Proof {
    serde_json::from_value(result["change"].clone()).unwrap()
}

#[test]
fn add_welcome_joins_only_the_signed_next_checkpoint_and_preserves_empty_history() {
    let (f, key, identity) = fixture();
    let added = prepare_add(&f, &identity, "addD");
    let retry = prepare_add(&f, &identity, "addD");
    assert_eq!(added["change"], retry["change"]);
    assert_eq!(added["join"], retry["join"]);
    let record = accepted(&key, &proof(&added));
    for device in ["A", "B", "C"] {
        recover(&f, device, &record);
    }
    let operation = json!({"operation":"permission_join","record":record,"join":added["join"]});
    let result = f.call("D", operation.clone());
    assert_eq!(
        result["checkpoint"],
        f.call("A", json!({"operation":"permission_inspect"}))["checkpoint"]
    );
    assert_eq!(result["admission"]["joined_authorization_version"], "2");
    assert_eq!(
        f.call("D", json!({"operation":"wire_inspect"}))["history"]["past_epochs"],
        json!([])
    );
    assert_eq!(f.call("D", operation)["duplicate"], true);
    f.receive("D", &f.send("A", "fromA")["envelope"]);
    f.receive("B", &f.send("D", "fromD")["envelope"]);
    // 已应用候选仍能取回原材料，不会重做 Add 或生成第二个 Welcome。
    assert_eq!(prepare_add(&f, &identity, "addD")["join"], added["join"]);
}

#[test]
fn valid_signatures_do_not_replace_real_welcome_validation_or_consume_keypackage_on_error() {
    let (f, key, identity) = fixture();
    let added = prepare_add(&f, &identity, "addD");
    let original = proof(&added);
    let mut fake = original.clone();
    let mut body: Value =
        serde_json::from_slice(&codec::decode(&original.statement_bytes).unwrap()).unwrap();
    body["to_state_ref"] = json!("a".repeat(64));
    resign(&f, "A", &mut fake, &body);
    permission::verify(&super::checkpoint(&f), &fake).unwrap();
    fail_atomic(
        &f,
        "D",
        json!({"operation":"permission_join","record":accepted(&key,&fake),"join":added["join"]}),
        "welcome_context",
    );
    let mut changed = added["join"].clone();
    changed["key_package"] = f.identities[1]["key_package"].clone();
    fail_atomic(
        &f,
        "D",
        json!({"operation":"permission_join","record":accepted(&key,&original),"join":changed}),
        "join_material_mismatch",
    );
    let record = accepted(&key, &original);
    recover(&f, "A", &record);
    f.call(
        "D",
        json!({"operation":"permission_join","record":record,"join":added["join"]}),
    );
    f.receive("D", &f.send("A", "works")["envelope"]);
}

#[test]
fn signed_add_with_real_remove_commit_is_rejected_without_poisoning_receiver() {
    let (f, key, identity) = fixture();
    let added = prepare_add(&f, &identity, "addD");
    // 独立生成真正 Remove，而不是仅用无法解析的假密文测试前置校验。
    let first = proof(&added);
    recover(&f, "A", &closed(&key, &first));
    let locked = LockedDevice::open(&f.root.join("A")).unwrap();
    let state = locked
        .load(&Context {
            service: "S1".into(),
            account: "A".into(),
            device: "A".into(),
        })
        .unwrap()
        .unwrap();
    let mut group = state.group().unwrap();
    let target = group
        .members()
        .find(|m| codec::credential_context(&m.credential).unwrap().account == "C")
        .unwrap()
        .index;
    let (commit, _, _) = group
        .remove_members(&state.provider, &state.signer().unwrap(), &[target])
        .unwrap();
    let raw = commit.to_bytes().unwrap();
    drop(locked);
    let mut fake = first.clone();
    fake.commit_bytes = codec::encode(&raw);
    let mut body: Value =
        serde_json::from_slice(&codec::decode(&first.statement_bytes).unwrap()).unwrap();
    body["commit_sha256"] = json!(permission::commit_digest(&raw));
    resign(&f, "A", &mut fake, &body);
    permission::verify(&super::checkpoint(&f), &fake).unwrap();
    fail_atomic(
        &f,
        "B",
        json!({"operation":"permission_recover","record":accepted(&key,&fake)}),
        "permission_commit",
    );
    let next = prepare_add(&f, &identity, "next");
    recover(&f, "B", &accepted(&key, &proof(&next)));
}

#[test]
fn closed_add_reprepare_keeps_identity_intent_materials_and_handshake_generation() {
    let (f, key, identity) = fixture();
    let first = prepare_add(&f, &identity, "first");
    let consume = |proof: &Proof| {
        let locked = LockedDevice::open(&f.root.join("B")).unwrap();
        let mut state = locked
            .load(&Context {
                service: "S1".into(),
                account: "B".into(),
                device: "B".into(),
            })
            .unwrap()
            .unwrap();
        let mut group = state.group().unwrap();
        group
            .process_message(
                &state.provider,
                codec::protocol(&codec::decode(&proof.commit_bytes).unwrap()).unwrap(),
            )
            .unwrap();
        locked.save(&mut state, CrashPoint::None).unwrap();
    };
    consume(&proof(&first));
    recover(&f, "A", &closed(&key, &proof(&first)));
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_prepare","change_id":"wrong","action":{"kind":"remove_member","account_id":"C"}}),
        "intent_mismatch",
    );
    let next = prepare_add(&f, &identity, "next");
    assert_ne!(
        statement(&proof(&first)).action,
        statement(&proof(&next)).action
    );
    assert!(statement(&proof(&first))
        .action
        .same_intent(&statement(&proof(&next)).action));
    assert_eq!(first["join"]["key_package"], next["join"]["key_package"]);
    consume(&proof(&next));
    let record = accepted(&key, &proof(&next));
    recover(&f, "A", &record);
    recover(&f, "C", &record);
    f.call(
        "D",
        json!({"operation":"permission_join","record":record,"join":next["join"]}),
    );
    f.receive("D", &f.send("A", "afterClose")["envelope"]);
}

#[test]
fn public_join_chain_cannot_skip_own_welcome_or_create_history_from_metadata() {
    let (f, key, identity) = fixture();
    let removed = super::prepare(&f, "A", "removeC");
    let record = accepted(&key, &removed);
    recover(&f, "A", &record);
    recover(&f, "B", &record);
    let result = f.call(
        "D",
        json!({"operation":"permission_join_advance","record":record}),
    );
    assert!(result["checkpoint"].is_null());
    assert_eq!(
        result["admission"]["public_checkpoint"]["authorization_version"],
        "2"
    );
    let added = prepare_add(&f, &identity, "addD");
    let record = accepted(&key, &proof(&added));
    fail_atomic(
        &f,
        "D",
        json!({"operation":"permission_join_advance","record":record}),
        "join_required",
    );
    f.call(
        "D",
        json!({"operation":"permission_join","record":record,"join":added["join"]}),
    );
    assert_eq!(
        f.call("D", json!({"operation":"wire_inspect"}))["history"]["past_epochs"],
        json!([])
    );
}

#[test]
fn public_admission_material_validation_is_strict_and_optional_evidence_cannot_be_null() {
    let (f, _, identity) = fixture();
    let added = prepare_add(&f, &identity, "addD");
    let statement = statement(&proof(&added));
    let join: JoinMaterial = serde_json::from_value(added["join"].clone()).unwrap();
    permission::admission::verify_material(&statement, &join).unwrap();
    let mut request =
        json!({"checkpoint":super::checkpoint(&f),"change":added["change"],"join":added["join"]});
    permission::execute(&request.to_string()).unwrap();
    request["join"] = Value::Null;
    assert_eq!(
        permission::execute(&request.to_string()).unwrap_err().code,
        "invalid_permission"
    );
    let mut wrong = join;
    let mut raw = codec::decode(&wrong.key_package).unwrap();
    raw[12] ^= 1;
    wrong.key_package = codec::encode(&raw);
    let mut changed = statement;
    if let permission::Action::AddMember {
        key_package_sha256, ..
    } = &mut changed.action
    {
        *key_package_sha256 = permission::commit_digest(&raw);
    }
    assert!(permission::admission::verify_material(&changed, &wrong).is_err());
}
