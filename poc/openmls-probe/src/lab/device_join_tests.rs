//! 同账号设备只有本群授权；实验账号 roster 和其本地版本不因此被重写。
use super::{accepted, closed, setup, statement, Context, Fixture, LockedDevice, Proof};
use crate::{
    lab::{codec, execute},
    permission,
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::fs;

#[path = "history_migration_tests.rs"]
mod history_migration_tests;

fn request(f: &Fixture, device: &str, operation: Value) -> String {
    let mut value: Value = serde_json::from_str(&f.request(device, operation)).unwrap();
    if device.starts_with('B') {
        value["account"] = json!("B");
    }
    if device == "A2" {
        value["account"] = json!("A");
    }
    value.to_string()
}
fn call(f: &Fixture, device: &str, operation: Value) -> Value {
    execute(&request(f, device, operation)).unwrap()["result"].clone()
}
fn fail(f: &Fixture, device: &str, operation: Value, code: &str) {
    let path = f.root.join(device).join("state.enc");
    let old = fs::read(&path).unwrap();
    assert_eq!(
        execute(&request(f, device, operation)).unwrap_err().code,
        code
    );
    assert_eq!(fs::read(path).unwrap(), old);
}
fn cp(f: &Fixture) -> Value {
    call(f, "A", json!({"operation":"permission_inspect"}))["checkpoint"].clone()
}
fn init(f: &Fixture, key: &SigningKey, device: &str) -> Value {
    let identity = call(f, device, json!({"operation":"init"}));
    let (initial, mut records) = {
        let locked = LockedDevice::open(&f.root.join("A")).unwrap();
        let state = locked
            .load(&Context {
                service: "S1".into(),
                account: "A".into(),
                device: "A".into(),
            })
            .unwrap()
            .unwrap();
        let initial = state
            .permissions
            .history
            .past
            .values()
            .next()
            .or(state.permissions.checkpoint.as_ref())
            .unwrap()
            .clone();
        // 本测试最多先添加一台设备，仍保存独立初始 CP；不拿任意中途 CP 冒充完整起点。
        assert_eq!(initial.authorization_version, "1");
        (
            initial,
            state
                .permissions
                .recovery
                .records
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    };
    records.sort_by_key(|r| {
        statement(&r.change)
            .authorization_version
            .parse::<u64>()
            .unwrap()
    });
    call(
        f,
        device,
        json!({"operation":"permission_device_join_anchor","checkpoint":initial,
        "relay_receipt_key":codec::encode(key.verifying_key().as_bytes())}),
    );
    for record in records {
        call(
            f,
            device,
            json!({"operation":"permission_join_advance","record":record}),
        );
    }
    identity
}
fn prepare(f: &Fixture, actor: &str, identity: &Value, id: &str) -> Value {
    call(
        f,
        actor,
        json!({"operation":"permission_prepare_device","change_id":id,
        "member":{"account_id":identity["account"],"device_id":identity["device"],"signature_key":identity["signature_key"]},
        "key_package":identity["key_package"],"history_policy":"from_join"}),
    )
}
fn proof(prepared: &Value) -> Proof {
    serde_json::from_value(prepared["change"].clone()).unwrap()
}
fn accept(f: &Fixture, key: &SigningKey, prepared: &Value, devices: &[&str]) {
    for device in devices {
        call(
            f,
            device,
            json!({"operation":"permission_recover","record":accepted(key,&proof(prepared))}),
        );
    }
}
fn join(f: &Fixture, key: &SigningKey, device: &str, prepared: &Value) -> Value {
    call(
        f,
        device,
        json!({"operation":"permission_join","record":accepted(key,&proof(prepared)),"join":prepared["join"]}),
    )
}
fn send(f: &Fixture, device: &str, id: &str) -> Value {
    call(
        f,
        device,
        json!({"operation":"wire_send","logical_message_id":id,"attempt_id":"P1","payload":"synthetic device test"}),
    )
}
fn roster(f: &Fixture, device: &str) -> Value {
    let locked = LockedDevice::open(&f.root.join(device)).unwrap();
    let state = locked
        .load(&Context {
            service: "S1".into(),
            account: if device.starts_with('B') {
                "B".into()
            } else {
                device.into()
            },
            device: device.into(),
        })
        .unwrap()
        .unwrap();
    serde_json::to_value(&state.roster).unwrap()
}
fn add_b2() -> (Fixture, SigningKey, Value) {
    let (f, key) = setup();
    let identity = init(&f, &key, "B2");
    let added = prepare(&f, "B", &identity, "addB2");
    accept(&f, &key, &added, &["A", "B", "C"]);
    join(&f, &key, "B2", &added);
    (f, key, identity)
}

#[test]
fn non_owner_device_admission_uses_verified_group_trust_without_changing_account_rosters() {
    let (f, key) = setup();
    let identity = init(&f, &key, "B2");
    let rosters: Vec<_> = ["A", "B", "C", "B2"]
        .iter()
        .map(|d| roster(&f, d))
        .collect();
    let added = prepare(&f, "B", &identity, "addB2");
    let retry = prepare(&f, "B", &identity, "addB2");
    assert_eq!(added["change"], retry["change"]);
    assert_eq!(added["join"], retry["join"]);
    assert!(matches!(
        statement(&proof(&added)).action,
        permission::Action::AddDevice { .. }
    ));
    accept(&f, &key, &added, &["A", "B", "C"]);
    assert_eq!(
        join(&f, &key, "B2", &added)["admission"]["anchor_mode"],
        "device"
    );
    assert_eq!(join(&f, &key, "B2", &added)["duplicate"], true);
    assert_eq!(
        rosters,
        ["A", "B", "C", "B2"]
            .iter()
            .map(|d| roster(&f, d))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        call(&f, "B2", json!({"operation":"wire_inspect"}))["history"]["past_epochs"],
        json!([])
    );
    for (sender, receiver, id) in [
        ("B2", "A", "fromNew"),
        ("B", "B2", "fromOld"),
        ("A", "B2", "fromOwner"),
    ] {
        let envelope = send(&f, sender, id)["envelope"].clone();
        call(
            &f,
            receiver,
            json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"]}),
        );
    }
}

#[test]
fn owner_pin_and_legacy_authorization_cannot_replace_same_account_group_authorization() {
    let (f, key) = setup();
    let identity = init(&f, &key, "B2");
    let member =
        json!({"account_id":"B","device_id":"B2","signature_key":identity["signature_key"]});
    call(
        &f,
        "A",
        json!({"operation":"permission_pin_member","member":member}),
    );
    fail(
        &f,
        "A",
        json!({"operation":"permission_prepare_device","change_id":"owner","member":member,
        "key_package":identity["key_package"],"history_policy":"from_join"}),
        "permission_denied",
    );
    // 旧 v1 独立账号实验仍可签声明，但在群权限模式中没有 apply 授权入口。
    let raw_key = codec::decode(identity["signature_key"].as_str().unwrap()).unwrap();
    let authorization = call(
        &f,
        "B",
        json!({"operation":"sign_authorization","request":{
        "service":"S1","account":"B","signer_device":"B","new_device":"B2",
        "new_signature_key":raw_key,"key_package_sha256":crate::authorization::key_package_sha256(&codec::decode(identity["key_package"].as_str().unwrap()).unwrap()),
        "expected_roster_version":0,"nonce":vec![1u8;32],"issued_at_unix_secs":1,"expires_at_unix_secs":301}}),
    );
    fail(
        &f,
        "B",
        json!({"operation":"authorize","authorization":authorization["authorization"],"key_package":identity["key_package"],"now_unix_secs":2}),
        "signed_permission_required",
    );
    let added = prepare(&f, "B", &identity, "valid");
    fail(
        &f,
        "A",
        json!({"operation":"permission_prepare","change_id":"bypass","action":statement(&proof(&added)).action}),
        "invalid_permission",
    );
}

#[test]
fn device_anchor_mode_is_immutable_and_cannot_skip_exact_self_add_device() {
    let (f, key) = setup();
    let identity = call(&f, "B2", json!({"operation":"init"}));
    let anchor = json!({"checkpoint":cp(&f),"relay_receipt_key":codec::encode(key.verifying_key().as_bytes())});
    fail(
        &f,
        "B2",
        json!({"operation":"permission_join_anchor","checkpoint":anchor["checkpoint"],"relay_receipt_key":anchor["relay_receipt_key"]}),
        "join_identity",
    );
    call(
        &f,
        "B2",
        json!({"operation":"permission_device_join_anchor","checkpoint":anchor["checkpoint"],"relay_receipt_key":anchor["relay_receipt_key"]}),
    );
    fail(
        &f,
        "B2",
        json!({"operation":"permission_device_join_anchor","checkpoint":anchor["checkpoint"],"relay_receipt_key":anchor["relay_receipt_key"]}),
        "permission_conflict",
    );
    let added = prepare(&f, "B", &identity, "B2");
    fail(
        &f,
        "B2",
        json!({"operation":"permission_join_advance","record":accepted(&key,&proof(&added))}),
        "join_required",
    );
    join(&f, &key, "B2", &added);
}

#[test]
fn different_device_winner_preserves_intent_and_public_same_account_chain_can_advance() {
    let (f, key, _) = add_b2();
    let b3 = init(&f, &key, "B3");
    let b4 = init(&f, &key, "B4");
    let loser = prepare(&f, "B", &b3, "wantB3");
    let winner = prepare(&f, "B2", &b4, "addB4");
    accept(&f, &key, &winner, &["A", "B", "B2", "C"]);
    let waiting = call(&f, "B", json!({"operation":"permission_inspect"}));
    assert_eq!(waiting["recovery_status"], "needs_reprepare");
    assert_eq!(
        waiting["needs_reprepare"]["action"],
        serde_json::to_value(statement(&proof(&loser)).action).unwrap()
    );
    fail(
        &f,
        "B",
        json!({"operation":"wire_send","logical_message_id":"paused","attempt_id":"P1","payload":"test"}),
        "permission_pending",
    );
    call(
        &f,
        "B3",
        json!({"operation":"permission_join_advance","record":accepted(&key,&proof(&winner))}),
    );
    let next = prepare(&f, "B", &b3, "retryB3");
    assert!(statement(&proof(&next))
        .action
        .same_intent(&statement(&proof(&loser)).action));
    accept(&f, &key, &next, &["A", "B", "B2", "C"]);
    join(&f, &key, "B3", &next);
    assert_eq!(
        call(&f, "B3", json!({"operation":"wire_inspect"}))["history"]["past_epochs"],
        json!([])
    );
}

#[test]
fn same_target_device_winner_finishes_original_intent_and_close_keeps_target_binding() {
    let (f, key, _) = add_b2();
    let b3 = init(&f, &key, "B3");
    let first = prepare(&f, "B", &b3, "first");
    call(
        &f,
        "B",
        json!({"operation":"permission_recover","record":closed(&key,&proof(&first))}),
    );
    let retry = prepare(&f, "B", &b3, "retry");
    let winner = prepare(&f, "B2", &b3, "winner");
    assert!(statement(&proof(&retry))
        .action
        .same_intent(&statement(&proof(&winner)).action));
    accept(&f, &key, &winner, &["A", "B", "B2", "C"]);
    assert_eq!(
        call(&f, "B", json!({"operation":"permission_inspect"}))["recovery_status"],
        "ready"
    );
    join(&f, &key, "B3", &winner);
    send(&f, "B", "resumed");
}

#[test]
fn revoked_device_cannot_sign_or_rejoin_but_different_new_device_remains_eligible() {
    let (f, key, b2) = add_b2();
    let b3 = init(&f, &key, "B3");
    let revoked = call(
        &f,
        "B",
        json!({"operation":"permission_prepare","change_id":"revokeB2","action":{"kind":"revoke_device","account_id":"B","device_id":"B2"}}),
    );
    accept(&f, &key, &revoked, &["A", "B", "C", "B2"]);
    fail(
        &f,
        "A",
        json!({"operation":"permission_pin_member","member":{"account_id":"B","device_id":"B2","signature_key":b3["signature_key"]}}),
        "identity_changed",
    );
    fail(
        &f,
        "A",
        json!({"operation":"permission_pin_member","member":{"account_id":"E","device_id":"E","signature_key":b2["signature_key"]}}),
        "identity_changed",
    );
    fail(
        &f,
        "B2",
        json!({"operation":"permission_prepare_device","change_id":"fromRevoked","member":{"account_id":"B","device_id":"B3","signature_key":b3["signature_key"]},"key_package":b3["key_package"],"history_policy":"from_join"}),
        "access_removed",
    );
    fail(
        &f,
        "B",
        json!({"operation":"permission_prepare_device","change_id":"reuse","member":{"account_id":"B","device_id":"B2","signature_key":b2["signature_key"]},"key_package":b2["key_package"],"history_policy":"from_join"}),
        "join_reentry",
    );
    let next = prepare(&f, "B", &b3, "freshB3");
    call(
        &f,
        "B3",
        json!({"operation":"permission_join_advance","record":accepted(&key,&proof(&revoked))}),
    );
    join(&f, &key, "B3", &next);
}

#[test]
fn legacy_snapshot_missing_identity_history_stays_incomplete_across_verified_epoch_changes() {
    let (f, key) = setup();
    let identity = init(&f, &key, "B2");
    let locked = LockedDevice::open(&f.root.join("B")).unwrap();
    let state = locked
        .load(&Context {
            service: "S1".into(),
            account: "B".into(),
            device: "B".into(),
        })
        .unwrap()
        .unwrap();
    let mut serialized = serde_json::to_value(&state).unwrap();
    let admission = serialized["permissions"]["admission"]
        .as_object_mut()
        .unwrap();
    admission.remove("seen_members");
    admission.remove("device_history_complete");
    let mut migrated: crate::lab::state::DeviceState = serde_json::from_value(serialized).unwrap();
    assert!(!migrated.permissions.admission.device_history_complete);
    migrated.restore_provider().unwrap();
    locked
        .save(&mut migrated, crate::lab::CrashPoint::None)
        .unwrap();
    drop(locked);
    let operation = json!({"operation":"permission_prepare_device","change_id":"unsupported",
        "member":{"account_id":"B","device_id":"B2","signature_key":identity["signature_key"]},
        "key_package":identity["key_package"],"history_policy":"from_join"});
    fail(&f, "B", operation.clone(), "device_history_unavailable");
    let old = call(
        &f,
        "A",
        json!({"operation":"permission_prepare","change_id":"removeC","action":{"kind":"remove_member","account_id":"C"}}),
    );
    accept(&f, &key, &old, &["A", "B"]);
    assert_eq!(
        call(&f, "B", json!({"operation":"permission_inspect"}))["admission"]
            ["device_history_complete"],
        false
    );
    fail(&f, "B", operation, "device_history_unavailable");
    send(&f, "B", "legacyStillWorks");
    let a2 = init(&f, &key, "A2");
    let added = prepare(&f, "A", &a2, "addA2");
    fail(
        &f,
        "B",
        json!({"operation":"permission_recover","record":accepted(&key,&proof(&added))}),
        "device_history_unavailable",
    );
}
