use super::{checkpoint, codec, prepare, resign, Context, Fixture, LockedDevice, Proof};
use crate::permission::{
    self,
    receipts::{self, Outcome, ReceiptStatement, RecoveryRecord, SignedRecord, RECEIPT_DOMAIN},
    Statement,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::fs;

#[path = "consistency_tests.rs"]
mod consistency_tests;
#[path = "device_join_tests.rs"]
mod device_join_tests;
#[path = "exchange_tests.rs"]
mod exchange_tests;
#[path = "join_tests.rs"]
mod join_tests;

fn setup() -> (Fixture, SigningKey) {
    setup_devices(&["A", "B", "C"])
}
fn setup_devices(devices: &[&str]) -> (Fixture, SigningKey) {
    let f = Fixture::with_devices(devices);
    let cp = checkpoint(&f);
    let key = SigningKey::from_bytes(&[19; 32]);
    for device in devices {
        f.call(
            device,
            json!({"operation":"permission_bootstrap","checkpoint":cp,
        "relay_receipt_key":codec::encode(key.verifying_key().as_bytes())}),
        );
    }
    (f, key)
}
fn statement(change: &Proof) -> Statement {
    Statement::parse(&codec::decode(&change.statement_bytes).unwrap()).unwrap()
}
fn receipt(
    key: &SigningKey,
    change: &Proof,
    outcome: Outcome,
    version: &str,
    reference: &str,
) -> RecoveryRecord {
    let original = statement(change);
    let body = ReceiptStatement {
        protocol_version: "rim-permission-receipt-1".into(),
        service_id: original.service_id,
        conversation_id: original.conversation_id,
        actor: original.actor,
        change_id: original.change_id,
        proof_sha256: receipts::proof_digest(change).unwrap(),
        outcome,
        authorization_version: version.into(),
        crypto_state_ref: reference.into(),
    };
    let raw = serde_json::to_vec(&body).unwrap();
    let mut signed = RECEIPT_DOMAIN.to_vec();
    signed.extend(&raw);
    RecoveryRecord {
        change: change.clone(),
        receipt: SignedRecord {
            statement_bytes: codec::encode(&raw),
            signature_bytes: codec::encode(&key.sign(&signed).to_bytes()),
        },
    }
}
fn accepted(key: &SigningKey, change: &Proof) -> RecoveryRecord {
    let s = statement(change);
    receipt(
        key,
        change,
        Outcome::Accepted,
        &s.authorization_version,
        &s.to_state_ref,
    )
}
fn closed(key: &SigningKey, change: &Proof) -> RecoveryRecord {
    let s = statement(change);
    receipt(
        key,
        change,
        Outcome::Closed,
        &s.previous_authorization_version,
        &s.from_state_ref,
    )
}
fn recover(f: &Fixture, device: &str, record: &RecoveryRecord) -> Value {
    f.call(
        device,
        json!({"operation":"permission_recover","record":record}),
    )
}
fn fail_atomic(f: &Fixture, device: &str, operation: Value, code: &str) {
    let before = fs::read(f.root.join(device).join("state.enc")).unwrap();
    f.fails(device, operation, code);
    assert_eq!(
        before,
        fs::read(f.root.join(device).join("state.enc")).unwrap()
    );
}
fn blocked(f: &Fixture, device: &str) {
    f.fails(device,json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P1","payload":"test"}),"permission_pending");
}

#[test]
fn accepted_receipt_requires_pin_exact_proof_and_real_mls_before_releasing_send() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "C1");
    let record = accepted(&key, &proof);
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_apply","change":proof}),
        "receipt_required",
    );
    let wrong = accepted(&SigningKey::from_bytes(&[20; 32]), &proof);
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_recover","record":wrong}),
        "permission_signature",
    );
    let mut bad = record.clone();
    bad.change.commit_bytes = codec::encode(b"fake");
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_recover","record":bad}),
        "permission_context",
    );
    let mut fake = proof.clone();
    let mut body: Value =
        serde_json::from_slice(&codec::decode(&proof.statement_bytes).unwrap()).unwrap();
    body["to_state_ref"] = json!("a".repeat(64));
    resign(&f, "A", &mut fake, &body);
    permission::verify(&checkpoint(&f), &fake).unwrap();
    fail_atomic(
        &f,
        "B",
        json!({"operation":"permission_recover","record":accepted(&key,&fake)}),
        "permission_commit",
    );
    assert_eq!(recover(&f, "A", &record)["recovery_status"], "ready");
    assert_eq!(recover(&f, "B", &record)["recovery_status"], "ready");
    assert_eq!(recover(&f, "A", &record)["duplicate"], true);
    let sent = f.send("A", "after");
    f.receive("B", &sent["envelope"]);
}

#[test]
fn close_preserves_intent_and_old_receipt_cannot_replace_new_pending() {
    let (f, key) = setup();
    let first = prepare(&f, "A", "first");
    let request = f.call("A", json!({"operation":"permission_close_request"}));
    assert_eq!(
        request,
        f.call("A", json!({"operation":"permission_close_request"}))
    );
    let close: SignedRecord = serde_json::from_value(request["close"].clone()).unwrap();
    receipts::verify_close(&checkpoint(&f), &first, &close).unwrap();
    let record = closed(&key, &first);
    let result = recover(&f, "A", &record);
    assert_eq!(result["recovery_status"], "needs_reprepare");
    blocked(&f, "A");
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_prepare","change_id":"other","action":{"kind":"remove_member","account_id":"B"}}),
        "intent_mismatch",
    );
    let next = prepare(&f, "A", "second");
    assert_ne!(statement(&first).nonce, statement(&next).nonce);
    assert_eq!(
        recover(&f, "A", &record)["pending_change"],
        serde_json::to_value(&next).unwrap()
    );
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_recover","record":accepted(&key,&first)}),
        "receipt_conflict",
    );
    blocked(&f, "A");
    recover(&f, "A", &accepted(&key, &next));
    assert_eq!(
        f.call("A", json!({"operation":"permission_inspect"}))["recovery_status"],
        "ready"
    );
}

#[test]
fn closed_reprepare_retains_handshake_generation_across_snapshot_reload() {
    let (f, key) = setup();
    let first = prepare(&f, "A", "first");
    let load = |device: &str| {
        let locked = LockedDevice::open(&f.root.join(device)).unwrap();
        let state = locked
            .load(&Context {
                service: "S1".into(),
                account: device.into(),
                device: device.into(),
            })
            .unwrap()
            .unwrap();
        (locked, state)
    };
    // 官方接收路径消耗第一次旧epoch握手密钥，但不合并候选；只保存接收ratchet。
    let (locked, mut b) = load("B");
    let mut group = b.group().unwrap();
    group
        .process_message(
            &b.provider,
            codec::protocol(&codec::decode(&first.commit_bytes).unwrap()).unwrap(),
        )
        .unwrap();
    locked.save(&mut b, super::super::CrashPoint::None).unwrap();
    drop(locked);
    recover(&f, "A", &closed(&key, &first));
    let second = prepare(&f, "A", "second");
    let (locked, a) = load("A");
    let group = a.group().unwrap();
    assert!(group.pending_commit().is_none());
    assert_eq!(
        super::super::wire::state_ref(&group).unwrap(),
        statement(&first).from_state_ref
    );
    drop(locked);
    // 原实现会重用相同sender generation，B第二次process_message得到SecretReuseError。
    let (locked, b) = load("B");
    let mut group = b.group().unwrap();
    group
        .process_message(
            &b.provider,
            codec::protocol(&codec::decode(&second.commit_bytes).unwrap()).unwrap(),
        )
        .unwrap();
    drop(locked);
    recover(&f, "A", &accepted(&key, &second));
    recover(&f, "B", &accepted(&key, &second));
}

#[test]
fn removed_local_member_enters_non_sending_terminal_without_claiming_verified_next_context() {
    let (f, key) = setup();
    let cp = checkpoint(&f);
    let proof = prepare(&f, "A", "removeC");
    let record = accepted(&key, &proof);
    let result = recover(&f, "C", &record);
    assert_eq!(result["recovery_status"], "access_removed");
    assert_eq!(result["checkpoint"], serde_json::to_value(&cp).unwrap());
    assert_eq!(result["service_target"]["authorization_version"], "2");
    fail_atomic(
        &f,
        "C",
        json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P1","payload":"test"}),
        "access_removed",
    );
    assert_eq!(recover(&f, "C", &record)["duplicate"], true);
}

#[test]
fn bounded_validity_retries_and_expired_original_close_are_authenticated() {
    let (f, _) = setup();
    let cp = checkpoint(&f);
    let result=f.call("A",json!({"operation":"permission_prepare","change_id":"short","action":{"kind":"remove_member","account_id":"C"},"validity_secs":1}));
    let proof: Proof = serde_json::from_value(result["change"].clone()).unwrap();
    let s = statement(&proof);
    assert_eq!(
        s.expires_at_unix_secs.parse::<u64>().unwrap()
            - s.issued_at_unix_secs.parse::<u64>().unwrap(),
        1
    );
    assert_eq!(proof, prepare(&f, "A", "short"));
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_prepare","change_id":"short","action":s.action,"validity_secs":2}),
        "pending_conflict",
    );
    let mut old = proof;
    let mut body = serde_json::to_value(s).unwrap();
    body["issued_at_unix_secs"] = json!("1");
    body["expires_at_unix_secs"] = json!("2");
    resign(&f, "A", &mut old, &body);
    let original = statement(&old);
    let close = receipts::CloseStatement {
        protocol_version: "rim-permission-close-1".into(),
        service_id: original.service_id,
        conversation_id: original.conversation_id,
        actor: original.actor,
        change_id: original.change_id,
        proof_sha256: receipts::proof_digest(&old).unwrap(),
    };
    let raw = serde_json::to_vec(&close).unwrap();
    let mut signed = receipts::CLOSE_DOMAIN.to_vec();
    signed.extend(&raw);
    let locked = LockedDevice::open(&f.root.join("A")).unwrap();
    let state = locked
        .load(&Context {
            service: "S1".into(),
            account: "A".into(),
            device: "A".into(),
        })
        .unwrap()
        .unwrap();
    let close = SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(
            &openmls_traits::signatures::Signer::sign(&state.signer().unwrap(), &signed).unwrap(),
        ),
    };
    receipts::verify_close(&cp, &old, &close).unwrap();
    let result =
        permission::execute(&json!({"checkpoint":cp,"change":old,"close":close}).to_string())
            .unwrap();
    assert_eq!(result["ok"], true);
}

#[test]
fn satisfied_intent_still_waits_for_recorded_floor_across_two_real_mls_steps() {
    let (f, key) = setup_devices(&["A", "B", "C", "D"]);
    let first = prepare(&f, "A", "removeC");
    let v2 = accepted(&key, &first);
    recover(&f, "A", &v2);
    let second:Proof=serde_json::from_value(f.call("A",json!({"operation":"permission_prepare","change_id":"removeD","action":{"kind":"remove_member","account_id":"D"}}))["change"].clone()).unwrap();
    let s3 = statement(&second);
    let v3 = accepted(&key, &second);
    // 构造已保存的恢复水位，仅为验证状态合并；两个后继均经真实MLS验证。
    let locked = LockedDevice::open(&f.root.join("B")).unwrap();
    let mut b = locked
        .load(&Context {
            service: "S1".into(),
            account: "B".into(),
            device: "B".into(),
        })
        .unwrap()
        .unwrap();
    b.permissions.recovery.intent = Some(super::super::recovery_state::Intent {
        origin_change_id: "closed_intent".into(),
        action: statement(&first).action,
        minimum_version: s3.authorization_version.clone(),
        minimum_state_ref: s3.to_state_ref.clone(),
        satisfied: false,
    });
    locked.save(&mut b, super::super::CrashPoint::None).unwrap();
    drop(locked);
    let result = recover(&f, "B", &v2);
    assert_eq!(result["recovery_status"], "needs_reprepare");
    assert_eq!(result["needs_reprepare"]["satisfied"], true);
    blocked(&f, "B");
    let result = recover(&f, "B", &v3);
    assert_eq!(result["recovery_status"], "ready");
    assert!(result["needs_reprepare"].is_null());
    recover(&f, "A", &v3);
    let sent = f.send("B", "afterfloor");
    f.receive("A", &sent["envelope"]);
}

#[test]
fn recovery_capacity_failure_keeps_snapshot_and_pending_candidate() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "first");
    let record = closed(&key, &proof);
    let locked = LockedDevice::open(&f.root.join("A")).unwrap();
    let mut a = locked
        .load(&Context {
            service: "S1".into(),
            account: "A".into(),
            device: "A".into(),
        })
        .unwrap()
        .unwrap();
    a.permissions.recovery.retired = (0..super::super::MAX_RECORDS)
        .map(|n| (format!("old{n}"), "a".repeat(64)))
        .collect();
    locked.save(&mut a, super::super::CrashPoint::None).unwrap();
    drop(locked);
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_recover","record":record}),
        "resource_exhausted",
    );
    blocked(&f, "A");
    assert_eq!(
        f.call("A", json!({"operation":"permission_inspect"}))["pending_change"],
        serde_json::to_value(proof).unwrap()
    );
}

#[path = "recovery_boundary_tests.rs"]
mod boundary;

#[path = "history_tests.rs"]
mod history;
