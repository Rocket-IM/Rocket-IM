//! 真实MLS、原密文与Service签名的接受ID唯一性；拒绝后保留快照及解密能力。
use super::{
    wire_receive,
    wire_send_order_test_support::{accept, alter_invalid, load, reject, setup},
    wire_tests::Fixture,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

fn receive(sent: &Value, key: &SigningKey, id: &str) -> Value {
    json!({"operation":"wire_receive","header_bytes":sent["envelope"]["header_bytes"],
        "payload_bytes":sent["envelope"]["payload_bytes"],"acceptance_id":id,
        "acceptance_receipt":accept(sent,key,id)["acceptance_receipt"]})
}

fn reject_receive(f: &Fixture, sent: &Value, key: &SigningKey, id: &str) {
    let operation = receive(sent, key, id);
    reject(f, "B", operation.clone(), "acceptance_conflict");
    // 同时检查调用内provider，不能仅靠失败后没有保存来隐藏一次MLS状态推进。
    let mut state = load(f, "B");
    let before = serde_json::to_vec(&state).unwrap();
    let result = wire_receive::receive(
        &mut state,
        serde_json::from_value(sent["envelope"].clone()).unwrap(),
        Some(id.into()),
        Some(serde_json::from_value(operation["acceptance_receipt"].clone()).unwrap()),
    );
    assert_eq!(result.unwrap_err().code, "acceptance_conflict");
    state.capture_provider().unwrap();
    assert!(serde_json::to_vec(&state).unwrap() == before);
}

#[test]
fn fresh_inbox_acceptance_collision_preserves_mls_and_correct_retry() {
    let (f, key) = setup();
    let first = f.send("A", "M1");
    let second = f.send("C", "M2");
    assert_eq!(f.call("B", receive(&first, &key, "K1"))["duplicate"], false);
    reject_receive(&f, &second, &key, "K1");
    assert_eq!(
        f.call("B", receive(&second, &key, "K2"))["duplicate"],
        false
    );
    assert_eq!(f.call("B", receive(&first, &key, "K1"))["duplicate"], true);
    reject_receive(&f, &first, &key, "K3");
    assert_eq!(f.call("B", receive(&first, &key, "K1"))["duplicate"], true);
    assert_eq!(load(&f, "B").wire.inbox.len(), 2);
}

#[test]
fn late_inbox_binding_checks_other_acceptances_before_duplicate_return() {
    let (f, key) = setup();
    let first = f.send("A", "M1");
    let second = f.send("C", "M2");
    f.receive("B", &first["envelope"]);
    f.receive("B", &second["envelope"]);
    assert_eq!(f.call("B", receive(&first, &key, "K1"))["duplicate"], true);
    reject_receive(&f, &second, &key, "K1");
    assert_eq!(f.call("B", receive(&second, &key, "K2"))["duplicate"], true);
    assert_eq!(f.call("B", receive(&second, &key, "K2"))["duplicate"], true);
}

#[test]
fn send_receive_acceptance_collisions_are_rejected_in_both_directions() {
    let (f, key) = setup();
    let inbound = f.send("A", "M1");
    let outbound = f.send("B", "M2");
    f.call("B", receive(&inbound, &key, "K1"));
    reject(
        &f,
        "B",
        accept(&outbound, &key, "K1"),
        "acceptance_conflict",
    );
    f.call("B", accept(&outbound, &key, "K2"));
    let next = f.send("C", "M3");
    reject_receive(&f, &next, &key, "K2");
    assert_eq!(f.call("B", receive(&next, &key, "K3"))["duplicate"], false);
    assert_eq!(
        f.call("B", accept(&outbound, &key, "K2"))["duplicate"],
        true
    );
}

#[test]
fn unsigned_legacy_inbox_ids_remain_unique_without_requiring_receipts() {
    let f = Fixture::new();
    let first = f.send("A", "M1");
    let second = f.send("C", "M2");
    let operation = |sent: &Value, id: &str| {
        json!({"operation":"wire_receive",
        "header_bytes":sent["envelope"]["header_bytes"],"payload_bytes":sent["envelope"]["payload_bytes"],
        "acceptance_id":id})
    };
    f.call("B", operation(&first, "K1"));
    reject(&f, "B", operation(&second, "K1"), "acceptance_conflict");
    assert_eq!(f.call("B", operation(&second, "K2"))["duplicate"], false);
    assert_eq!(f.call("B", operation(&first, "K1"))["duplicate"], true);
}

#[test]
fn old_conflicting_inbox_acceptances_are_rejected_on_load_without_repair() {
    let (f, key) = setup();
    let first = f.send("A", "M1");
    let second = f.send("C", "M2");
    f.call("B", receive(&first, &key, "K1"));
    f.call("B", receive(&second, &key, "K2"));
    alter_invalid(&f, "B", |state| {
        let record = state
            .wire
            .inbox
            .values_mut()
            .find(|r| r.acceptance_id.as_deref() == Some("K2"))
            .unwrap();
        record.acceptance_id = Some("K1".into());
        record.acceptance_receipt = Some(
            serde_json::from_value(accept(&second, &key, "K1")["acceptance_receipt"].clone())
                .unwrap(),
        );
    });
    reject(
        &f,
        "B",
        json!({"operation":"wire_inspect"}),
        "acceptance_conflict",
    );
    reject(&f, "B", receive(&first, &key, "K1"), "acceptance_conflict");
}

#[test]
fn old_conflicting_send_receive_acceptances_are_rejected_on_load() {
    let (f, key) = setup();
    let first = f.send("A", "M1");
    let outbound = f.send("B", "M2");
    f.call("B", receive(&first, &key, "K1"));
    f.call("B", accept(&outbound, &key, "K2"));
    alter_invalid(&f, "B", |state| {
        state
            .wire
            .outbox
            .values_mut()
            .next()
            .unwrap()
            .acceptance_receipt = Some(
            serde_json::from_value(accept(&outbound, &key, "K1")["acceptance_receipt"].clone())
                .unwrap(),
        );
    });
    reject(
        &f,
        "B",
        json!({"operation":"wire_inspect"}),
        "acceptance_conflict",
    );
}

#[test]
fn snapshots_without_acceptance_fields_still_load_and_bind_signed_receipts() {
    let (f, key) = setup();
    let sent = f.send("A", "M1");
    f.receive("B", &sent["envelope"]);
    // 保存真正缺少可选字段的旧格式，而不是用默认None重新序列化新格式。
    let state = load(&f, "B");
    let context = serde_json::to_vec(&("Rocket-IM/state-lab/v1", &state.context)).unwrap();
    let mut old = serde_json::to_value(state).unwrap();
    for record in old["wire"]["inbox"].as_object_mut().unwrap().values_mut() {
        record.as_object_mut().unwrap().remove("acceptance_id");
        record.as_object_mut().unwrap().remove("acceptance_receipt");
    }
    let local_key: [u8; 32] = std::fs::read(f.root.join("B/device.key"))
        .unwrap()
        .try_into()
        .unwrap();
    crate::snapshot::save(
        &f.root.join("B/state.enc"),
        &local_key,
        &context,
        &serde_json::to_vec(&old).unwrap(),
        crate::snapshot::Failpoint::None,
    )
    .unwrap();
    assert_eq!(
        f.call("B", json!({"operation":"wire_inspect"}))["inbox_count"],
        1
    );
    assert_eq!(f.call("B", receive(&sent, &key, "K1"))["duplicate"], true);
    assert_eq!(f.call("B", receive(&sent, &key, "K1"))["duplicate"], true);
}

#[test]
fn receipt_verification_precedes_binding_and_resigned_same_fact_stays_idempotent() {
    let (f, key) = setup();
    let sent = f.send("A", "M1");
    f.receive("B", &sent["envelope"]);
    reject(
        &f,
        "B",
        receive(&sent, &SigningKey::from_bytes(&[99; 32]), "K1"),
        "acceptance_signature",
    );
    let original = receive(&sent, &key, "K1");
    assert_eq!(f.call("B", original.clone())["duplicate"], true);
    // 完整同一声明允许重新签发；字节不同不等于占用另一个消息原件。
    let mut raw = super::codec::decode(
        original["acceptance_receipt"]["statement_bytes"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    raw.push(b' ');
    let mut signed = crate::message_acceptance::SIGNING_DOMAIN.to_vec();
    signed.extend(&raw);
    let mut reissued = original;
    reissued["acceptance_receipt"] = json!({"statement_bytes":super::codec::encode(&raw),
        "signature_bytes":super::codec::encode(&key.sign(&signed).to_bytes())});
    assert_eq!(f.call("B", reissued.clone())["duplicate"], true);
    assert_eq!(f.call("B", reissued)["duplicate"], true);
}
