//! 默认发送与旧 outbox 分界；原密文恢复不等于旧发送历史已安全迁移。
use super::wire_send_order_test_support::*;
use super::wire_tests::Fixture;
use ed25519_dalek::SigningKey;
use serde_json::json;

#[test]
fn send_order_default_first_send_persists_gate_and_late_proof_keeps_new_pending() {
    let (f, key) = setup();
    assert!(load(&f, "A").wire_send_order.is_none());
    let first = f.send("A", "M1");
    assert_eq!(
        inspect(&f, "A")["send_order"]["pending"]["logical_message_id"],
        "M1"
    );
    reject(
        &f,
        "A",
        json!({"operation":"wire_send","logical_message_id":"M2","attempt_id":"P1","payload":"test"}),
        "send_order_pending",
    );
    f.call("A", accept(&first, &key, "K1"));
    f.send("A", "M2");
    assert!(f.send("A", "M1")["reused"].as_bool().unwrap());
    assert_eq!(f.call("A", accept(&first, &key, "K1"))["duplicate"], true);
    assert_eq!(
        inspect(&f, "A")["send_order"]["pending"]["logical_message_id"],
        "M2"
    );
}

#[test]
fn send_order_default_legacy_outbox_retries_but_never_auto_adopts_even_after_acceptance() {
    for count in [1, 2] {
        let f = Fixture::new();
        let originals: Vec<_> = (0..count).map(|i| f.send("A", &format!("M{i}"))).collect();
        let key = SigningKey::from_bytes(&[74; 32]);
        pin(&f, &key);
        for (index, first) in originals.iter().enumerate() {
            assert_eq!(
                f.send("A", &format!("M{index}"))["envelope"],
                first["envelope"]
            );
            reject(
                &f,
                "A",
                json!({"operation":"wire_send","logical_message_id":"new","attempt_id":"P1","payload":"test"}),
                "send_order_enable_conflict",
            );
            f.call("A", accept(first, &key, &format!("K{index}")));
        }
        assert_eq!(inspect(&f, "A")["accepted_outbox_count"], count);
        reject(
            &f,
            "A",
            json!({"operation":"wire_send_order_enable"}),
            "send_order_enable_conflict",
        );
        reject(
            &f,
            "A",
            json!({"operation":"wire_send","logical_message_id":"new","attempt_id":"P1","payload":"test"}),
            "send_order_enable_conflict",
        );
        assert!(load(&f, "A").wire_send_order.is_none());
    }
}

#[test]
fn send_order_default_raw_history_blocks_new_wire_send_without_consuming_state() {
    let f = Fixture::new();
    f.call("A", json!({"operation":"send","id":"raw","payload":"test"}));
    pin(&f, &SigningKey::from_bytes(&[74; 32]));
    reject(
        &f,
        "A",
        json!({"operation":"wire_send","logical_message_id":"new","attempt_id":"P1","payload":"test"}),
        "send_order_enable_conflict",
    );
    assert!(load(&f, "A").wire_send_order.is_none());
}

#[test]
fn send_order_default_invalid_first_attempt_does_not_persist_half_enabled_gate() {
    let (f, _) = setup();
    reject(
        &f,
        "A",
        json!({"operation":"wire_send","logical_message_id":"new","attempt_id":"P2",
        "payload":"test","replaces_attempt_id":"P1","closure_id":"C1"}),
        "attempt_closed",
    );
    assert!(load(&f, "A").wire_send_order.is_none());
    assert_eq!(inspect(&f, "A")["outbox_count"], 0);
}
