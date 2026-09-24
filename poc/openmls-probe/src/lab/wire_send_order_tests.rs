//! 每次公开调用重新加载快照；错误不得消费新发送 generation 或清除未决原件。

use super::wire_send_order_test_support::*;
use super::{codec, state::DeviceState, wire_send_order::Policy, wire_tests::Fixture};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

fn next_send() -> Value {
    json!({"operation":"wire_send","logical_message_id":"M2","attempt_id":"P1","payload":"synthetic test content"})
}

#[test]
fn send_order_disabled_snapshots_and_inspection_keep_legacy_shape() {
    let f = Fixture::new();
    let value = serde_json::to_value(load(&f, "A")).unwrap();
    assert!(value.get("wire_send_order").is_none());
    let restored: DeviceState = serde_json::from_value(value).unwrap();
    assert!(restored.wire_send_order.is_none());
    assert!(inspect(&f, "A").get("send_order").is_none());
    f.send("A", "M1");
    f.send("A", "M2");
    assert_eq!(inspect(&f, "A")["outbox_count"], 2);
}

#[test]
fn send_order_enable_requires_configuration_active_membership_and_pin() {
    let f = Fixture::new();
    f.call("D", json!({"operation":"init"}));
    reject(
        &f,
        "D",
        json!({"operation":"wire_send_order_enable"}),
        "trust_required",
    );
    reject(
        &f,
        "A",
        json!({"operation":"wire_send_order_enable"}),
        "receipt_pin_required",
    );
    let removed = f.call(
        "A",
        json!({"operation":"remove","id":"removeB","member":"B"}),
    );
    f.call(
        "B",
        json!({"operation":"apply_commit","commit":removed["commit"]}),
    );
    reject(
        &f,
        "B",
        json!({"operation":"wire_send_order_enable"}),
        "device_revoked",
    );
}

#[test]
fn send_order_first_enable_rejects_both_legacy_and_wire_outboxes() {
    for legacy in [true, false] {
        let f = Fixture::new();
        if legacy {
            f.call(
                "A",
                json!({"operation":"send","id":"raw","payload":"synthetic test content"}),
            );
        } else {
            f.send("A", "M1");
        }
        pin(&f, &SigningKey::from_bytes(&[74; 32]));
        reject(
            &f,
            "A",
            json!({"operation":"wire_send_order_enable"}),
            "send_order_enable_conflict",
        );
        assert!(load(&f, "A").wire_send_order.is_none());
    }
}

#[test]
fn send_order_reentry_keeps_pending_and_only_exact_signed_acceptance_advances() {
    let (f, key) = setup();
    assert_eq!(
        enable(&f, "A"),
        json!({"policy":"acceptance_serial_v1","conversation_id":"G1","pending":null})
    );
    let first = f.send("A", "M1");
    let pending = inspect(&f, "A")["send_order"].clone();
    assert_eq!(
        pending["pending"],
        json!({"logical_message_id":"M1","attempt_id":"P1"})
    );
    assert_eq!(enable(&f, "A"), pending);
    reject(&f, "A", next_send(), "send_order_pending");
    assert_eq!(f.send("A", "M1")["envelope"], first["envelope"]);
    assert_eq!(f.send("A", "M1")["reused"], true);
    let accepted = f.call("A", accept(&first, &key, "K1"));
    assert_eq!(accepted["duplicate"], false);
    assert!(inspect(&f, "A")["send_order"]["pending"].is_null());
    assert_eq!(f.call("A", accept(&first, &key, "K1"))["duplicate"], true);
    let next = f.call("A", next_send());
    assert_eq!(next["reused"], false);
    assert_eq!(
        inspect(&f, "A")["send_order"]["pending"]["logical_message_id"],
        "M2"
    );
}

#[test]
fn send_order_wrong_signature_and_other_envelope_cannot_release_pending() {
    let (f, key) = setup();
    enable(&f, "A");
    let original = f.send("A", "M1");
    reject(
        &f,
        "A",
        accept(&original, &SigningKey::from_bytes(&[75; 32]), "K1"),
        "acceptance_signature",
    );
    let other = f.send("B", "M1");
    reject(&f, "A", accept(&other, &key, "K1"), "acceptance_conflict");
    reject(&f, "A", next_send(), "send_order_pending");
    assert_eq!(
        inspect(&f, "A")["send_order"]["pending"]["logical_message_id"],
        "M1"
    );
}

#[test]
fn send_order_raw_send_and_unsigned_successor_closure_cannot_bypass_pending() {
    let (f, _) = setup();
    enable(&f, "A");
    let original = f.send("A", "M1");
    reject(
        &f,
        "A",
        json!({"operation":"send","id":"raw","payload":"synthetic test content"}),
        "send_order_required",
    );
    reject(
        &f,
        "A",
        json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P2",
        "payload":"synthetic test content","replaces_attempt_id":"P1","closure_id":"unsigned_closure"}),
        "send_order_pending",
    );
    reject(
        &f,
        "A",
        json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P1",
        "payload":"changed"}),
        "idempotency_conflict",
    );
    assert_eq!(f.send("A", "M1")["envelope"], original["envelope"]);
}

#[test]
fn send_order_accounts_are_independent_and_accepted_retry_does_not_release_new_pending() {
    let (f, key) = setup();
    enable(&f, "A");
    enable(&f, "B");
    let first = f.send("A", "M1");
    let other = f.send("B", "M1");
    assert_eq!(other["reused"], false);
    f.call("A", accept(&first, &key, "K1"));
    f.call("A", next_send());
    assert_eq!(f.send("A", "M1")["envelope"], first["envelope"]);
    assert_eq!(f.call("A", accept(&first, &key, "K1"))["duplicate"], true);
    assert_eq!(
        inspect(&f, "A")["send_order"]["pending"]["logical_message_id"],
        "M2"
    );
    assert_eq!(
        inspect(&f, "B")["send_order"]["pending"]["logical_message_id"],
        "M1"
    );
    reject(&f, "B", next_send(), "send_order_pending");
}

#[test]
fn send_order_corrupt_multi_pending_is_rejected_before_execution_without_cleanup() {
    let (f, _) = setup();
    f.send("A", "M1");
    f.send("A", "M2");
    alter_invalid(&f, "A", |state| {
        state.wire_send_order = Some(Policy::AcceptanceSerialV1 {
            conversation_id: "G1".into(),
        });
    });
    for operation in [
        json!({"operation":"wire_inspect"}),
        json!({"operation":"wire_send_order_enable"}),
        next_send(),
    ] {
        reject(&f, "A", operation, "send_order_state");
    }
}

#[test]
fn send_order_scope_and_missing_trust_are_rejected_on_load() {
    for field in [
        "policy_conversation",
        "checkpoint",
        "pin",
        "service_id",
        "account_id",
        "device_id",
    ] {
        let (f, _) = setup();
        enable(&f, "A");
        f.send("A", "M1");
        alter_invalid(&f, "A", |state| match field {
            "policy_conversation" => {
                state.wire_send_order = Some(Policy::AcceptanceSerialV1 {
                    conversation_id: "foreign".into(),
                })
            }
            "checkpoint" => state.permissions.checkpoint = None,
            "pin" => state.permissions.recovery.relay_receipt_key = None,
            _ => {
                let record = state.wire.outbox.values_mut().next().unwrap();
                let raw = codec::decode(&record.envelope.header_bytes).unwrap();
                let mut header: Value = serde_json::from_slice(&raw).unwrap();
                if field == "service_id" {
                    header[field] = json!("foreign");
                } else {
                    header["sender"][field] = json!("foreign");
                }
                record.envelope.header_bytes = codec::encode(&serde_json::to_vec(&header).unwrap());
            }
        });
        reject(
            &f,
            "A",
            json!({"operation":"wire_inspect"}),
            "send_order_state",
        );
    }
}

#[test]
fn send_order_accept_stays_available_under_original_permission_and_consistency_guards() {
    for paused in ["pending", "removed", "consistency"] {
        let (f, key) = setup();
        enable(&f, "A");
        let sent = f.send("A", "M1");
        match paused {
            "pending" => {
                f.call(
                    "A",
                    json!({"operation":"permission_prepare","change_id":"removeC",
                "action":{"kind":"remove_member","account_id":"C"}}),
                );
            }
            "consistency" => {
                f.call("A", json!({"operation":"consistency_challenge"}));
            }
            _ => alter_invalid(&f, "A", |state| {
                state.permissions.recovery.access_removed = true
            }),
        }
        let accepted = f.call("A", accept(&sent, &key, "K1"));
        assert_eq!(accepted["status"], "accepted");
        assert!(inspect(&f, "A")["send_order"]["pending"].is_null());
        reject(
            &f,
            "A",
            next_send(),
            match paused {
                "pending" => "permission_pending",
                "removed" => "access_removed",
                _ => "consistency_paused",
            },
        );
    }
}

#[cfg(feature = "wire-send-probe")]
#[test]
fn send_order_blocked_and_original_retry_do_not_call_create_message() {
    use super::wire_send_probe::{calls, reset};
    let (f, key) = setup();
    enable(&f, "A");
    reset();
    let first = f.send("A", "M1");
    assert_eq!(calls(), 1);
    reset();
    reject(&f, "A", next_send(), "send_order_pending");
    assert_eq!(calls(), 0);
    assert_eq!(f.send("A", "M1")["envelope"], first["envelope"]);
    assert_eq!(calls(), 0);
    f.call("A", accept(&first, &key, "K1"));
    assert_eq!(calls(), 0);
    f.call("A", next_send());
    assert_eq!(calls(), 1);
    reset();
}
