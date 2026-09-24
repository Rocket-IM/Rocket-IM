//! 合成固定 Service 私钥只在测试中签名；每次命令都走原快照加载与保存。
#[path = "wire_closure_boundary_tests.rs"]
mod boundaries;

use super::wire_send_order_test_support::*;
use super::{codec, wire_tests::Fixture};
use crate::{message_closure, permission::receipts::SignedRecord};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::fs;

fn export(f: &Fixture, message: &str, attempt: &str) -> Value {
    let before = fs::read(f.root.join("A/state.enc")).unwrap();
    let request = f.call(
        "A",
        json!({"operation":"wire_close_request","logical_message_id":message,"attempt_id":attempt}),
    );
    assert!(before == fs::read(f.root.join("A/state.enc")).unwrap());
    request
}
fn statement(request: &Value, id: &str) -> Value {
    json!({"protocol_version":"rim-message-closure-1","service_id":request["service_id"],
        "conversation_id":request["conversation_id"],"sender":{"account_id":"A","device_id":"A"},
        "logical_message_id":request["logical_message_id"],"attempt_id":request["attempt_id"],
        "envelope_sha256":request["envelope_sha256"],"replaces_attempt_id":request["replaces_attempt_id"],
        "predecessor_closure_id":request["closure_id"],"closure_id":id,"outcome":"cancelled_before_accept"})
}
fn signed(value: &Value, key: &SigningKey) -> SignedRecord {
    let raw = serde_json::to_vec(value).unwrap();
    let mut input = message_closure::SIGNING_DOMAIN.to_vec();
    input.extend(&raw);
    SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(&key.sign(&input).to_bytes()),
    }
}
fn close_op(request: &Value, proof: &SignedRecord) -> Value {
    json!({"operation":"wire_close","logical_message_id":request["logical_message_id"],
        "attempt_id":request["attempt_id"],"closure_receipt":proof})
}
fn close(f: &Fixture, key: &SigningKey, attempt: &str, id: &str) -> Value {
    let request = export(f, "M1", attempt);
    close_op(&request, &signed(&statement(&request, id), key))
}
fn successor(attempt: &str, previous: &str, closure: &str) -> Value {
    json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":attempt,
        "payload":"synthetic test content","replaces_attempt_id":previous,"closure_id":closure})
}
fn next() -> Value {
    json!({"operation":"wire_send","logical_message_id":"M2","attempt_id":"P1","payload":"synthetic test content"})
}

#[test]
fn closure_signed_successor_keeps_gate_and_late_proof_never_rewinds_tail() {
    let (f, key) = setup();
    enable(&f, "A");
    let p1 = f.send("A", "M1");
    let proof = close(&f, &key, "P1", "C1");
    let result = f.call("A", proof.clone());
    assert_eq!(result["status"], "closed");
    assert_eq!(result["duplicate"], false);
    assert_eq!(
        result["send_order"]["pending"],
        json!({"logical_message_id":"M1","attempt_id":"P1","status":"closed_awaiting_successor","closure_id":"C1"})
    );
    reject(&f, "A", next(), "send_order_pending");
    reject(
        &f,
        "A",
        successor("P2", "P1", "unsigned"),
        "closure_conflict",
    );
    assert_eq!(f.send("A", "M1")["envelope"], p1["envelope"]);
    let p2 = f.call("A", successor("P2", "P1", "C1"));
    assert_eq!(p2["reused"], false);
    assert!(p2["envelope"] != p1["envelope"]);
    let request = export(&f, "M1", "P2");
    assert_eq!(request["replaces_attempt_id"], "P1");
    assert_eq!(request["closure_id"], "C1");
    for accepted in [false, true] {
        if accepted {
            f.call("A", accept(&p2, &key, "K1"));
        }
        let before = fs::read(f.root.join("A/state.enc")).unwrap();
        let pending = inspect(&f, "A")["send_order"].clone();
        let duplicate = f.call("A", proof.clone());
        assert_eq!(duplicate["duplicate"], true);
        assert_eq!(duplicate["send_order"], pending);
        assert!(before == fs::read(f.root.join("A/state.enc")).unwrap());
        if !accepted {
            reject(&f, "A", successor("P3", "P1", "C1"), "send_order_pending");
        }
    }
    reject(&f, "A", accept(&p1, &key, "K2"), "closure_conflict");
    f.call("A", next());
    assert_eq!(inspect(&f, "A")["accepted_outbox_count"], 1);
}

#[test]
fn closure_acceptance_and_closure_are_first_saved_terminal_wins() {
    for accepted_first in [true, false] {
        let (f, key) = setup();
        enable(&f, "A");
        let sent = f.send("A", "M1");
        let proof = close(&f, &key, "P1", "C1");
        if accepted_first {
            f.call("A", accept(&sent, &key, "K1"));
            reject(&f, "A", proof, "closure_conflict");
            reject(
                &f,
                "A",
                json!({"operation":"wire_close_request","logical_message_id":"M1","attempt_id":"P1"}),
                "closure_conflict",
            );
        } else {
            f.call("A", proof);
            reject(&f, "A", accept(&sent, &key, "K1"), "closure_conflict");
        }
    }
}

#[test]
fn closure_four_successors_can_accept_but_fifth_closed_tail_cannot_advance() {
    for finish_accepted in [true, false] {
        let (f, key) = setup();
        enable(&f, "A");
        let mut sent = f.send("A", "M1");
        for i in 1..=4 {
            let previous = format!("P{i}");
            let id = format!("C{i}");
            f.call("A", close(&f, &key, &previous, &id));
            sent = f.call("A", successor(&format!("P{}", i + 1), &previous, &id));
        }
        assert_eq!(inspect(&f, "A")["outbox_count"], 5);
        if finish_accepted {
            f.call("A", accept(&sent, &key, "K1"));
            f.call("A", next());
        } else {
            f.call("A", close(&f, &key, "P5", "C5"));
            reject(
                &f,
                "A",
                successor("P6", "P5", "C5"),
                "send_order_successor_limit",
            );
            reject(&f, "A", next(), "send_order_pending");
            assert_eq!(
                inspect(&f, "A")["send_order"]["pending"]["attempt_id"],
                "P5"
            );
        }
    }
}

#[test]
fn closure_export_and_terminal_persist_under_pending_removed_and_consistency_guards() {
    for paused in ["pending", "removed", "consistency"] {
        let (f, key) = setup();
        enable(&f, "A");
        f.send("A", "M1");
        match paused {
            "pending" => {
                f.call("A",json!({"operation":"permission_prepare","change_id":"removeC","action":{"kind":"remove_member","account_id":"C"}}));
            }
            "consistency" => {
                f.call("A", json!({"operation":"consistency_challenge"}));
            }
            _ => alter_invalid(&f, "A", |state| {
                state.permissions.recovery.access_removed = true
            }),
        }
        let proof = close(&f, &key, "P1", "C1");
        f.call("A", proof);
        assert_eq!(
            inspect(&f, "A")["send_order"]["pending"]["status"],
            "closed_awaiting_successor"
        );
        reject(
            &f,
            "A",
            successor("P2", "P1", "C1"),
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
fn closure_only_fresh_successor_creates_one_message() {
    use super::wire_send_probe::{calls, reset};
    let (f, key) = setup();
    enable(&f, "A");
    f.send("A", "M1");
    reset();
    let proof = close(&f, &key, "P1", "C1");
    f.call("A", proof.clone());
    f.call("A", proof);
    f.send("A", "M1");
    reject(&f, "A", next(), "send_order_pending");
    assert_eq!(calls(), 0);
    f.call("A", successor("P2", "P1", "C1"));
    assert_eq!(calls(), 1);
    reset();
    f.call("A", successor("P2", "P1", "C1"));
    assert_eq!(calls(), 0);
}
