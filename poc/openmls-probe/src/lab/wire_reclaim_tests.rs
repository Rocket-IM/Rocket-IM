//! 回收后实际载荷消除、幂等、来源、阅读及预算；不代替跨进程Relay或锚故障验证。
#[path = "wire_reclaim_boundary_tests.rs"]
mod boundaries;
#[path = "wire_reclaim_chain_tests.rs"]
mod chain;
#[path = "wire_reclaim_preparation_tests.rs"]
mod preparation;
#[path = "wire_reclaim_quota_tests.rs"]
mod quota;
#[path = "wire_reclaim_test_support.rs"]
mod support;
use super::{
    codec,
    wire_send_order_test_support::{accept, load, reject},
    wire_tests::Fixture,
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::fs;
use support::*;

#[test]
fn identity_change_keeps_compact_terminal_query_without_releasing_new_ciphertext() {
    let (f, key, sent, payload) = fixture(false, "deleted");
    f.call(
        "A",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"A",&sent,"R1","deleted")}),
    );
    let replacement = super::state::DeviceState::new(super::Context {
        service: "S1".into(),
        account: "B".into(),
        device: "B".into(),
    })
    .unwrap();
    f.call("A", json!({"operation":"identity_trust_observe","identity":super::identity_state::own(&replacement)}));
    let before = serde_json::to_vec(&load(&f, "A")).unwrap();
    let terminal = f.call("A", json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P1","payload":payload}));
    assert_eq!(terminal["payload_reclaimed"], true);
    assert!(terminal.get("envelope").is_none());
    assert!(serde_json::to_vec(&load(&f, "A")).unwrap() == before);
    let before = fs::read(f.root.join("A/state.enc")).unwrap();
    reject(
        &f,
        "A",
        json!({"operation":"wire_send","logical_message_id":"M2","attempt_id":"P1","payload":"synthetic new"}),
        "identity_changed",
    );
    assert_eq!(fs::read(f.root.join("A/state.enc")).unwrap(), before);
}

#[test]
fn actual_plaintext_and_all_message_ciphertext_copies_are_removed_with_immutable_provider() {
    for terminal in ["deleted", "expired"] {
        for read in [false, true] {
            let (f, key, sent, payload) = fixture(read, terminal);
            for device in ["A", "B"] {
                let before_inspect = f.call(device, json!({"operation":"wire_inspect"}));
                assert!(before_inspect.get("reclamation").is_none());
                assert!(before_inspect["sync"].get("active_slot_count").is_none());
                let before = load(&f, device).provider_entries;
                let proof = permit(&f, &key, device, &sent, "R1", terminal);
                let result = f.call(device, json!({"operation":"wire_reclaim","receipt":proof}));
                assert_eq!(result["reclaimed_count"], 1);
                let state = load(&f, device);
                assert_eq!(state.provider_entries, before);
                assert!(state.wire.inbox.is_empty() && state.wire.outbox.is_empty());
                let raw = serde_json::to_string(&state).unwrap();
                assert!(!raw.contains(&payload));
                assert!(!raw.contains(sent["envelope"]["payload_bytes"].as_str().unwrap()));
                assert!(!raw.contains("\"envelope\":"));
                let bytes = fs::read(f.root.join(device).join("state.enc")).unwrap();
                let duplicate = f.call(device, json!({"operation":"wire_reclaim","receipt":proof}));
                assert_eq!(duplicate["duplicate"], true);
                assert_eq!(
                    fs::read(f.root.join(device).join("state.enc")).unwrap(),
                    bytes
                );
            }
            let output=f.call("A",json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P1","payload":payload}));
            assert_eq!(output["payload_reclaimed"], true);
            assert!(output.get("envelope").is_none());
            assert_eq!(output["acceptance_id"], "K1");
            assert_eq!(f.call("A", accept(&sent, &key, "K1"))["duplicate"], true);
            let received = f.call(
                "B",
                json!({"operation":"wire_receive","header_bytes":sent["envelope"]["header_bytes"],
            "payload_bytes":sent["envelope"]["payload_bytes"]}),
            );
            assert_eq!(received["duplicate"], true);
            assert_eq!(received["payload_reclaimed"], true);
            if read {
                assert_eq!(
                    f.call("B", json!({"operation":"wire_read","event_ids":["BE1"]}))
                        ["duplicate_count"],
                    1
                );
            } else {
                reject(
                    &f,
                    "B",
                    json!({"operation":"wire_read","event_ids":["BE1"]}),
                    "payload_reclaimed",
                );
            }
            assert_eq!(
                f.call("B", json!({"operation":"wire_inspect"}))["sync"]["active_slot_count"],
                0
            );
            assert_eq!(
                f.call("B", json!({"operation":"wire_process"}))["deliveries"],
                json!([])
            );
            let next = f.send("A", "M2");
            assert_eq!(f.receive("B", &next["envelope"])["duplicate"], false);
        }
    }
}

#[test]
fn signed_wrong_scope_target_or_recipient_cannot_reclaim_and_original_stays() {
    let (f, key, sent, _) = fixture(false, "deleted");
    let original = permit(&f, &key, "B", &sent, "R1", "deleted");
    let mutations: Vec<fn(&mut Value)> = vec![
        |s| s["account_id"] = json!("A"),
        |s| s["device_id"] = json!("A"),
        |s| s["stream_id"] = json!("other"),
        |s| s["processed_seq"] = json!("999"),
        |s| s["messages"][0]["envelope_sha256"] = json!("00".repeat(32)),
        |s| s["messages"][0]["availability"] = json!("expired"),
        |s| {
            s["messages"][0]["recipients"].as_array_mut().unwrap().pop();
        },
    ];
    for change in mutations {
        reject(
            &f,
            "B",
            json!({"operation":"wire_reclaim","receipt":re_sign(&key,&original,change)}),
            "reclaim_conflict",
        );
    }
    let wrong = re_sign(&SigningKey::from_bytes(&[2; 32]), &original, |_| {});
    reject(
        &f,
        "B",
        json!({"operation":"wire_reclaim","receipt":wrong}),
        "reclaim_signature",
    );
    f.call("B", json!({"operation":"wire_reclaim","receipt":original}));
    reject(
        &f,
        "B",
        json!({"operation":"wire_reclaim","receipt":re_sign(&key,&original,|s|s["processed_seq"]=json!("2"))}),
        "reclaim_conflict",
    );
}

#[test]
fn reclaimed_sender_rejects_changed_content_and_any_new_attempt_for_same_logical_message() {
    let (f, key, sent, payload) = fixture(false, "deleted");
    f.call(
        "A",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"A",&sent,"R1","deleted")}),
    );
    reject(
        &f,
        "A",
        json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P1","payload":"changed"}),
        "idempotency_conflict",
    );
    reject(
        &f,
        "A",
        json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P2","payload":payload}),
        "acceptance_conflict",
    );
    let receipt = re_sign(&key, &permit(&f, &key, "A", &sent, "R1", "deleted"), |s| {
        s["plan_id"] = json!("R2")
    });
    reject(
        &f,
        "A",
        json!({"operation":"wire_reclaim","receipt":receipt}),
        "reclaim_target_invalid",
    );
}

#[test]
fn compact_proof_budget_counts_full_plan_results_and_signatures() {
    use super::wire_reclaim_types::{Plan, State, BYTE_LIMIT, PLAN_LIMIT};
    let mut state = State::default();
    let empty = crate::permission::receipts::SignedRecord {
        statement_bytes: "".into(),
        signature_bytes: "".into(),
    };
    state.plans.insert(
        "R".into(),
        Plan {
            request_json: None,
            receipt: empty.clone(),
            result: json!("x".repeat(BYTE_LIMIT)),
        },
    );
    assert_eq!(state.budget().unwrap_err().code, "resource_exhausted");
    state.plans.clear();
    for i in 0..=PLAN_LIMIT {
        state.plans.insert(
            format!("R{i}"),
            Plan {
                request_json: None,
                receipt: empty.clone(),
                result: json!(null),
            },
        );
    }
    assert_eq!(state.budget().unwrap_err().code, "resource_exhausted");
}
