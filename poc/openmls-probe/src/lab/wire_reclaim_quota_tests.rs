//! 原阈值合成占额后，真实已结算候选和真实后继走公开入口；不代表自然累计容量。
use super::super::{wire_send_order_test_support::alter_invalid, wire_types, MAX_RECORDS};
use super::*;

#[test]
fn full_original_outbox_reclaims_real_candidate_then_sends_real_successor() {
    let (f, key, sent, payload) = fixture(false, "deleted");
    alter_invalid(&f, "A", |state| {
        let raw = codec::decode(sent["envelope"]["header_bytes"].as_str().unwrap()).unwrap();
        for i in 1..MAX_RECORDS {
            let mut h: wire_types::Header = serde_json::from_slice(&raw).unwrap();
            h.logical_message_id = format!("fill{i}");
            let header_bytes = codec::encode(&serde_json::to_vec(&h).unwrap());
            let synthetic = json!({"envelope":{"header_bytes":header_bytes,"payload_bytes":codec::encode(b"x")},"logical_message_id":h.logical_message_id,"attempt_id":"P1"});
            let logical = h.logical_key().unwrap();
            let attempt = h.attempt_key().unwrap();
            state.wire.tails.insert(logical.clone(), attempt.clone());
            state.wire.outbox.insert(
                attempt,
                wire_types::Outbound {
                    logical_key: logical,
                    attempt_id: "P1".into(),
                    payload: String::new(),
                    envelope: serde_json::from_value(synthetic["envelope"].clone()).unwrap(),
                    replaces_attempt_id: None,
                    closure_id: None,
                    acceptance_receipt: Some(
                        serde_json::from_value(
                            accept(&synthetic, &key, &format!("F{i}"))["acceptance_receipt"]
                                .clone(),
                        )
                        .unwrap(),
                    ),
                },
            );
        }
    });
    let next = json!({"operation":"wire_send","logical_message_id":"M2","attempt_id":"P1","payload":"synthetic test content"});
    reject(&f, "A", next.clone(), "resource_exhausted");
    f.call(
        "A",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"A",&sent,"R1","deleted")}),
    );
    assert_eq!(load(&f, "A").wire.outbox.len(), MAX_RECORDS - 1);
    let result = f.call("A", next);
    assert_eq!(result["reused"], false);
    assert_eq!(load(&f, "A").wire.outbox.len(), MAX_RECORDS);
    assert_eq!(f.call("A",json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P1","payload":payload}))["payload_reclaimed"],true);
}

#[test]
fn full_original_inbox_and_slots_reclaim_real_candidate_then_receive_real_message() {
    let (f, key, sent, _) = fixture(false, "deleted");
    alter_invalid(&f, "B", |state| {
        while state.wire.inbox.len() < MAX_RECORDS {
            let id = format!("fill{}", state.wire.inbox.len());
            state.wire.inbox.insert(
                id.clone(),
                wire_types::Inbound {
                    logical_key: id,
                    attempt_id: "P1".into(),
                    envelope: wire_types::Envelope {
                        header_bytes: codec::encode(b"x"),
                        payload_bytes: codec::encode(b"x"),
                    },
                    payload_digest: [0; 32],
                    acceptance_id: None,
                    payload: None,
                    acceptance_receipt: None,
                },
            );
        }
        for seq in 4..=10000 {
            state.wire_sync.slots.insert(seq,super::super::wire_sync_types::StoredSlot {
                slot:serde_json::from_value(json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("BE{seq}"),"availability":"deleted"})).unwrap(),
                result:Some(json!({"status":"unavailable","availability":"deleted"})),waiting:false});
        }
        state.wire_sync.download_cursor = 10000;
        state.wire_sync.processed_cursor = 10000;
    });
    let next = f.send("A", "M2");
    let proof = accept(&next, &key, "K2");
    let next_event = event(
        "B",
        10001,
        json!({"type":"message","acceptance_id":"K2","envelope":next["envelope"],"acceptance_receipt":proof["acceptance_receipt"]}),
    );
    reject(
        &f,
        "B",
        download_operation(&key, "B", vec![next_event.clone()], 10000, 10001),
        "resource_exhausted",
    );
    reject(
        &f,
        "B",
        json!({"operation":"wire_receive","header_bytes":next["envelope"]["header_bytes"],"payload_bytes":next["envelope"]["payload_bytes"]}),
        "resource_exhausted",
    );
    f.call(
        "B",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"B",&sent,"R1","deleted")}),
    );
    assert_eq!(load(&f, "B").wire.inbox.len(), MAX_RECORDS - 1);
    assert_eq!(
        f.call("B", json!({"operation":"wire_inspect"}))["sync"]["active_slot_count"],
        9997
    );
    download(&f, &key, "B", vec![next_event], 10000, 10001);
    let after = load(&f, "B");
    assert_eq!(after.wire.inbox.len(), MAX_RECORDS);
    assert_eq!(after.wire_sync.slots.len(), 10001);
    assert_eq!(after.wire_sync.processed_cursor, 10001);
    assert_eq!(f.receive("B", &sent["envelope"])["payload_reclaimed"], true);
}

#[test]
fn full_compact_proof_budgets_reject_complete_candidate_before_any_original_removal() {
    use super::super::wire_reclaim_types::{
        Plan, SlotFact, State, BYTE_LIMIT, MESSAGE_LIMIT, PLAN_LIMIT, SLOT_LIMIT,
    };
    let (f, key, sent, _) = fixture(false, "deleted");
    // 填充项只占额，不是可加载的成功回收快照；真实候选构造、许可核验和整批预算走执行函数。
    for limit in ["bytes", "plans", "messages", "slots"] {
        let device = if limit == "slots" { "B" } else { "A" };
        let mut state = load(&f, device);
        let receipt: crate::permission::receipts::SignedRecord =
            serde_json::from_value(permit(&f, &key, device, &sent, "R1", "deleted")).unwrap();
        let mut ledger = State::default();
        let filler = Plan {
            receipt: receipt.clone(),
            result: json!(null),
        };
        match limit {
            "bytes" => {
                ledger.plans.insert(
                    "F".into(),
                    Plan {
                        receipt: receipt.clone(),
                        result: json!("x".repeat(BYTE_LIMIT)),
                    },
                );
                let excess = serde_json::to_vec(&ledger).unwrap().len() - BYTE_LIMIT;
                ledger.plans.get_mut("F").unwrap().result = json!("x".repeat(BYTE_LIMIT - excess));
            }
            "plans" => {
                for i in 0..PLAN_LIMIT {
                    ledger.plans.insert(format!("F{i}"), filler.clone());
                }
            }
            "messages" => {
                let candidate =
                    super::super::wire_reclaim::candidate(&state, "K1", "R1", None).unwrap();
                for i in 0..MESSAGE_LIMIT {
                    let mut item = candidate.clone();
                    item.acceptance_id = format!("F{i}");
                    item.logical_key = format!("L{i}");
                    item.header_bytes.clear();
                    item.outbound.clear();
                    item.acceptance_receipt.statement_bytes.clear();
                    item.acceptance_receipt.signature_bytes.clear();
                    ledger.messages.insert(item.logical_key.clone(), item);
                }
            }
            _ => {
                for i in 0..SLOT_LIMIT {
                    ledger.slots.insert(
                        100_000 + i as u64,
                        SlotFact {
                            event_id: format!("F{i}"),
                            acceptance_id: "F".into(),
                            original_event_sha256: "00".repeat(32),
                            kind: "message".into(),
                        },
                    );
                }
            }
        }
        assert!(ledger.budget().is_ok(), "占额未新增候选前仍在{limit}硬界内");
        state.wire_reclamation = Some(ledger);
        let before = serde_json::to_vec(&state).unwrap();
        assert_eq!(
            super::super::wire_reclaim::execute(&mut state, receipt.clone())
                .unwrap_err()
                .code,
            "resource_exhausted",
            "{limit}"
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
}
