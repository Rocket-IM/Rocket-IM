//! 阅读命令是合成显式意图，不能作为人类实际阅读或 UI 验收证据。
#[path = "wire_read_boundary_tests.rs"]
mod boundaries;
#[path = "wire_read_test_support.rs"]
mod support;
use super::wire_send_order_test_support::{alter_invalid, load, reject};
use super::{codec, stream_source_test_support::setup, wire_tests::Fixture};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::fs;
use support::*;

#[test]
fn read_receive_delivery_and_read_events_never_create_implicit_intent() {
    let (f, key) = setup();
    let event = message(&f, &key, 1);
    download(
        &f,
        &key,
        vec![
            event,
            receipt(2, "delivery", "K001", "P1", "B", "B"),
            receipt(3, "read", "K001", "P1", "B", "B"),
        ],
        0,
        3,
    );
    let result = process(&f);
    assert!(result.get("read_confirmed_count").is_none());
    assert_eq!(
        pending(&f),
        json!({"request":null,"pending_count":0,"has_more":false})
    );
    assert_eq!(
        inspect(&f),
        json!({"pending_count":0,"confirmed_count":0,"records":[]})
    );
    assert!(serde_json::to_value(load(&f, "B"))
        .unwrap()
        .get("wire_reads")
        .is_none());
    assert_eq!(
        mark(&f, &["E1"]),
        json!({"marked_count":1,"duplicate_count":0,"pending_count":1,"confirmed_count":0})
    );
    assert_eq!(
        pending(&f)["request"],
        json!({"service_id":"S1","acceptance_ids":["K001"]})
    );
    // 原 Read 先于阅读意图；下一次处理只使用已持久事实，不重新解密或自动标记。
    let after = process(&f);
    assert_eq!(after["results"], json!([]));
    assert_eq!(after["read_confirmed_count"], 1);
    assert_eq!(
        inspect(&f)["records"][0]["confirmation"],
        json!({"event_id":"E3","event_seq":"3"})
    );
    assert!(pending(&f)["request"].is_null());
}

#[test]
fn read_only_exact_own_processed_signed_read_confirms_and_duplicate_mark_does_not_save() {
    let (f, key) = setup();
    let event = message(&f, &key, 1);
    download(&f, &key, vec![event], 0, 1);
    process(&f);
    mark(&f, &["E1"]);
    let before = fs::read(f.root.join("B/state.enc")).unwrap();
    assert_eq!(mark(&f, &["E1"])["duplicate_count"], 1);
    assert!(before == fs::read(f.root.join("B/state.enc")).unwrap());
    let invalid = vec![
        receipt(2, "delivery", "K001", "P1", "B", "B"),
        receipt(3, "read", "K001", "P1", "C", "C"),
        receipt(4, "read", "K001", "P1", "other", "B"),
        receipt(5, "read", "K001", "P2", "B", "B"),
        receipt(6, "read", "K999", "P1", "B", "B"),
    ];
    download(&f, &key, invalid, 1, 6);
    assert_eq!(process(&f)["read_confirmed_count"], 0);
    assert_eq!(inspect(&f)["pending_count"], 1);
    download(
        &f,
        &key,
        vec![receipt(7, "read", "K001", "P1", "B", "B")],
        6,
        7,
    );
    assert_eq!(inspect(&f)["pending_count"], 1);
    assert_eq!(process(&f)["read_confirmed_count"], 1);
    let saved = inspect(&f);
    let bytes = fs::read(f.root.join("B/state.enc")).unwrap();
    assert_eq!(mark(&f, &["E1"])["marked_count"], 0);
    assert!(bytes == fs::read(f.root.join("B/state.enc")).unwrap());
    assert_eq!(process(&f)["read_confirmed_count"], 0);
    assert_eq!(inspect(&f), saved);
    let output = saved.to_string();
    assert!(!output.contains("synthetic test content"));
    for field in [
        "payload",
        "provider",
        "envelope_sha256",
        "logical_key",
        "signature_bytes",
    ] {
        assert!(!output.contains(&format!("\"{field}\":")));
    }
}

#[test]
fn read_equivalent_resigned_acceptance_retry_preserves_pending_and_confirmation() {
    use crate::permission::receipts::SignedRecord;
    use ed25519_dalek::Signer;

    let (f, key) = setup();
    let event = message(&f, &key, 1);
    let envelope = &event["event"]["envelope"];
    let original: SignedRecord =
        serde_json::from_value(event["event"]["acceptance_receipt"].clone()).unwrap();
    let statement = codec::decode(&original.statement_bytes).unwrap();
    download(&f, &key, vec![event.clone()], 0, 1);
    process(&f);
    mark(&f, &["E1"]);

    for confirmed in [false, true] {
        if confirmed {
            download(
                &f,
                &key,
                vec![receipt(2, "read", "K001", "P1", "B", "B")],
                1,
                2,
            );
            assert_eq!(process(&f)["read_confirmed_count"], 1);
        }
        let saved = inspect(&f);
        // 同一声明重新编码后由同一合成 Service 私钥真实签名，原收件入口允许替换证明。
        let body: Value = serde_json::from_slice(&statement).unwrap();
        let mut raw = serde_json::to_vec_pretty(&body).unwrap();
        if confirmed {
            raw.push(b'\n');
        }
        let mut signed = crate::message_acceptance::SIGNING_DOMAIN.to_vec();
        signed.extend(&raw);
        let proof = SignedRecord {
            statement_bytes: codec::encode(&raw),
            signature_bytes: codec::encode(&key.sign(&signed).to_bytes()),
        };
        assert!(proof != original);
        let result = f.call(
            "B",
            json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],
                "payload_bytes":envelope["payload_bytes"],"acceptance_id":"K001",
                "acceptance_receipt":proof}),
        );
        assert_eq!(result["duplicate"], true);
        assert_eq!(inspect(&f), saved);
        let restored = load(&f, "B");
        assert!(
            restored
                .wire
                .inbox
                .values()
                .next()
                .unwrap()
                .acceptance_receipt
                .as_ref()
                == Some(&proof)
        );
        assert_eq!(mark(&f, &["E1"])["marked_count"], 0);
        assert_eq!(inspect(&f), saved);
        assert_eq!(pending(&f)["pending_count"], usize::from(!confirmed));
    }
}

#[test]
fn read_aliases_deduplicate_by_acceptance_and_later_unavailability_keeps_original_fact() {
    let (f, key) = setup();
    let first = message(&f, &key, 1);
    let mut alias = first.clone();
    alias["event_seq"] = json!("2");
    alias["event_id"] = json!("E2");
    download(&f, &key, vec![first.clone(), alias.clone()], 0, 2);
    process(&f);
    assert_eq!(mark(&f, &["E2", "E1"])["marked_count"], 1);
    assert_eq!(inspect(&f)["records"][0]["message_event_id"], "E2");
    download(
        &f,
        &key,
        vec![receipt(3, "read", "K001", "P1", "B", "B")],
        2,
        3,
    );
    process(&f);
    let saved = inspect(&f);
    let tombstones=(1..=3).map(|seq|json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),"availability":"deleted"})).collect();
    download(&f, &key, tombstones, 0, 3);
    let bytes = fs::read(f.root.join("B/state.enc")).unwrap();
    assert_eq!(mark(&f, &["E1", "E2"])["duplicate_count"], 1);
    assert!(bytes == fs::read(f.root.join("B/state.enc")).unwrap());
    assert_eq!(inspect(&f), saved);
    let (f, key) = setup();
    let first = message(&f, &key, 1);
    download(&f, &key, vec![first], 0, 1);
    process(&f);
    download(
        &f,
        &key,
        vec![
            json!({"stream_id":"B_stream","event_seq":"1","event_id":"E1","availability":"expired"}),
        ],
        0,
        1,
    );
    reject(
        &f,
        "B",
        json!({"operation":"wire_read","event_ids":["E1"]}),
        "read_target_invalid",
    );
}

#[test]
fn read_pending_exports_stable_hundred_item_batches_and_confirmed_items_leave_queue() {
    let (f, key) = setup();
    let events: Vec<_> = (1..=101).map(|seq| message(&f, &key, seq)).collect();
    download(&f, &key, events[..100].to_vec(), 0, 100);
    process(&f);
    download(&f, &key, events[100..].to_vec(), 100, 101);
    process(&f);
    let ids: Vec<_> = (1..=100).map(|seq| format!("E{seq}")).collect();
    f.call("B", json!({"operation":"wire_read","event_ids":ids}));
    mark(&f, &["E101"]);
    let batch = pending(&f);
    assert_eq!(batch["pending_count"], 101);
    assert_eq!(batch["has_more"], true);
    assert_eq!(
        batch["request"]["acceptance_ids"].as_array().unwrap().len(),
        100
    );
    assert_eq!(pending(&f), batch);
    let acknowledgements = (1..=100)
        .map(|seq| receipt(seq + 101, "read", &format!("K{seq:03}"), "P1", "B", "B"))
        .collect();
    download(&f, &key, acknowledgements, 101, 201);
    assert_eq!(process(&f)["read_confirmed_count"], 100);
    assert_eq!(
        pending(&f),
        json!({"request":{"service_id":"S1","acceptance_ids":["K101"]},"pending_count":1,"has_more":false})
    );
}
