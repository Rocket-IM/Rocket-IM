//! 固定原阈值的合成近满装置；真实末条消息和控制走原入口，不作为容量或性能验收。
#[path = "quota_cache_tests.rs"]
mod cache;
#[path = "quota_test_support.rs"]
mod support;
use super::stream_source_test_support::{page, setup, signed, slot};
use super::wire_send_order_test_support::{load, reject};
use super::{wire_tests::Fixture, MAX_RECORDS};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use support::*;

#[test]
fn quota_wire_outbox_last_insert_and_full_retry_preserve_original_crypto() {
    let f = Fixture::new();
    let original = f.send("A", "original");
    fill_outbox(&f, &original, MAX_RECORDS - 1);
    #[cfg(feature = "wire-send-probe")]
    super::wire_send_probe::reset();
    assert_eq!(f.send("A", "last")["reused"], false);
    #[cfg(feature = "wire-send-probe")]
    assert_eq!(super::wire_send_probe::calls(), 1);
    let saved = state_bytes(&f, "A");
    assert_eq!(load(&f, "A").wire.outbox.len(), MAX_RECORDS);
    #[cfg(feature = "wire-send-probe")]
    super::wire_send_probe::reset();
    reject(
        &f,
        "A",
        json!({"operation":"wire_send","logical_message_id":"overflow",
        "attempt_id":"P1","payload":"synthetic test content"}),
        "resource_exhausted",
    );
    let retry = f.send("A", "original");
    assert_eq!(retry["reused"], true);
    assert!(retry["envelope"] == original["envelope"]);
    assert!(state_bytes(&f, "A") == saved);
    #[cfg(feature = "wire-send-probe")]
    assert_eq!(super::wire_send_probe::calls(), 0);
}

#[test]
fn quota_wire_inbox_last_insert_then_duplicate_succeeds_at_full_capacity() {
    let f = Fixture::new();
    let original = f.send("A", "original");
    f.receive("B", &original["envelope"]);
    fill_inbox(&f, &original, MAX_RECORDS - 1);
    let last = f.send("A", "last");
    assert_eq!(f.receive("B", &last["envelope"])["duplicate"], false);
    assert_eq!(load(&f, "B").wire.inbox.len(), MAX_RECORDS);
    let saved = state_bytes(&f, "B");
    assert_eq!(f.receive("B", &original["envelope"])["duplicate"], true);
    assert!(state_bytes(&f, "B") == saved);
    let overflow = f.send("A", "overflow");
    reject(
        &f,
        "B",
        json!({"operation":"wire_receive",
        "header_bytes":overflow["envelope"]["header_bytes"],
        "payload_bytes":overflow["envelope"]["payload_bytes"]}),
        "resource_exhausted",
    );
    assert!(state_bytes(&f, "B") == saved);
}

#[test]
fn quota_processing_rolls_back_successful_prefix_when_last_inbox_slot_is_exceeded() {
    let (f, key) = setup();
    let first = f.send("A", "first");
    let second = f.send("A", "second");
    fill_inbox(&f, &first, MAX_RECORDS - 1);
    download(
        &f,
        &key,
        vec![slot(1), message(&first, &key, 2), message(&second, &key, 3)],
        0,
        3,
    );
    let saved = state_bytes(&f, "B");
    reject(
        &f,
        "B",
        json!({"operation":"wire_process"}),
        "resource_exhausted",
    );
    assert!(state_bytes(&f, "B") == saved);
    let state = load(&f, "B");
    assert_eq!(state.wire.inbox.len(), MAX_RECORDS - 1);
    assert!(state
        .wire_sync
        .slots
        .values()
        .all(|s| s.result.is_none() && !s.waiting));
    assert_eq!(state.wire_sync.processed_cursor, 0);
    // 通过真实签页更新第三槽不可用性，未删本机记录；前次失败没有耗掉第一条的 MLS 状态。
    let third =
        json!({"stream_id":"B_stream","event_seq":"3","event_id":"E3","availability":"deleted"});
    download(&f, &key, vec![third], 2, 3);
    let recovered = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(recovered["results"][1]["result"]["status"], "valid");
    assert_eq!(recovered["sync"]["processed_cursor"], "3");
    assert_eq!(load(&f, "B").wire.inbox.len(), MAX_RECORDS);
}

#[test]
fn quota_total_slots_stays_full_after_processing_and_allows_exact_overlap() {
    let (f, key) = setup();
    fill_slots(&f, &key, 9999, true);
    let sent = f.send("A", "last");
    let last = message(&sent, &key, 10_000);
    download(&f, &key, vec![last.clone()], 9999, 10_000);
    let processed = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(processed["sync"]["pending_count"], 0);
    assert_eq!(processed["sync"]["slot_count"], 10_000);
    let saved = state_bytes(&f, "B");
    download(&f, &key, vec![last], 9999, 10_000);
    assert!(state_bytes(&f, "B") == saved);
    reject(
        &f,
        "B",
        signed(&key, &page(vec![slot(10_001)], 10_001, 10_001), 10_000, 100),
        "resource_exhausted",
    );
    assert!(state_bytes(&f, "B") == saved);
}

#[test]
fn quota_pending_thousand_releases_after_process_without_deleting_total_slots() {
    let (f, key) = setup();
    fill_slots(&f, &key, 999, false);
    let sent = f.send("A", "last");
    let last = message(&sent, &key, 1000);
    download(&f, &key, vec![last.clone()], 999, 1000);
    assert_eq!(load(&f, "B").wire_sync.summary()["pending_count"], 1000);
    let saved = state_bytes(&f, "B");
    download(&f, &key, vec![last], 999, 1000);
    assert!(state_bytes(&f, "B") == saved);
    let next = signed(&key, &page(vec![slot(1001)], 1001, 1001), 1000, 100);
    reject(&f, "B", next.clone(), "resource_exhausted");
    let processed = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(processed["results"][999]["result"]["status"], "valid");
    assert_eq!(processed["sync"]["pending_count"], 0);
    assert_eq!(processed["sync"]["slot_count"], 1000);
    f.call("B", next);
    let after = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(after["sync"]["slot_count"], 1001);
    assert_eq!(after["sync"]["processed_cursor"], "1001");
}
