//! 每次公开调用重新加载加密快照；拒绝路径核对原快照字节不变。
use super::{codec, stream_source_test_support::*, wire_tests::Fixture, Context};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::fs;

fn reject(f: &Fixture, operation: Value, code: &str) {
    let before = fs::read(f.root.join("B/state.enc")).unwrap();
    f.fails("B", operation, code);
    assert_eq!(before, fs::read(f.root.join("B/state.enc")).unwrap());
}

#[test]
fn signed_empty_first_page_binds_source_and_survives_reload() {
    let (f, key) = setup();
    let empty = page(vec![], 0, 0);
    let request = signed(&key, &empty, 0, 100);
    assert_eq!(
        f.call("B", request.clone())["sync"]["source_verified"],
        true
    );
    assert_eq!(
        f.call("B", json!({"operation":"wire_inspect"}))["sync"]["stream_id"],
        "B_stream"
    );
    assert_eq!(f.call("B", request)["status"], "downloaded");
    let first = signed(&key, &page(vec![slot(1)], 1, 1), 0, 100);
    assert_eq!(f.call("B", first)["sync"]["download_cursor"], "1");
    assert_eq!(
        f.call("B", json!({"operation":"wire_process"}))["sync"]["processed_cursor"],
        "1"
    );
}

#[test]
fn source_scope_key_digest_and_raw_bypass_reject_before_save() {
    let (f, key) = setup();
    let original_page = page(vec![slot(1)], 1, 1);
    let raw = serde_json::to_vec(&original_page).unwrap();
    for field in ["service_id", "account_id", "device_id", "stream_id"] {
        let mut body = statement(&raw, 0, 100);
        body[field] = json!("foreign");
        reject(&f, signed_raw(&key, &raw, &body), "stream_page_context");
    }
    reject(
        &f,
        signed(&SigningKey::from_bytes(&[62; 32]), &original_page, 0, 100),
        "stream_page_signature",
    );
    let mut tampered = signed(&key, &original_page, 0, 100);
    tampered["page_bytes"] = json!(codec::encode(b"{}"));
    reject(&f, tampered, "stream_page_digest");
    let mut raw_request = original_page;
    raw_request["operation"] = json!("wire_download");
    reject(&f, raw_request, "stream_source_required");
    assert_eq!(
        f.call("B", signed(&key, &page(vec![slot(1)], 1, 1), 0, 100))["status"],
        "downloaded"
    );
}

#[test]
fn missing_pin_does_not_learn_key_from_signed_response() {
    let f = Fixture::new();
    reject(
        &f,
        signed(
            &SigningKey::from_bytes(&[61; 32]),
            &page(vec![], 0, 0),
            0,
            100,
        ),
        "stream_source_required",
    );
    assert_eq!(f.download(vec![], 0)["sync"]["source_verified"], false);
}

#[test]
fn signed_range_and_statement_encoding_fail_atomically() {
    let (f, key) = setup();
    let valid = page(vec![slot(1)], 1, 1);
    let raw = serde_json::to_vec(&valid).unwrap();
    for (field, value) in [
        ("protocol_version", "future"),
        ("limit", "0"),
        ("limit", "101"),
        ("after_seq", "01"),
        ("after_seq", "18446744073709551616"),
        ("page_sha256", "z"),
    ] {
        let mut body = statement(&raw, 0, 100);
        body[field] = json!(value);
        reject(&f, signed_raw(&key, &raw, &body), "stream_page_invalid");
    }
    reject(&f, signed(&key, &valid, 1, 100), "stream_page_range");
    reject(
        &f,
        signed(&key, &page(vec![slot(2)], 2, 2), 0, 100),
        "stream_page_range",
    );
    reject(
        &f,
        signed(&key, &page(vec![slot(1), slot(2)], 2, 2), 0, 1),
        "stream_page_range",
    );
    reject(
        &f,
        signed(&key, &page(vec![], 1, 1), 0, 100),
        "stream_page_range",
    );
    reject(
        &f,
        signed(&key, &page(vec![slot(1)], 1, 0), 0, 100),
        "cursor_invalid",
    );
    let duplicate = br#"{"stream_id":"B_stream","stream_id":"B_stream","events":[],"next_after_seq":"0","watermark":"0","has_more":false}"#;
    reject(
        &f,
        signed_raw(&key, duplicate, &statement(duplicate, 0, 100)),
        "stream_page_invalid",
    );
    let too_large = vec![b' '; crate::stream_page::PAGE_BYTES_LIMIT + 1];
    reject(
        &f,
        signed_raw(&key, &too_large, &statement(&too_large, 0, 100)),
        "stream_page_invalid",
    );
}

#[test]
fn legacy_bound_pages_cannot_be_laundered_after_pinning() {
    for events in [vec![], vec![slot(1)]] {
        let f = Fixture::new();
        let next = events.len() as u64;
        f.download(events, next);
        let key = SigningKey::from_bytes(&[61; 32]);
        pin(&f, &key);
        reject(
            &f,
            json!({"operation":"wire_process"}),
            "source_migration_required",
        );
        reject(
            &f,
            signed(&key, &page(vec![], next, next), next, 100),
            "source_migration_required",
        );
        assert_eq!(
            f.call("B", json!({"operation":"wire_inspect"}))["sync"]["source_verified"],
            false
        );
    }
    let mut old = serde_json::to_value(super::wire_sync::SyncState::default()).unwrap();
    old.as_object_mut().unwrap().remove("source_verified");
    let loaded: super::wire_sync::SyncState = serde_json::from_value(old).unwrap();
    assert!(!loaded.source_verified);
}

#[test]
fn signed_overlap_projection_and_conflict_keep_original_slot() {
    let (f, key) = setup();
    let first = page(vec![slot(1)], 1, 2);
    f.call("B", signed(&key, &first, 0, 1));
    f.call("B", signed(&key, &first, 0, 1));
    f.call(
        "B",
        signed(&key, &page(vec![slot(1), slot(2)], 2, 2), 0, 100),
    );
    f.call("B", json!({"operation":"wire_process"}));
    let mut expired = slot(1);
    expired["availability"] = json!("expired");
    expired.as_object_mut().unwrap().remove("event");
    f.call(
        "B",
        signed(&key, &page(vec![expired, slot(2)], 2, 2), 0, 100),
    );
    let before = f.call(
        "B",
        json!({"operation":"wire_slot_inspect","event_seq":"1"}),
    );
    assert_eq!(before["slot"]["availability"], "expired");
    assert_eq!(before["slot"]["event"], slot(1)["event"]);
    assert_eq!(
        f.call(
            "B",
            signed(&key, &page(vec![slot(1), slot(2)], 2, 2), 0, 100)
        )["status"],
        "stream_conflict"
    );
    assert_eq!(
        f.call(
            "B",
            json!({"operation":"wire_slot_inspect","event_seq":"1"})
        ),
        before
    );
    reject(&f, json!({"operation":"wire_process"}), "stream_conflict");
}

#[test]
fn signed_empty_page_at_u64_max_does_not_overflow() {
    let (f, key) = setup();
    let locked = super::store::LockedDevice::open(&f.root.join("B")).unwrap();
    let mut state = locked
        .load(&Context {
            service: "S1".into(),
            account: "B".into(),
            device: "B".into(),
        })
        .unwrap()
        .unwrap();
    state.wire_sync.source_verified = true;
    state.wire_sync.stream_id = Some("B_stream".into());
    state.wire_sync.download_cursor = u64::MAX;
    state.wire_sync.processed_cursor = u64::MAX;
    locked.save(&mut state, super::CrashPoint::None).unwrap();
    drop(locked);
    let empty = page(vec![], u64::MAX, u64::MAX);
    assert_eq!(
        f.call("B", signed(&key, &empty, u64::MAX, 100))["status"],
        "downloaded"
    );
    reject(
        &f,
        signed(&key, &page(vec![slot(1)], 1, u64::MAX), u64::MAX, 100),
        "stream_page_range",
    );
}
