//! 消息生命周期只改变当前可用性，不承诺回收已有正文或重置 MLS 状态。

#[path = "wire_lifecycle_test_support.rs"]
mod support;
use super::{
    stream_source_test_support::{page, setup, signed},
    wire_send_order_test_support::{load, reject},
    wire_tests::Fixture,
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use support::*;

#[test]
fn same_page_lifecycle_prevents_real_message_decryption_before_processing() {
    for availability in ["deleted", "expired"] {
        let (f, key) = setup();
        let event = message(&f, &key, 1);
        let before = business(&f);
        download(
            &f,
            &key,
            vec![event.clone(), notice(2, 1, availability)],
            0,
            2,
        );
        assert_eq!(business(&f), before);
        assert_eq!(slot(&f, 1)["slot"]["event"], event["event"]);
        assert_eq!(slot(&f, 1)["slot"]["availability"], availability);
        no_plaintext(&f, &process(&f), availability);
        assert_eq!(business(&f), before);
        reject(
            &f,
            "B",
            json!({"operation":"wire_read","event_ids":["E1"]}),
            "read_target_invalid",
        );
    }
}

#[test]
fn later_signed_notice_stops_already_queued_message_without_clearing_original() {
    for availability in ["deleted", "expired"] {
        let (f, key) = setup();
        let event = message(&f, &key, 1);
        download(&f, &key, vec![event.clone()], 0, 1);
        let before = business(&f);
        download(&f, &key, vec![notice(2, 1, availability)], 1, 2);
        assert!(slot(&f, 1)["result"].is_null());
        no_plaintext(&f, &process(&f), availability);
        assert_eq!(business(&f), before);
        assert_eq!(slot(&f, 1)["slot"]["event"], event["event"]);
    }
}

#[test]
fn processed_plaintext_delivery_and_existing_read_intent_survive_terminal_projection() {
    for already_read in [false, true] {
        let (f, key) = setup();
        download(&f, &key, vec![message(&f, &key, 1)], 0, 1);
        let original = process(&f);
        assert_eq!(original["results"][0]["result"]["status"], "valid");
        if already_read {
            f.call("B", json!({"operation":"wire_read","event_ids":["E1"]}));
        }
        let before = business(&f);
        let stored_result = slot(&f, 1)["result"].clone();
        download(&f, &key, vec![notice(2, 1, "deleted")], 1, 2);
        let processed = process(&f);
        assert_eq!(processed["results"].as_array().unwrap().len(), 1);
        assert_eq!(
            processed["results"][0]["result"]["status"],
            "availability_recorded"
        );
        assert_eq!(processed["deliveries"], original["deliveries"]);
        assert_eq!(slot(&f, 1)["result"], stored_result);
        assert_eq!(business(&f), before);
        if already_read {
            assert_eq!(
                f.call("B", json!({"operation":"wire_read","event_ids":["E1"]}))["duplicate_count"],
                1
            );
        } else {
            reject(
                &f,
                "B",
                json!({"operation":"wire_read","event_ids":["E1"]}),
                "read_target_invalid",
            );
        }
    }
}

#[test]
fn waiting_real_future_epoch_becomes_unavailable_without_applying_missing_commit() {
    let (f, key) = setup();
    f.call(
        "A",
        json!({"operation":"remove","id":"removeC","member":"C"}),
    );
    f.call(
        "A",
        json!({"operation":"wire_configure","conversation_id":"G1","authorization_version":"2"}),
    );
    download(&f, &key, vec![message(&f, &key, 1)], 0, 1);
    let before = business(&f);
    let waiting = process(&f);
    assert_eq!(
        waiting["results"][0]["result"]["status"],
        "waiting_dependency"
    );
    assert_eq!(
        waiting["results"][0]["result"]["code"],
        "missing_crypto_state"
    );
    assert_eq!(waiting["sync"]["processed_cursor"], "0");
    assert_eq!(slot(&f, 1)["waiting"], true);
    download(&f, &key, vec![notice(2, 1, "expired")], 1, 2);
    no_plaintext(&f, &process(&f), "expired");
    assert_eq!(slot(&f, 1)["waiting"], false);
    assert_eq!(business(&f), before);
}

#[test]
fn signed_tombstone_uses_service_binding_and_rejects_later_identity_substitution() {
    let (f, key) = setup();
    let original = request(
        &key,
        vec![tombstone(1, "expired"), notice(2, 1, "expired")],
        0,
        2,
    );
    assert_eq!(
        f.call("B", original.clone())["sync"]["source_verified"],
        true
    );
    no_plaintext(&f, &process(&f), "expired");
    let before = state_bytes(&f);
    f.call("B", original);
    assert_eq!(state_bytes(&f), before);
    for field in ["acceptance_id", "attempt_id", "target_event_id"] {
        let mut changed = notice(3, 1, "expired");
        changed["event"][field] = json!("different");
        reject(
            &f,
            "B",
            request(&key, vec![changed], 2, 3),
            "lifecycle_target_invalid",
        );
    }
    download(&f, &key, vec![notice(3, 1, "expired")], 2, 3);
    assert_eq!(
        process(&f)["results"][0]["result"]["status"],
        "availability_recorded"
    );
    assert!(slot(&f, 1)["slot"].get("event").is_none());
}

#[test]
fn lifecycle_target_confusion_and_malformed_fields_leave_complete_snapshot_unchanged() {
    let (f, key) = setup();
    download(&f, &key, vec![message(&f, &key, 1)], 0, 1);
    for (field, value, code) in [
        ("target_event_seq", json!("0"), "invalid_envelope"),
        ("target_event_seq", json!("01"), "invalid_envelope"),
        ("target_event_seq", json!("2"), "lifecycle_target_invalid"),
        ("target_event_seq", json!("3"), "lifecycle_target_invalid"),
        (
            "target_event_seq",
            json!("18446744073709551615"),
            "lifecycle_target_invalid",
        ),
        (
            "target_event_id",
            json!("other"),
            "lifecycle_target_invalid",
        ),
        ("acceptance_id", json!("other"), "lifecycle_target_invalid"),
        ("attempt_id", json!("P2"), "lifecycle_target_invalid"),
        ("availability", json!("available"), "invalid_envelope"),
        ("availability", json!("access_removed"), "invalid_envelope"),
    ] {
        let mut changed = notice(2, 1, "deleted");
        changed["event"][field] = value;
        reject(&f, "B", request(&key, vec![changed], 1, 2), code);
    }
    let mut cross_stream = notice(2, 1, "deleted");
    cross_stream["stream_id"] = json!("other_stream");
    reject(
        &f,
        "B",
        request(&key, vec![cross_stream], 1, 2),
        "invalid_envelope",
    );
    assert_eq!(slot(&f, 1)["slot"]["availability"], "available");
}

#[test]
fn invalid_suffix_cannot_commit_valid_prefix_or_hide_original_message_binding() {
    let (f, key) = setup();
    let event = message(&f, &key, 1);
    download(&f, &key, vec![event], 0, 1);
    let mut bad = notice(3, 1, "deleted");
    bad["event"]["acceptance_id"] = json!("different");
    reject(
        &f,
        "B",
        request(&key, vec![notice(2, 1, "deleted"), bad], 1, 3),
        "lifecycle_target_invalid",
    );
    // 页内先提供无正文投影，也不能避开本机已存原头的绑定检查。
    let mut bad = notice(2, 1, "deleted");
    bad["event"]["attempt_id"] = json!("P2");
    reject(
        &f,
        "B",
        request(&key, vec![tombstone(1, "deleted"), bad], 0, 2),
        "lifecycle_target_invalid",
    );
    assert_eq!(slot(&f, 1)["slot"]["availability"], "available");
    assert_eq!(process(&f)["results"][0]["result"]["status"], "valid");
}

#[test]
fn receipts_controls_and_notifications_are_not_message_lifecycle_targets() {
    for kind in ["delivery", "read", "crypto_control"] {
        let (f, key) = setup();
        let mut target = super::stream_source_test_support::slot(1);
        target["event"]["type"] = json!(kind);
        if kind == "crypto_control" {
            target["event"] = json!({"type":"crypto_control","control":{"control_id":"C1",
                "from_state_ref":"0".repeat(64),"to_state_ref":"1".repeat(64),"payload_bytes":"YQ=="}});
        }
        reject(
            &f,
            "B",
            request(&key, vec![target, notice(2, 1, "deleted")], 0, 2),
            "lifecycle_target_invalid",
        );
    }
    let (f, key) = setup();
    download(
        &f,
        &key,
        vec![message(&f, &key, 1), notice(2, 1, "deleted")],
        0,
        2,
    );
    reject(
        &f,
        "B",
        request(&key, vec![notice(3, 2, "deleted")], 2, 3),
        "lifecycle_target_invalid",
    );
}

#[test]
fn unsigned_legacy_download_cannot_introduce_new_lifecycle_claim() {
    let f = Fixture::new();
    let sent = f.send("A", "M1");
    f.download(vec![json!({"stream_id":"B_stream","event_seq":"1","event_id":"E1","availability":"available",
        "event":{"type":"message","acceptance_id":"K1","envelope":sent["envelope"]}})], 1);
    reject(
        &f,
        "B",
        json!({"operation":"wire_download","stream_id":"B_stream","events":[notice(2,1,"deleted")],
        "next_after_seq":"2","watermark":"2","has_more":false}),
        "stream_source_required",
    );
    assert_eq!(process(&f)["results"][0]["result"]["status"], "valid");
}

#[test]
fn duplicate_notices_are_idempotent_and_stale_available_overlap_still_halts() {
    let (f, key) = setup();
    let event = message(&f, &key, 1);
    download(&f, &key, vec![event.clone()], 0, 1);
    let notification = notice(2, 1, "deleted");
    let update = request(&key, vec![notification.clone()], 1, 2);
    f.call("B", update.clone());
    no_plaintext(&f, &process(&f), "deleted");
    let before = state_bytes(&f);
    f.call("B", update);
    assert_eq!(state_bytes(&f), before);
    assert_eq!(process(&f)["results"], json!([]));
    let duplicate = notice(3, 1, "deleted");
    download(&f, &key, vec![duplicate.clone()], 2, 3);
    assert_eq!(process(&f)["results"].as_array().unwrap().len(), 1);
    let target = slot(&f, 1);
    let before = business(&f);
    let stale = download(
        &f,
        &key,
        vec![event, notification, duplicate, tombstone(4, "deleted")],
        0,
        4,
    );
    assert_eq!(stale["status"], "stream_conflict");
    assert_eq!(stale["sync"]["slot_count"], 3);
    assert_eq!(stale["sync"]["download_cursor"], "3");
    assert_eq!(slot(&f, 1), target);
    assert_eq!(business(&f), before);
    reject(
        &f,
        "B",
        json!({"operation":"wire_process"}),
        "stream_conflict",
    );
}

#[test]
fn conflicting_terminal_reason_cannot_overwrite_known_lifecycle() {
    let (f, key) = setup();
    download(
        &f,
        &key,
        vec![message(&f, &key, 1), notice(2, 1, "deleted")],
        0,
        2,
    );
    reject(
        &f,
        "B",
        request(&key, vec![notice(3, 1, "expired")], 2, 3),
        "lifecycle_target_invalid",
    );
    // 后续普通投影同样不能绕过已保存生命周期通知的终态约束。
    reject(
        &f,
        "B",
        request(
            &key,
            vec![tombstone(1, "expired"), notice(2, 1, "deleted")],
            0,
            2,
        ),
        "lifecycle_target_invalid",
    );
    no_plaintext(&f, &process(&f), "deleted");
}

#[test]
fn missing_target_and_access_removed_projection_are_not_accepted_as_message_binding() {
    let (f, key) = setup();
    download(&f, &key, vec![message(&f, &key, 1)], 0, 1);
    // 只在内存构造缺槽的损坏状态，证明不能仅凭 download_cursor 推定目标存在。
    let mut state = load(&f, "B");
    state.wire_sync.slots.clear();
    let before = serde_json::to_vec(&state).unwrap();
    let events = serde_json::from_value(json!([notice(2, 1, "deleted")])).unwrap();
    let error = super::wire_sync::download_verified(
        &mut state,
        "B_stream".into(),
        events,
        "2".into(),
        "2".into(),
        false,
    )
    .unwrap_err();
    assert_eq!(error.code, "lifecycle_target_invalid");
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    reject(
        &f,
        "B",
        request(
            &key,
            vec![tombstone(1, "access_removed"), notice(2, 1, "deleted")],
            0,
            2,
        ),
        "lifecycle_target_invalid",
    );
}

#[test]
fn notification_cannot_reuse_read_message_id_and_break_snapshot_reload() {
    let (f, key) = setup();
    download(&f, &key, vec![message(&f, &key, 1)], 0, 1);
    let valid = process(&f);
    assert_eq!(valid["results"][0]["result"]["status"], "valid");
    f.call("B", json!({"operation":"wire_read","event_ids":["E1"]}));
    let before = state_bytes(&f);
    let mut duplicate_id = notice(2, 1, "deleted");
    duplicate_id["event_id"] = json!("E1");
    reject(
        &f,
        "B",
        request(&key, vec![duplicate_id], 1, 2),
        "invalid_envelope",
    );
    assert_eq!(state_bytes(&f), before);
    assert_eq!(process(&f)["deliveries"], valid["deliveries"]);
    assert_eq!(
        f.call("B", json!({"operation":"wire_read","event_ids":["E1"]}))["duplicate_count"],
        1
    );
}

#[test]
fn repeated_event_id_in_new_batch_is_rejected_before_any_slot_is_saved() {
    let (f, key) = setup();
    let original = message(&f, &key, 1);
    let before = state_bytes(&f);
    let mut duplicate_id = notice(2, 1, "deleted");
    duplicate_id["event_id"] = original["event_id"].clone();
    reject(
        &f,
        "B",
        request(&key, vec![original.clone(), duplicate_id], 0, 2),
        "invalid_envelope",
    );
    assert_eq!(state_bytes(&f), before);
    let exact = request(&key, vec![original], 0, 1);
    f.call("B", exact.clone());
    let saved = state_bytes(&f);
    assert_eq!(f.call("B", exact)["status"], "downloaded");
    assert_eq!(state_bytes(&f), saved);
    assert_eq!(process(&f)["deliveries"].as_array().unwrap().len(), 1);
}
