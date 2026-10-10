//! 本机只用精确相关签页事实刷新被证明不可能接受的旧P；真实Relay时序另验。
use super::*;

pub(super) fn receipt(kind: &str) -> Value {
    json!({"type":kind,"acceptance_id":"K1","attempt_id":"P1",
        "device":{"account_id":"B","device_id":"B"}})
}

pub(super) fn terminal(reference: Option<Value>) -> Value {
    let mut slot = event("A", 1, receipt("delivery"));
    slot["availability"] = json!("deleted");
    slot.as_object_mut().unwrap().remove("event");
    if let Some(reference) = reference {
        slot["terminal_reference"] = reference;
    }
    slot
}

#[test]
fn reclaim_refresh_old_terminal_placeholder_needs_signed_bound_reference() {
    let (f, key, sent, _) = fixture(false, "deleted");
    let old_permit = permit(&f, &key, "A", &sent, "R1", "deleted");
    let original = prepare(&f, "A", "R1", &["K1"]);
    download(&f, &key, "A", vec![terminal(None)], 0, 1);
    assert_eq!(
        prepare(&f, "A", "R1", &["K1"])["request_json"],
        original["request_json"]
    );
    // 同event_id/seq的签名重叠页只补公开身份；处理结果仍是unavailable。
    download(
        &f,
        &key,
        "A",
        vec![terminal(Some(receipt("delivery")))],
        0,
        1,
    );
    let before_provider = load(&f, "A").provider_entries;
    let refreshed = prepare(&f, "A", "R1", &["K1"]);
    assert_eq!(refreshed["reprepared"], true);
    assert_eq!(refreshed["duplicate"], false);
    assert_eq!(refreshed["previous_processed_seq"], "0");
    assert_eq!(refreshed["request"]["processed_seq"], "1");
    assert_eq!(
        refreshed["previous_request_sha256"],
        codec::digest_hex(&codec::digest(
            original["request_json"].as_str().unwrap().as_bytes()
        ))
    );
    assert_eq!(
        recover(&f, "A", "R1")["request_json"],
        refreshed["request_json"]
    );
    let state = load(&f, "A");
    assert_eq!(state.provider_entries, before_provider);
    assert!(state.wire_sync.slots[&1].slot.event.is_none());
    assert_eq!(
        state.wire_sync.slots[&1].result.as_ref().unwrap()["status"],
        "unavailable"
    );
    reject(
        &f,
        "A",
        json!({"operation":"wire_reclaim","receipt":old_permit}),
        "reclaim_conflict",
    );
    let current = permit(&f, &key, "A", &sent, "R1", "deleted");
    f.call("A", json!({"operation":"wire_reclaim","receipt":current}));
    assert_eq!(
        prepare(&f, "A", "R1", &["K1"])["request_json"],
        refreshed["request_json"]
    );
}

#[test]
fn reclaim_refresh_late_read_updates_once_and_recovery_does_not_refresh() {
    let (f, key, _, _) = fixture(false, "deleted");
    download(
        &f,
        &key,
        "A",
        vec![event("A", 1, receipt("delivery"))],
        0,
        1,
    );
    let original = prepare(&f, "A", "R1", &["K1"]);
    download(&f, &key, "A", vec![event("A", 2, receipt("read"))], 1, 2);
    let snapshot = bytes(&f, "A");
    assert_eq!(
        recover(&f, "A", "R1")["request_json"],
        original["request_json"]
    );
    assert_eq!(bytes(&f, "A"), snapshot);
    let refreshed = prepare(&f, "A", "R1", &["K1"]);
    assert_eq!(refreshed["reprepared"], true);
    assert_eq!(refreshed["previous_processed_seq"], "1");
    assert_eq!(refreshed["request"]["processed_seq"], "2");
    let saved = bytes(&f, "A");
    let duplicate = prepare(&f, "A", "R1", &["K1"]);
    assert_eq!(duplicate["duplicate"], true);
    assert!(duplicate.get("reprepared").is_none());
    assert_eq!(bytes(&f, "A"), saved);
}

#[test]
fn reclaim_refresh_unrelated_wrong_attempt_or_recipient_keeps_original_bytes() {
    for field in ["acceptance_id", "attempt_id", "device"] {
        let (f, key, _, _) = fixture(false, "deleted");
        let original = prepare(&f, "A", "R1", &["K1"]);
        let mut body = receipt("read");
        body[field] = if field == "device" {
            json!({"account_id":"X","device_id":"X"})
        } else {
            json!("unrelated")
        };
        download(&f, &key, "A", vec![event("A", 1, body)], 0, 1);
        let saved = bytes(&f, "A");
        assert_eq!(
            prepare(&f, "A", "R1", &["K1"])["request_json"],
            original["request_json"]
        );
        assert_eq!(bytes(&f, "A"), saved);
    }
}

#[test]
fn reclaim_refresh_unprocessed_unverified_waiting_and_quarantined_are_not_evidence() {
    let (f, key, _, _) = fixture(false, "deleted");
    let original = prepare(&f, "A", "R1", &["K1"]);
    f.call(
        "A",
        download_operation(&key, "A", vec![event("A", 1, receipt("delivery"))], 0, 1),
    );
    assert_eq!(
        prepare(&f, "A", "R1", &["K1"])["request_json"],
        original["request_json"]
    );
    f.call("A", json!({"operation":"wire_process"}));
    let request =
        lab::wire_reclaim_preparation::Confirm::parse(original["request_json"].as_str().unwrap())
            .unwrap();
    for condition in ["unverified", "waiting", "quarantined"] {
        let mut state = load(&f, "A");
        match condition {
            "unverified" => state.wire_sync.source_verified = false,
            "waiting" => state.wire_sync.slots.get_mut(&1).unwrap().waiting = true,
            _ => {
                state.wire_sync.slots.get_mut(&1).unwrap().result =
                    Some(json!({"status":"quarantined"}))
            }
        }
        assert!(lab::wire_reclaim_refresh::evidence(&state, &request)
            .unwrap()
            .is_none());
    }
}

#[test]
fn reclaim_refresh_revalidates_all_selected_dependencies_before_changing_request() {
    let (f, key, _, _) = fixture(false, "deleted");
    let next = f.send("A", "M2");
    f.call("A", accept(&next, &key, "K2"));
    prepare(&f, "A", "R1", &["K1", "K2"]);
    download(&f, &key, "A", vec![event("A", 1, receipt("read"))], 0, 1);
    let mut state = load(&f, "A");
    // 内存损坏负例：证明只关联K1，不能因此跳过同选择K2的完整候选验证。
    state.wire.outbox.retain(|_, record| {
        record.acceptance_receipt.as_ref().is_none_or(|receipt| {
            crate::message_acceptance::verify(
                &codec::encode(key.verifying_key().as_bytes()),
                receipt,
            )
            .unwrap()
            .acceptance_id
                != "K2"
        })
    });
    let before = serde_json::to_vec(&state).unwrap();
    assert!(
        lab::wire_reclaim::request(&mut state, "R1".into(), vec!["K1".into(), "K2".into()])
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}
