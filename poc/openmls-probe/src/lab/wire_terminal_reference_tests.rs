//! 引用仅补已验签终态槽的公开身份；不能恢复正文、改变绑定或越过来源检查。
use super::{
    refresh::{receipt, terminal},
    *,
};

#[test]
fn terminal_reference_source_shape_and_availability_are_checked_before_mutation() {
    let (f, key, _, _) = fixture(false, "deleted");
    for kind in [
        "available",
        "access_removed",
        "message",
        "with_event",
        "null",
        "unknown",
    ] {
        let mut slot = terminal(Some(receipt("delivery")));
        let expected = match kind {
            "available" | "access_removed" => {
                slot["availability"] = json!(kind);
                "terminal_reference_invalid"
            }
            "message" => {
                slot["terminal_reference"] = json!({"type":"crypto_control", "control":{
                    "control_id":"C1","from_state_ref":"0".repeat(64),"to_state_ref":"1".repeat(64),"payload_bytes":"AA=="}});
                "terminal_reference_invalid"
            }
            "with_event" => {
                slot["event"] = receipt("delivery");
                "terminal_reference_invalid"
            }
            "null" => {
                slot["terminal_reference"] = Value::Null;
                "stream_page_invalid"
            }
            _ => {
                slot["terminal_reference"]["unexpected"] = json!(true);
                "stream_page_invalid"
            }
        };
        reject(
            &f,
            "A",
            download_operation(&key, "A", vec![slot], 0, 1),
            expected,
        );
    }
    reject(
        &f,
        "A",
        json!({"operation":"wire_download","stream_id":"A_stream",
        "events":[terminal(Some(receipt("delivery")))],"next_after_seq":"1","watermark":"1","has_more":false}),
        "stream_source_required",
    );
    let mut metadata = load(&f, "A");
    // 直接调用原无签名下载入口也必须拒绝，不能依赖外层已固定Service钥才有效。
    let slot = serde_json::from_value(terminal(Some(receipt("delivery")))).unwrap();
    assert_eq!(
        lab::wire_sync::download(
            &mut metadata,
            "A_stream".into(),
            vec![slot],
            "1".into(),
            "1".into(),
            false
        )
        .unwrap_err()
        .code,
        "stream_source_required"
    );
}

#[test]
fn terminal_reference_overlap_preserves_reference_and_rejects_rebinding() {
    let (f, key, _, _) = fixture(false, "deleted");
    download(
        &f,
        &key,
        "A",
        vec![terminal(Some(receipt("delivery")))],
        0,
        1,
    );
    download(&f, &key, "A", vec![terminal(None)], 0, 1);
    assert!(load(&f, "A").wire_sync.slots[&1]
        .slot
        .terminal_reference
        .is_some());
    for field in [
        "acceptance_id",
        "attempt_id",
        "device",
        "type",
        "event_id",
        "availability",
    ] {
        let mut slot = terminal(Some(receipt("delivery")));
        match field {
            "event_id" => slot[field] = json!("other-event"),
            "availability" => slot[field] = json!("expired"),
            "device" => {
                slot["terminal_reference"][field] = json!({"account_id":"C","device_id":"C"})
            }
            "type" => slot["terminal_reference"][field] = json!("read"),
            _ => slot["terminal_reference"][field] = json!("other"),
        }
        reject(
            &f,
            "A",
            download_operation(&key, "A", vec![slot], 0, 1),
            "terminal_reference_conflict",
        );
    }
}

#[test]
fn terminal_reference_preserves_original_event_and_compaction_counts_reference_slots() {
    let (f, key, sent, _) = fixture(false, "deleted");
    download(
        &f,
        &key,
        "A",
        vec![event("A", 1, receipt("delivery"))],
        0,
        1,
    );
    download(
        &f,
        &key,
        "A",
        vec![terminal(Some(receipt("delivery")))],
        0,
        1,
    );
    let state = load(&f, "A");
    assert!(state.wire_sync.slots[&1].slot.event.is_some());
    assert!(state.wire_sync.slots[&1].slot.terminal_reference.is_some());
    assert_eq!(
        state.wire_sync.slots[&1].result.as_ref().unwrap()["status"],
        "receipt_recorded"
    );
    lab::wire_terminal_reference::stored(&state).unwrap();
    let mut wrong = load(&f, "A");
    wrong
        .wire_sync
        .slots
        .get_mut(&1)
        .unwrap()
        .slot
        .terminal_reference = Some(serde_json::from_value(receipt("read")).unwrap());
    assert_eq!(
        lab::wire_terminal_reference::stored(&wrong)
            .unwrap_err()
            .code,
        "terminal_reference_invalid"
    );
    f.call(
        "A",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"A",&sent,"R1","deleted")}),
    );
    assert_eq!(load(&f, "A").wire_reclamation.unwrap().slots.len(), 1);

    let (f, key, sent, _) = fixture(false, "deleted");
    download(
        &f,
        &key,
        "A",
        vec![terminal(Some(receipt("delivery")))],
        0,
        1,
    );
    f.call(
        "A",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"A",&sent,"R1","deleted")}),
    );
    let state = load(&f, "A");
    assert_eq!(state.wire_reclamation.unwrap().slots.len(), 1);
    assert_eq!(
        f.call("A", json!({"operation":"wire_inspect"}))["sync"]["active_slot_count"],
        0
    );
}

#[test]
fn terminal_reference_new_errors_are_detected_by_metadata_preflight_without_provider() {
    let (f, key, _, _) = fixture(false, "deleted");
    download(
        &f,
        &key,
        "A",
        vec![terminal(Some(receipt("delivery")))],
        0,
        1,
    );
    let state = load(&f, "A");
    let metadata: lab::state::DeviceState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(metadata.group().is_err());
    let mut changed = terminal(Some(receipt("read")));
    for shape in ["conflict", "invalid"] {
        if shape == "invalid" {
            changed["availability"] = json!("available");
        }
        let operation: lab::Operation =
            serde_json::from_value(download_operation(&key, "A", vec![changed.clone()], 0, 1))
                .unwrap();
        assert!(lab::wire_stream_source::preflight(&metadata, &operation).is_err());
        assert!(metadata.group().is_err());
    }
}

#[test]
fn terminal_delivery_reference_satisfies_existing_incoming_dependency_without_restoring_body() {
    let (f, key) = lab::wire_send_order_test_support::setup();
    let sent = f.send("A", "M1");
    let acceptance = accept(&sent, &key, "K1");
    f.call("A", acceptance.clone());
    download(
        &f,
        &key,
        "B",
        vec![event(
            "B",
            1,
            json!({"type":"message",
        "acceptance_id":"K1","envelope":sent["envelope"],
        "acceptance_receipt":acceptance["acceptance_receipt"]}),
        )],
        0,
        1,
    );
    let mut hidden = event("B", 2, receipt("delivery"));
    hidden["availability"] = json!("deleted");
    hidden.as_object_mut().unwrap().remove("event");
    let lifecycle = event(
        "B",
        3,
        json!({"type":"message_availability",
        "target_event_seq":"1","target_event_id":"BE1","acceptance_id":"K1",
        "attempt_id":"P1","availability":"deleted"}),
    );
    download(&f, &key, "B", vec![hidden.clone(), lifecycle.clone()], 1, 3);
    reject(
        &f,
        "B",
        json!({"operation":"wire_reclaim_request","plan_id":"R1",
        "acceptance_ids":["K1"]}),
        "reclaim_dependency",
    );
    hidden["terminal_reference"] = receipt("delivery");
    download(&f, &key, "B", vec![hidden, lifecycle], 1, 3);
    let state = load(&f, "B");
    assert!(state.wire_sync.slots[&2].slot.event.is_none());
    assert_eq!(
        state.wire_sync.slots[&2].result.as_ref().unwrap()["status"],
        "unavailable"
    );
    for missing in ["body", "processed_message"] {
        let mut invalid = load(&f, "B");
        if missing == "body" {
            invalid.wire.inbox.values_mut().next().unwrap().payload = None;
        } else {
            invalid.wire_sync.slots.get_mut(&1).unwrap().result =
                Some(json!({"status":"unavailable"}));
        }
        assert!(lab::wire_reclaim::candidate(&invalid, "K1", "R1", None).is_err());
    }
    assert_eq!(prepare(&f, "B", "R1", &["K1"])["status"], "prepared");
    f.call(
        "B",
        json!({"operation":"wire_reclaim",
        "receipt":permit(&f,&key,"B",&sent,"R1","deleted")}),
    );
    let state = load(&f, "B");
    assert!(state.wire.inbox.is_empty());
    assert_eq!(state.wire_reclamation.unwrap().slots.len(), 3);
    assert_eq!(recover(&f, "B", "R1")["status"], "applied");
}
