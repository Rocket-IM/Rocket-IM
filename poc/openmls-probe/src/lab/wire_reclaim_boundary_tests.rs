//! 无部分删除、证明损坏拒载与签名缺口；不以坏快照作为回收成功证据。
use super::super::{wire_reclaim, wire_reclaim_validate, wire_sync_types::Availability};
use super::*;

#[test]
fn invalid_second_selection_is_atomic_and_unrelated_pending_send_survives() {
    let (f, key, sent, _) = fixture(false, "deleted");
    let proof = permit(&f, &key, "A", &sent, "R1", "deleted");
    let bad = re_sign(&key, &proof, |s| {
        let mut second = s["messages"][0].clone();
        second["acceptance_id"] = json!("K2");
        s["messages"].as_array_mut().unwrap().push(second);
    });
    reject(
        &f,
        "A",
        json!({"operation":"wire_reclaim","receipt":bad}),
        "reclaim_target_invalid",
    );
    let next = f.send("A", "M2");
    f.call("A", json!({"operation":"wire_reclaim","receipt":proof}));
    assert_eq!(f.send("A", "M2")["envelope"], next["envelope"]);
    assert_eq!(load(&f, "A").wire.outbox.len(), 1);
}

#[test]
fn selected_unsettled_local_dependencies_cannot_be_reclaimed() {
    let (f, _, _, _) = fixture(true, "deleted");
    for kind in [
        "pending_read",
        "available",
        "waiting",
        "quarantine",
        "no_delivery",
    ] {
        let mut state = load(&f, "B");
        let expected = match kind {
            "pending_read" => {
                state
                    .wire_reads
                    .as_mut()
                    .unwrap()
                    .records
                    .get_mut("K1")
                    .unwrap()
                    .confirmation = None;
                "reclaim_dependency"
            }
            "available" => {
                state.wire_sync.slots.get_mut(&1).unwrap().slot.availability =
                    Availability::Available;
                "reclaim_target_invalid"
            }
            "waiting" => {
                state.wire_sync.slots.get_mut(&1).unwrap().waiting = true;
                "reclaim_dependency"
            }
            "quarantine" => {
                state.wire_sync.slots.get_mut(&1).unwrap().result =
                    Some(json!({"status":"quarantined"}));
                "reclaim_dependency"
            }
            _ => {
                state.wire_sync.slots.remove(&2);
                "reclaim_dependency"
            }
        };
        let before = serde_json::to_vec(&state).unwrap();
        assert_eq!(
            wire_reclaim::request(&mut state, "R1".into(), vec!["K1".into()])
                .unwrap_err()
                .code,
            expected
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }
}

#[test]
fn compact_records_cannot_lose_plan_slot_or_original_binding() {
    let (f, key, sent, _) = fixture(true, "deleted");
    f.call(
        "B",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"B",&sent,"R1","deleted")}),
    );
    for kind in [
        "version",
        "plan",
        "message_slot",
        "delivery",
        "binding",
        "plaintext_slot",
    ] {
        let mut state = load(&f, "B");
        let compact = state.wire_reclamation.as_mut().unwrap();
        match kind {
            "version" => compact.version=2,
            "plan" => compact.plans.clear(),
            "message_slot" => { compact.slots.remove(&1); },
            "delivery" => { compact.slots.remove(&2); },
            "binding" => compact.messages.values_mut().next().unwrap().envelope_sha256="00".repeat(32),
            _ => state.wire_sync.slots.get_mut(&1).unwrap().slot.event=Some(serde_json::from_value(json!({"type":"message","acceptance_id":"K1","envelope":sent["envelope"],"acceptance_receipt":accept(&sent,&key,"K1")["acceptance_receipt"]})).unwrap()),
        }
        assert!(wire_reclaim_validate::validate(&state).is_err(), "{kind}");
    }
}

#[test]
fn signed_retention_gap_verifies_source_scope_and_request_without_advancing_cursors() {
    let (f, key, _, _) = fixture(false, "deleted");
    let body = json!({"protocol_version":"rim-stream-retention-1","service_id":"S1","account_id":"B","device_id":"B",
        "stream_id":"B_stream","after_seq":"1","limit":"100","floor":"3","watermark":"3"});
    let op =
        |proof| json!({"operation":"wire_retention","receipt":proof,"after_seq":"1","limit":"100"});
    let before = fs::read(f.root.join("B/state.enc")).unwrap();
    let result = f.call(
        "B",
        op(sign(
            &key,
            crate::message_reclamation::RETENTION_DOMAIN,
            body.clone(),
        )),
    );
    assert_eq!(result["status"], "recovery_required");
    assert_eq!(result["sync"]["processed_cursor"], "3");
    assert_eq!(fs::read(f.root.join("B/state.enc")).unwrap(), before);
    for field in [
        "service_id",
        "account_id",
        "device_id",
        "stream_id",
        "after_seq",
        "limit",
    ] {
        let mut bad = body.clone();
        bad[field] = json!(if field == "after_seq" {
            "0"
        } else if field == "limit" {
            "99"
        } else {
            "other"
        });
        reject(
            &f,
            "B",
            op(sign(
                &key,
                crate::message_reclamation::RETENTION_DOMAIN,
                bad,
            )),
            "retention_conflict",
        );
    }
    reject(
        &f,
        "B",
        op(sign(
            &SigningKey::from_bytes(&[1; 32]),
            crate::message_reclamation::RETENTION_DOMAIN,
            body,
        )),
        "retention_signature",
    );
}

#[test]
fn new_slot_cannot_restore_reclaimed_ciphertext_or_reuse_acceptance_identity() {
    let (f, key, sent, _) = fixture(false, "deleted");
    for device in ["A", "B"] {
        f.call(device,json!({"operation":"wire_reclaim","receipt":permit(&f,&key,device,&sent,"R1","deleted")}));
    }
    let duplicate = event(
        "B",
        4,
        json!({"type":"message","acceptance_id":"K1","envelope":sent["envelope"],"acceptance_receipt":accept(&sent,&key,"K1")["acceptance_receipt"]}),
    );
    reject(
        &f,
        "B",
        download_operation(&key, "B", vec![duplicate], 3, 4),
        "payload_reclaimed",
    );
    let next = f.send("A", "M2");
    reject(&f, "A", accept(&next, &key, "K1"), "acceptance_conflict");
    let collision = event(
        "B",
        4,
        json!({"type":"message","acceptance_id":"K1","envelope":next["envelope"],"acceptance_receipt":accept(&next,&key,"K1")["acceptance_receipt"]}),
    );
    // 新逻辑的同接受ID也不能重新存储载荷。
    reject(
        &f,
        "B",
        download_operation(&key, "B", vec![collision], 3, 4),
        "payload_reclaimed",
    );
}

#[test]
fn direct_receive_cannot_reuse_reclaimed_send_or_inbox_acceptance_id() {
    let (f, key, sent, _) = fixture(false, "deleted");
    for device in ["A", "B"] {
        f.call(device,json!({"operation":"wire_reclaim","receipt":permit(&f,&key,device,&sent,"R1","deleted")}));
    }
    let next = f.send("C", "M2");
    let operation = |id: &str| {
        json!({"operation":"wire_receive",
        "header_bytes":next["envelope"]["header_bytes"],"payload_bytes":next["envelope"]["payload_bytes"],
        "acceptance_id":id,"acceptance_receipt":accept(&next,&key,id)["acceptance_receipt"]})
    };
    for device in ["A", "B"] {
        reject(&f, device, operation("K1"), "acceptance_conflict");
        let mut state = load(&f, device);
        let before = serde_json::to_vec(&state).unwrap();
        assert_eq!(
            super::super::wire_receive::receive(
                &mut state,
                serde_json::from_value(next["envelope"].clone()).unwrap(),
                Some("K1".into()),
                Some(
                    serde_json::from_value(operation("K1")["acceptance_receipt"].clone()).unwrap()
                )
            )
            .unwrap_err()
            .code,
            "acceptance_conflict"
        );
        state.capture_provider().unwrap();
        assert!(serde_json::to_vec(&state).unwrap() == before);
        assert_eq!(f.call(device, operation("K2"))["duplicate"], false);
    }
    assert_eq!(f.call("A", accept(&sent, &key, "K1"))["duplicate"], true);
    let original = json!({"operation":"wire_receive","header_bytes":sent["envelope"]["header_bytes"],
        "payload_bytes":sent["envelope"]["payload_bytes"],"acceptance_id":"K1",
        "acceptance_receipt":accept(&sent,&key,"K1")["acceptance_receipt"]});
    assert_eq!(f.call("B", original)["payload_reclaimed"], true);
}

#[test]
fn reclaim_with_other_pending_send_preflights_gate_without_restoring_provider() {
    let (f, key, sent, payload) = fixture(false, "deleted");
    f.send("A", "M2");
    f.call(
        "A",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"A",&sent,"R1","deleted")}),
    );
    let saved = load(&f, "A");
    // serde只重建元数据，provider的内存存储保持为空；与metadata_committed相同恢复边界。
    let metadata: super::super::state::DeviceState =
        serde_json::from_slice(&serde_json::to_vec(&saved).unwrap()).unwrap();
    assert_eq!(metadata.group().err().unwrap().code, "missing_group");
    let before = serde_json::to_vec(&metadata).unwrap();
    for (logical, body, expected) in [
        ("M3", "synthetic test content", Some("send_order_pending")),
        ("M2", "synthetic test content", None),
        ("M1", payload.as_str(), None),
    ] {
        let operation=serde_json::from_value(json!({"operation":"wire_send","logical_message_id":logical,"attempt_id":"P1","payload":body})).unwrap();
        let result = super::super::wire_send_order::preflight_send(&metadata, &operation);
        assert_eq!(result.err().map(|e| e.code), expected);
        assert_eq!(serde_json::to_vec(&metadata).unwrap(), before);
        assert_eq!(metadata.group().err().unwrap().code, "missing_group");
    }
}
