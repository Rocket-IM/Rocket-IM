//! 合成损坏状态只用于负例；任何拒绝都核对原快照与设备钥保持不变。
use super::*;

#[test]
fn read_batch_rejects_unprocessed_unknown_receipt_quarantined_and_foreign_recipient_atomically() {
    let (f, key) = setup();
    let good = message(&f, &key, 1);
    download(&f, &key, vec![good], 0, 1);
    reject(
        &f,
        "B",
        json!({"operation":"wire_read","event_ids":["E1"]}),
        "read_target_invalid",
    );
    process(&f);
    let sent = f.send("A", "corrupt");
    let mut bad = sent["envelope"].clone();
    let mut bytes = codec::decode(bad["payload_bytes"].as_str().unwrap()).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    bad["payload_bytes"] = json!(codec::encode(&bytes));
    let bad = message_envelope(&key, &bad, 3, "bad");
    let foreign = f.send("B", "self");
    let foreign = message_envelope(&key, &foreign["envelope"], 4, "foreign");
    download(
        &f,
        &key,
        vec![receipt(2, "delivery", "K001", "P1", "B", "B"), bad, foreign],
        1,
        4,
    );
    process(&f);
    for (id, code) in [
        ("missing", "read_target_not_found"),
        ("E2", "read_target_invalid"),
        ("E3", "read_target_invalid"),
        ("E4", "read_target_invalid"),
    ] {
        reject(
            &f,
            "B",
            json!({"operation":"wire_read","event_ids":["E1",id]}),
            code,
        );
        assert_eq!(inspect(&f)["pending_count"], 0);
    }
    assert_eq!(mark(&f, &["E1"])["marked_count"], 1);
}

#[test]
fn read_requires_ordinary_signed_message_slot_not_direct_receive_or_untrusted_queue() {
    let f = Fixture::new();
    let sent = f.send("A", "M1");
    f.receive("B", &sent["envelope"]);
    reject(
        &f,
        "B",
        json!({"operation":"wire_read","event_ids":["E1"]}),
        "read_source_required",
    );
    let (f, key) = setup();
    let sent = f.send("A", "M1");
    f.receive("B", &sent["envelope"]);
    download(&f, &key, vec![], 0, 0);
    reject(
        &f,
        "B",
        json!({"operation":"wire_read","event_ids":["E1"]}),
        "read_target_not_found",
    );
    assert_eq!(inspect(&f)["confirmed_count"], 0);
}

#[test]
fn read_batch_bounds_duplicate_ids_and_naked_confirmation_fields_are_rejected() {
    let (f, key) = setup();
    let first = message(&f, &key, 1);
    download(&f, &key, vec![first], 0, 1);
    process(&f);
    for ids in [
        vec![],
        vec!["E1".to_owned(), "E1".to_owned()],
        (0..101).map(|i| format!("E{i}")).collect(),
        vec!["bad space".into()],
    ] {
        reject(
            &f,
            "B",
            json!({"operation":"wire_read","event_ids":ids}),
            "read_invalid",
        );
    }
    reject(
        &f,
        "B",
        json!({"operation":"wire_read","event_ids":["E1"],"read":true}),
        "invalid_request",
    );
    assert_eq!(mark(&f, &["E1"])["marked_count"], 1);
    download(
        &f,
        &key,
        vec![
            json!({"stream_id":"B_stream","event_seq":"2","event_id":"E2","availability":"expired"}),
        ],
        1,
        2,
    );
    assert_eq!(process(&f)["read_confirmed_count"], 0);
}

#[test]
fn read_scope_source_inbox_and_confirmation_damage_fail_on_load() {
    for defect in [
        "scope",
        "source",
        "pin",
        "message",
        "inbox",
        "attempt",
        "confirm_device",
        "confirm_seq",
        "empty",
    ] {
        let (f, key) = setup();
        let first = message(&f, &key, 1);
        download(&f, &key, vec![first], 0, 1);
        process(&f);
        mark(&f, &["E1"]);
        download(
            &f,
            &key,
            vec![receipt(2, "read", "K001", "P1", "B", "B")],
            1,
            2,
        );
        process(&f);
        alter_invalid(&f, "B", |state| match defect {
            "scope" => {
                state
                    .wire_reads
                    .as_mut()
                    .unwrap()
                    .records
                    .values_mut()
                    .next()
                    .unwrap()
                    .target
                    .account_id = "foreign".into();
            }
            "source" => state.wire_sync.source_verified = false,
            "pin" => state.permissions.recovery.relay_receipt_key = None,
            "message" => {
                state.wire_sync.slots.remove(&1);
            }
            "inbox" => {
                state.wire.inbox.values_mut().next().unwrap().payload =
                    Some("changed synthetic content".into())
            }
            "attempt" => {
                state
                    .wire_reads
                    .as_mut()
                    .unwrap()
                    .records
                    .values_mut()
                    .next()
                    .unwrap()
                    .target
                    .attempt_id = "wrong".into()
            }
            "confirm_device" => {
                if let Some(super::super::wire_sync_types::Event::Read { device, .. }) =
                    &mut state.wire_sync.slots.get_mut(&2).unwrap().slot.event
                {
                    device.device_id = "C".into();
                }
            }
            "confirm_seq" => {
                state
                    .wire_reads
                    .as_mut()
                    .unwrap()
                    .records
                    .values_mut()
                    .next()
                    .unwrap()
                    .confirmation
                    .as_mut()
                    .unwrap()
                    .event_seq = "1".into()
            }
            _ => state.wire_reads.as_mut().unwrap().records.clear(),
        });
        reject(
            &f,
            "B",
            json!({"operation":"wire_read_inspect"}),
            "read_state",
        );
    }
}

#[test]
fn read_mutating_permission_consistency_and_halted_guards_keep_readonly_diagnostics() {
    for guard in ["pending", "removed", "consistency", "halted"] {
        let (f, key) = setup();
        let first = message(&f, &key, 1);
        download(&f, &key, vec![first], 0, 1);
        process(&f);
        mark(&f, &["E1"]);
        if guard == "consistency" {
            f.call("B", json!({"operation":"consistency_challenge"}));
        } else {
            alter_invalid(&f, "B", |state| match guard {
                "pending" => {
                    state.permissions.recovery.intent = Some(super::super::recovery_state::Intent {
                        origin_change_id: "synthetic_intent".into(),
                        action: crate::permission::Action::RemoveMember {
                            account_id: "C".into(),
                        },
                        minimum_version: "1".into(),
                        minimum_state_ref: state
                            .permissions
                            .checkpoint
                            .as_ref()
                            .unwrap()
                            .crypto_state_ref
                            .clone(),
                        satisfied: false,
                    })
                }
                "removed" => state.permissions.recovery.access_removed = true,
                _ => state.wire_sync.halted = true,
            });
        }
        reject(
            &f,
            "B",
            json!({"operation":"wire_read","event_ids":["E1"]}),
            match guard {
                "pending" => "permission_pending",
                "removed" => "access_removed",
                "consistency" => "consistency_paused",
                _ => "stream_conflict",
            },
        );
        assert_eq!(inspect(&f)["pending_count"], 1);
        assert_eq!(pending(&f)["request"]["acceptance_ids"], json!(["K001"]));
    }
}
