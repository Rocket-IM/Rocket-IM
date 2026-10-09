//! 外部字段、固定请求及当前依赖边界；损坏记录只作拒绝证据，不冒充业务迁移。
use super::*;

#[test]
fn list_and_recover_validate_decimal_limits_and_plan_ids_without_creating_state() {
    let (f, _, _, _) = fixture(false, "deleted");
    for limit in ["0", "101", "01", "-1", "18446744073709551616", "x"] {
        reject(
            &f,
            "B",
            json!({"operation":"wire_reclaim_list","limit":limit}),
            "reclaim_invalid",
        );
    }
    for operation in [
        json!({"operation":"wire_reclaim_list","limit":1}),
        json!({"operation":"wire_reclaim_list"}),
        json!({"operation":"wire_reclaim_recover","plan_id":1}),
    ] {
        reject(&f, "B", operation, "invalid_request");
    }
    for id in [String::new(), "space id".into(), "x".repeat(65)] {
        for operation in [
            json!({"operation":"wire_reclaim_list","after_plan_id":id,"limit":"1"}),
            json!({"operation":"wire_reclaim_recover","plan_id":id}),
        ] {
            reject(&f, "B", operation, "reclaim_invalid");
        }
    }
    assert_eq!(
        list(&f, "B", Some(&"x".repeat(64)), "100")["plans"],
        json!([])
    );
    reject(
        &f,
        "B",
        json!({"operation":"wire_reclaim_recover","plan_id":"x".repeat(64)}),
        "reclaim_not_found",
    );
    assert!(load(&f, "B").wire_reclamation.is_none());
}

#[test]
fn malformed_prepared_scope_prefix_selection_and_encoding_reject_every_reopen() {
    let (f, _, _, _) = fixture(false, "deleted");
    prepare(&f, "B", "R1", &["K1"]);
    let original = bytes(&f, "B");
    // 对真实prepare保存的快照逐项构造损坏元数据，再真实加密保存；不把它们当正常操作。
    for kind in [
        "service",
        "conversation",
        "stream",
        "plan",
        "future_p",
        "numeric_p",
        "empty",
        "duplicate",
        "unsorted",
        "overlong",
        "encoding",
        "unknown_version",
        "v1_prepared",
        "missing_request",
    ] {
        fs::write(f.root.join("B").join("state.enc"), &original).unwrap();
        alter_invalid(&f, "B", |state| {
            let ledger = state.wire_reclamation.as_mut().unwrap();
            let prepared = ledger.prepared.get_mut("R1").unwrap();
            let mut request: Value = serde_json::from_str(&prepared.request_json).unwrap();
            match kind {
                "service" => request["service_id"] = json!("S2"),
                "conversation" => request["conversation_id"] = json!("G2"),
                "stream" => request["stream_id"] = json!("other_stream"),
                "plan" => request["plan_id"] = json!("other_plan"),
                "future_p" => request["processed_seq"] = json!("4"),
                "numeric_p" => request["processed_seq"] = json!(3),
                "empty" => request["acceptance_ids"] = json!([]),
                "duplicate" => request["acceptance_ids"] = json!(["K1", "K1"]),
                "unsorted" => request["acceptance_ids"] = json!(["K2", "K1"]),
                "overlong" => request["acceptance_ids"] = json!(["x".repeat(65)]),
                "encoding" => prepared.request_json = "{".into(),
                "unknown_version" => ledger.version = 3,
                "v1_prepared" => ledger.version = 1,
                _ => {
                    request.as_object_mut().unwrap().remove("stream_id");
                }
            }
            if kind != "encoding" {
                ledger.prepared.get_mut("R1").unwrap().request_json =
                    serde_json::to_string(&request).unwrap();
            }
        });
        let damaged = bytes(&f, "B");
        for _ in 0..2 {
            let operation = f.request(
                "B",
                json!({"operation":"wire_reclaim_recover","plan_id":"R1"}),
            );
            assert!(lab::execute(&operation).is_err(), "{kind}");
            assert_eq!(bytes(&f, "B"), damaged, "拒载不能修写坏库：{kind}");
        }
    }
}

#[test]
fn preparation_survives_later_dependency_changes_but_does_not_override_them() {
    for dependency in ["read", "history"] {
        let (f, key, sent, _) = fixture(true, "deleted");
        let receipt = permit(&f, &key, "B", &sent, "R1", "deleted");
        let prepared = prepare(&f, "B", "R1", &["K1"]);
        // 仅注入当前依赖元数据，验证加载与执行的职责分界；未声称是可达的自然历史迁移。
        alter_invalid(&f, "B", |state| {
            if dependency == "read" {
                state
                    .wire_reads
                    .as_mut()
                    .unwrap()
                    .records
                    .get_mut("K1")
                    .unwrap()
                    .confirmation = None;
            } else {
                let incoming = state.wire.inbox.values().next().unwrap();
                state.history_transfers.copies.insert(
                    "synthetic_copy".into(),
                    lab::history_state::ArchivedCopy {
                        copy: lab::history_state::Copy {
                            envelope: incoming.envelope.clone(),
                            acceptance_receipt: incoming.acceptance_receipt.clone().unwrap(),
                            payload: incoming.payload.clone().unwrap(),
                        },
                        source: crate::permission::Identity {
                            account_id: "A".into(),
                            device_id: "A".into(),
                        },
                    },
                );
            }
        });
        assert_eq!(
            load(&f, "B")
                .wire_reclamation
                .as_ref()
                .unwrap()
                .prepared
                .len(),
            1
        );
        assert_eq!(
            recover(&f, "B", "R1")["request_json"],
            prepared["request_json"]
        );
        reject(
            &f,
            "B",
            json!({"operation":"wire_reclaim","receipt":receipt}),
            "reclaim_dependency",
        );
        assert_eq!(load(&f, "B").wire.inbox.len(), 1);
    }
    // 当前终态原本就禁止首次阅读；prepare不会扩大这个原业务边界。
    let (f, _, _, _) = fixture(false, "deleted");
    prepare(&f, "B", "R1", &["K1"]);
    reject(
        &f,
        "B",
        json!({"operation":"wire_read","event_ids":["BE1"]}),
        "read_target_invalid",
    );
}

#[test]
fn prepare_list_and_recover_keep_original_permission_and_consistency_gates() {
    for guard in ["permission_pending", "access_removed", "consistency_paused"] {
        let (f, key, sent, _) = fixture(false, "deleted");
        let receipt = permit(&f, &key, "A", &sent, "R1", "deleted");
        let prepared = prepare(&f, "A", "R1", &["K1"]);
        match guard {
            "permission_pending" => {
                f.call(
                    "A",
                    json!({"operation":"permission_prepare","change_id":"removeC",
                "action":{"kind":"remove_member","account_id":"C"}}),
                );
            }
            "consistency_paused" => {
                f.call("A", json!({"operation":"consistency_challenge"}));
            }
            // 撤权元数据负例；其余两项由实际公开入口进入未决状态。
            _ => alter_invalid(&f, "A", |state| {
                state.permissions.recovery.access_removed = true
            }),
        }
        let state = load(&f, "A");
        assert_eq!(
            state.wire_reclamation.as_ref().unwrap().prepared["R1"].request_json,
            prepared["request_json"].as_str().unwrap()
        );
        for operation in [
            json!({"operation":"wire_reclaim_list","limit":"100"}),
            json!({"operation":"wire_reclaim_recover","plan_id":"R1"}),
            json!({"operation":"wire_reclaim_request","plan_id":"R1","acceptance_ids":["K1"]}),
            json!({"operation":"wire_reclaim","receipt":receipt}),
        ] {
            reject(&f, "A", operation, guard);
        }
    }
}
