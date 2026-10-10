//! 接受事实附在原发送尝试上；迁移只复制正文，不恢复发送状态。
use super::*;

fn ack(f: &Fixture, device: &str, message: &str, attempt: &str, receipt: &SignedRecord) -> Value {
    call(f, device, ack_op(message, attempt, receipt))
}
fn ack_op(message: &str, attempt: &str, receipt: &SignedRecord) -> Value {
    json!({"operation":"wire_accept","logical_message_id":message,"attempt_id":attempt,"acceptance_receipt":receipt})
}
fn send_attempt(
    f: &Fixture,
    device: &str,
    id: &str,
    attempt: &str,
    replaces: Option<&str>,
) -> Value {
    let mut op = json!({"operation":"wire_send","logical_message_id":id,"attempt_id":attempt,"payload":"synthetic device test"});
    if let Some(old) = replaces {
        op["replaces_attempt_id"] = json!(old);
        op["closure_id"] = json!(format!("closed{old}"));
    }
    op["operation"] = json!("wire_send");
    call(f, device, op)["envelope"].clone()
}
// 仅构造历史多原件快照：暂存旧 outbox，以当前密码状态生成真实新密文后合回旧格式。
// 不回退 provider，不进入公开实现；真实旧程序兼容由 HTTP 联合场景另行验证。
fn legacy_send_attempt(
    f: &Fixture,
    device: &str,
    id: &str,
    attempt: &str,
    replaces: Option<&str>,
) -> Value {
    let mut old_outbox = Default::default();
    let mut old_tails = Default::default();
    mutate(f, device, |state| {
        assert!(state.wire_send_order.is_none());
        old_outbox = std::mem::take(&mut state.wire.outbox);
        old_tails = std::mem::take(&mut state.wire.tails);
    });
    let envelope = send_attempt(f, device, id, attempt, None);
    mutate(f, device, |state| {
        let record = state.wire.outbox.values_mut().next().unwrap();
        record.replaces_attempt_id = replaces.map(str::to_owned);
        record.closure_id = replaces.map(|old| format!("closed{old}"));
        old_outbox.append(&mut state.wire.outbox);
        old_tails.append(&mut state.wire.tails);
        state.wire.outbox = old_outbox;
        state.wire.tails = old_tails;
        state.wire_send_order = None;
    });
    envelope
}
fn assert_only_acceptance_changed(mut before: Value, mut after: Value) {
    for value in [&mut before, &mut after] {
        for record in value["wire"]["outbox"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            record.as_object_mut().unwrap().remove("acceptance_receipt");
        }
    }
    assert_eq!(before, after);
}

#[test]
fn past_acceptance_is_persisted_without_reencrypting_and_sent_copy_uses_existing_migration() {
    let (f, key) = setup();
    let envelope = send_attempt(&f, "B", "sentBeforeJoin", "P1", None);
    let receipt = acceptance(&key, &envelope, "sentK");
    let b2 = init(&f, &key, "B2");
    let prepared = prepare(&f, "B", &b2, "addB2");
    accept(&f, &key, &prepared, &["A", "B", "C"]);
    join(&f, &key, "B2", &prepared);
    let before = future_state(&f, "B");
    assert_eq!(
        ack(&f, "B", "sentBeforeJoin", "P1", &receipt)["duplicate"],
        false
    );
    assert_eq!(
        ack(&f, "B", "sentBeforeJoin", "P1", &receipt)["duplicate"],
        true
    );
    assert_only_acceptance_changed(before, future_state(&f, "B"));
    assert_eq!(
        send_attempt(&f, "B", "sentBeforeJoin", "P1", None),
        envelope
    );
    assert_eq!(
        call(&f, "B", json!({"operation":"wire_inspect"}))["accepted_outbox_count"],
        1
    );
    let request = begin(&f, "sentT", select(&f, &["sentK"]));
    let package = export(&f, &request);
    let before = future_state(&f, "B2");
    assert_eq!(
        call(&f, "B2", import_op(&key, &request, &package))["imported_count"],
        1
    );
    assert_eq!(future_state(&f, "B2"), before);
}

#[test]
fn late_accepted_attempt_blocks_other_cached_and_new_attempts_and_preserves_first_fact() {
    let (f, key) = fixture();
    let first = legacy_send_attempt(&f, "B", "late", "P1", None);
    let second = legacy_send_attempt(&f, "B", "late", "P2", Some("P1"));
    let before = future_state(&f, "B");
    let receipt = acceptance(&key, &first, "lateK");
    ack(&f, "B", "late", "P1", &receipt);
    assert_only_acceptance_changed(before, future_state(&f, "B"));
    for (attempt, replaces) in [("P2", "P1"), ("P3", "P2")] {
        fail(
            &f,
            "B",
            json!({"operation":"wire_send","logical_message_id":"late","attempt_id":attempt,"payload":"synthetic device test","replaces_attempt_id":replaces,"closure_id":format!("closed{replaces}")}),
            "acceptance_conflict",
        );
    }
    assert_eq!(send_attempt(&f, "B", "late", "P1", None), first);
    fail(
        &f,
        "B",
        ack_op("late", "P2", &acceptance(&key, &second, "otherK")),
        "acceptance_conflict",
    );
    fail(
        &f,
        "B",
        ack_op("late", "P1", &acceptance(&key, &first, "newK")),
        "acceptance_conflict",
    );
    let other = legacy_send_attempt(&f, "B", "another", "P1", None);
    fail(
        &f,
        "B",
        ack_op("another", "P1", &acceptance(&key, &other, "lateK")),
        "acceptance_conflict",
    );
    fail(
        &f,
        "B",
        ack_op("another", "P1", &acceptance(&key, &other, "old1")),
        "acceptance_conflict",
    );
    fail(
        &f,
        "B",
        ack_op("missing", "P1", &receipt),
        "attempt_not_found",
    );
    fail(
        &f,
        "B",
        ack_op(
            "another",
            "P1",
            &acceptance(&SigningKey::from_bytes(&[23; 32]), &other, "validK"),
        ),
        "acceptance_signature",
    );
    ack(
        &f,
        "B",
        "another",
        "P1",
        &acceptance(&key, &other, "validK"),
    );
}

#[test]
fn pending_or_removed_sender_can_record_old_acceptance_without_restoring_access() {
    let (f, key) = fixture();
    let envelope = send_attempt(&f, "B2", "pending", "P1", None);
    let before = call(
        &f,
        "B2",
        json!({"operation":"permission_prepare","change_id":"revokeB","action":{"kind":"revoke_device","account_id":"B","device_id":"B"}}),
    );
    ack(
        &f,
        "B2",
        "pending",
        "P1",
        &acceptance(&key, &envelope, "pendingK"),
    );
    assert_eq!(
        call(&f, "B2", json!({"operation":"permission_inspect"}))["pending_change"],
        before["change"]
    );
    fail(
        &f,
        "B2",
        json!({"operation":"wire_send","logical_message_id":"pending","attempt_id":"P1","payload":"synthetic device test"}),
        "permission_pending",
    );
    let (f, key) = fixture();
    let envelope = send_attempt(&f, "B2", "removed", "P1", None);
    let prepared = call(
        &f,
        "B",
        json!({"operation":"permission_prepare","change_id":"revokeB2","action":{"kind":"revoke_device","account_id":"B","device_id":"B2"}}),
    );
    accept(&f, &key, &prepared, &["A", "B", "C", "B2"]);
    let before = future_state(&f, "B2");
    ack(
        &f,
        "B2",
        "removed",
        "P1",
        &acceptance(&key, &envelope, "removedK"),
    );
    assert_only_acceptance_changed(before, future_state(&f, "B2"));
    assert_eq!(
        call(&f, "B2", json!({"operation":"permission_inspect"}))["access_removed"],
        true
    );
    fail(
        &f,
        "B2",
        json!({"operation":"wire_send","logical_message_id":"removed","attempt_id":"P1","payload":"synthetic device test"}),
        "access_removed",
    );
}

#[test]
fn old_outbox_without_receipt_stays_unaccepted_and_ambiguous_ids_fail_on_load() {
    let (f, key) = fixture();
    let envelope = legacy_send_attempt(&f, "B", "legacySent", "P1", None);
    mutate(&f, "B", |s| {
        let mut value = serde_json::to_value(&s.wire).unwrap();
        for record in value["outbox"].as_object_mut().unwrap().values_mut() {
            record.as_object_mut().unwrap().remove("acceptance_receipt");
        }
        s.wire = serde_json::from_value(value).unwrap();
    });
    assert_eq!(
        call(&f, "B", json!({"operation":"wire_inspect"}))["accepted_outbox_count"],
        0
    );
    assert_eq!(
        call(&f, "B", json!({"operation":"history_inspect"}))["sent_without_acceptance_count"],
        1
    );
    let receipt = acceptance(&key, &envelope, "sentK");
    ack(&f, "B", "legacySent", "P1", &receipt);
    let request = begin(&f, "ambiguous", select(&f, &["sentK"]));
    mutate(&f, "B", |s| {
        let record = s.wire.inbox.values_mut().next().unwrap();
        record.acceptance_id = Some("sentK".into());
        record.payload = None;
    });
    fail(
        &f,
        "B",
        json!({"operation":"history_export","request":request}),
        "acceptance_conflict",
    );
}

#[test]
fn importing_own_sent_copy_checks_native_attempts_but_does_not_mark_them_accepted() {
    let (f, key) = fixture();
    let first = legacy_send_attempt(&f, "B2", "native", "P1", None);
    let receipt = acceptance(&key, &first, "nativeK");
    call(
        &f,
        "B",
        json!({"operation":"wire_receive","header_bytes":first["header_bytes"],"payload_bytes":first["payload_bytes"],"acceptance_id":"nativeK","acceptance_receipt":receipt}),
    );
    let second = legacy_send_attempt(&f, "B2", "native", "P2", Some("P1"));
    let request = begin(&f, "nativeT", select(&f, &["nativeK"]));
    let package = export(&f, &request);
    let before = future_state(&f, "B2");
    call(&f, "B2", import_op(&key, &request, &package));
    assert_eq!(future_state(&f, "B2"), before);
    assert_eq!(
        call(&f, "B2", json!({"operation":"wire_inspect"}))["accepted_outbox_count"],
        0
    );
    // 已接受另一尝试时，新的迁移不能借源设备证明盖过本机原接受事实。
    ack(
        &f,
        "B2",
        "native",
        "P2",
        &acceptance(&key, &second, "nativeP2K"),
    );
    let request = begin(&f, "nativeConflict", select(&f, &["nativeK"]));
    let package = export(&f, &request);
    fail(
        &f,
        "B2",
        import_op(&key, &request, &package),
        "history_conflict",
    );
    let (f, key) = fixture();
    let envelope = send_attempt(&f, "B2", "sameAttempt", "P1", None);
    call(
        &f,
        "B",
        json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"],"acceptance_id":"sameK","acceptance_receipt":acceptance(&key,&envelope,"sameK")}),
    );
    let request = begin(&f, "sameAttemptT", select(&f, &["sameK"]));
    let package = export(&f, &request);
    mutate(&f, "B2", |s| {
        let r = s.wire.outbox.values_mut().next().unwrap();
        r.envelope.payload_bytes = codec::encode(b"different stored bytes");
    });
    fail(
        &f,
        "B2",
        import_op(&key, &request, &package),
        "history_conflict",
    );
}
