//! 错误证明与负例损坏快照不允许释放发送门；不输出明文、密钥或完整快照。
use super::*;

#[test]
fn rejection_opt_in_and_unknown_attempt_are_explicit_and_old_snapshot_omits_marker() {
    let (f, key) = setup();
    let sent = f.send("B", "M1");
    let (_, cp) = advance(&f, &key, "C");
    assert!(serde_json::to_value(load(&f, "B"))
        .unwrap()
        .get("wire_rejections")
        .is_none());
    reject(
        &f,
        "B",
        rejection(&body(&sent, &cp, "R1", None), &key),
        "rejection_required",
    );
    let (f, key) = setup();
    enable(&f, "B");
    let absent = body(&sent, &cp, "R1", None);
    reject(&f, "B", rejection(&absent, &key), "rejection_not_found");
}

#[test]
fn rejection_signature_scope_digest_predecessor_and_strict_floor_are_atomic() {
    let (f, key) = setup();
    enable(&f, "B");
    let sent = f.send("B", "M1");
    let (_, cp) = advance(&f, &key, "C");
    let original = body(&sent, &cp, "R1", None);
    reject(
        &f,
        "B",
        rejection(&original, &SigningKey::from_bytes(&[75; 32])),
        "rejection_signature",
    );
    for field in [
        "service_id",
        "conversation_id",
        "sender",
        "logical_message_id",
        "attempt_id",
        "envelope_sha256",
        "predecessor",
        "required_authorization_version",
    ] {
        let mut bad = original.clone();
        match field {
            "sender" => bad[field] = json!({"account_id":"A","device_id":"A"}),
            "envelope_sha256" => bad[field] = json!("0".repeat(64)),
            "required_authorization_version" => bad[field] = json!("1"),
            "predecessor" => {
                bad["replaces_attempt_id"] = json!("P0");
                bad["predecessor_closure_id"] = json!("R0");
            }
            _ => bad[field] = json!("foreign"),
        }
        let mut operation = rejection(&bad, &key);
        operation["logical_message_id"] = json!("M1");
        operation["attempt_id"] = json!("P1");
        reject(&f, "B", operation, "rejection_conflict");
    }
    for field in [
        "code",
        "outcome",
        "version_overflow",
        "version_leading_zero",
        "replaces_attempt_id",
        "predecessor_closure_id",
    ] {
        let mut bad = original.clone();
        match field {
            "code" => bad[field] = json!("state_conflict"),
            "outcome" => bad[field] = json!("accepted"),
            "version_overflow" => {
                bad["required_authorization_version"] = json!("18446744073709551616")
            }
            "version_leading_zero" => bad["required_authorization_version"] = json!("02"),
            _ => {
                bad.as_object_mut().unwrap().remove(field);
            }
        }
        reject(&f, "B", rejection(&bad, &key), "rejection_invalid");
    }
    f.call("B", rejection(&original, &key));
    let mut changed = original;
    changed["closure_id"] = json!("another");
    reject(&f, "B", rejection(&changed, &key), "rejection_conflict");
}

#[test]
fn rejection_known_floor_conflict_and_foreign_account_proof_are_rejected() {
    let (f, key) = setup();
    enable(&f, "B");
    enable(&f, "A");
    f.send("A", "M1");
    let sent = f.send("B", "M1");
    let (record, cp) = advance(&f, &key, "C");
    let original = body(&sent, &cp, "R1", None);
    reject(&f, "A", rejection(&original, &key), "rejection_conflict");
    apply(&f, "B", &record);
    let mut bad = original.clone();
    bad["required_crypto_state_ref"] = json!("0".repeat(64));
    reject(&f, "B", rejection(&bad, &key), "rejection_conflict");
    f.call("B", rejection(&original, &key));
    reject(
        &f,
        "B",
        successor("P2", "P1", "foreign"),
        "rejection_conflict",
    );
    let mut changed = successor("P2", "P1", "R1");
    changed["payload"] = json!("different synthetic content");
    reject(&f, "B", changed, "idempotency_conflict");
}

#[test]
fn rejection_marker_proof_terminal_and_successor_checkpoint_damage_fail_on_load() {
    for defect in [
        "gate",
        "empty",
        "marker",
        "signature",
        "accepted",
        "closed",
        "floor",
        "header_version",
        "header_ref",
    ] {
        let (f, key) = setup();
        enable(&f, "B");
        let sent = f.send("B", "M1");
        let (record, cp) = advance(&f, &key, "C");
        let closure = close(&f, &key, "P1", "C1");
        f.call("B", rejection(&body(&sent, &cp, "R1", None), &key));
        apply(&f, "B", &record);
        f.call("B", successor("P2", "P1", "R1"));
        alter_invalid(&f, "B", |state| match defect {
            "gate" => state.wire_send_order = None,
            "empty" => state.wire_rejections.as_mut().unwrap().records.clear(),
            "marker" => state.wire_rejections = None,
            "signature" => {
                state
                    .wire_rejections
                    .as_mut()
                    .unwrap()
                    .records
                    .values_mut()
                    .next()
                    .unwrap()
                    .signature_bytes = codec::encode(&[0; 64])
            }
            "accepted" => {
                state
                    .wire
                    .outbox
                    .values_mut()
                    .find(|r| r.attempt_id == "P1")
                    .unwrap()
                    .acceptance_receipt = Some(
                    serde_json::from_value(accept(&sent, &key, "K1")["acceptance_receipt"].clone())
                        .unwrap(),
                )
            }
            "closed" => {
                let attempt = state
                    .wire_rejections
                    .as_ref()
                    .unwrap()
                    .records
                    .keys()
                    .next()
                    .unwrap()
                    .clone();
                state
                    .wire_closures
                    .get_or_insert_with(Default::default)
                    .records
                    .insert(
                        attempt,
                        serde_json::from_value(closure["closure_receipt"].clone()).unwrap(),
                    );
            }
            "floor" => {
                state.permissions.recovery.verified_refs.remove("2");
            }
            _ => {
                let child = state
                    .wire
                    .outbox
                    .values_mut()
                    .find(|r| r.attempt_id == "P2")
                    .unwrap();
                let mut header: Value =
                    serde_json::from_slice(&codec::decode(&child.envelope.header_bytes).unwrap())
                        .unwrap();
                if defect == "header_version" {
                    header["authorization_version"] = json!("1");
                } else {
                    header["crypto_state_ref"] = json!("0".repeat(64));
                }
                child.envelope.header_bytes = codec::encode(&serde_json::to_vec(&header).unwrap());
            }
        });
        reject(
            &f,
            "B",
            json!({"operation":"wire_inspect"}),
            if defect == "marker" {
                "closure_state"
            } else {
                "rejection_state"
            },
        );
    }
}
