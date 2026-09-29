//! 不可信证明与损坏快照回归；篡改仅作为 synthetic 负例装置。
use super::*;

#[test]
fn closure_requires_gate_for_legacy_outbox_and_snapshot_shape_stays_absent() {
    let f = super::super::wire_tests::Fixture::new();
    let key = SigningKey::from_bytes(&[74; 32]);
    f.send("A", "M1");
    pin(&f, &key);
    let state = serde_json::to_value(load(&f, "A")).unwrap();
    assert!(state.get("wire_closures").is_none());
    let request = json!({"service_id":"S1","conversation_id":"G1","logical_message_id":"M1","attempt_id":"P1","envelope_sha256":"a".repeat(64)});
    reject(
        &f,
        "A",
        close_op(&request, &signed(&statement(&request, "C1"), &key)),
        "closure_required",
    );
    reject(
        &f,
        "A",
        json!({"operation":"wire_close_request","logical_message_id":"M1","attempt_id":"P1"}),
        "closure_required",
    );
    let (f, _) = setup();
    enable(&f, "A");
    reject(
        &f,
        "A",
        json!({"operation":"wire_close_request","logical_message_id":"M1","attempt_id":"P1"}),
        "closure_not_found",
    );
}

#[test]
fn closure_invalid_signature_scope_digest_and_predecessor_keep_original_snapshot() {
    let (f, key) = setup();
    enable(&f, "A");
    f.send("A", "M1");
    let request = export(&f, "M1", "P1");
    let body = statement(&request, "C1");
    reject(
        &f,
        "A",
        close_op(&request, &signed(&body, &SigningKey::from_bytes(&[75; 32]))),
        "closure_signature",
    );
    for field in [
        "service_id",
        "conversation_id",
        "logical_message_id",
        "attempt_id",
        "envelope_sha256",
        "sender",
        "predecessor",
    ] {
        let mut bad = body.clone();
        match field {
            "envelope_sha256" => bad[field] = json!("0".repeat(64)),
            "sender" => bad[field] = json!({"account_id":"B","device_id":"B"}),
            "predecessor" => {
                bad["replaces_attempt_id"] = json!("P0");
                bad["predecessor_closure_id"] = json!("C0");
            }
            _ => bad[field] = json!("other"),
        }
        reject(
            &f,
            "A",
            close_op(&request, &signed(&bad, &key)),
            "closure_conflict",
        );
    }
    for missing in ["replaces_attempt_id", "predecessor_closure_id"] {
        let mut bad = body.clone();
        bad.as_object_mut().unwrap().remove(missing);
        reject(
            &f,
            "A",
            close_op(&request, &signed(&bad, &key)),
            "closure_invalid",
        );
    }
    let mut rejected = body.clone();
    rejected["outcome"] = json!("rejected_final");
    reject(
        &f,
        "A",
        close_op(&request, &signed(&rejected, &key)),
        "closure_invalid",
    );
    f.call("A", close_op(&request, &signed(&body, &key)));
    reject(
        &f,
        "A",
        close_op(&request, &signed(&statement(&request, "different"), &key)),
        "closure_conflict",
    );
    let mut changed = successor("P2", "P1", "C1");
    changed["payload"] = json!("different synthetic content");
    reject(&f, "A", changed, "idempotency_conflict");
}

#[test]
fn closure_corrupt_marker_signature_ancestor_and_tail_are_rejected_on_load() {
    for defect in [
        "gate",
        "empty",
        "signature",
        "scope",
        "proof_removed",
        "ancestor_accepted",
        "tail",
        "payload",
        "marker_removed",
    ] {
        let (f, key) = setup();
        enable(&f, "A");
        let p1 = f.send("A", "M1");
        f.call("A", close(&f, &key, "P1", "C1"));
        f.call("A", successor("P2", "P1", "C1"));
        alter_invalid(&f, "A", |state| match defect {
            "gate" => state.wire_send_order = None,
            "empty" => state.wire_closures.as_mut().unwrap().records.clear(),
            "marker_removed" => state.wire_closures = None,
            "proof_removed" => {
                state.wire.outbox.retain(|_, r| r.attempt_id != "P1");
            }
            "signature" => {
                state
                    .wire_closures
                    .as_mut()
                    .unwrap()
                    .records
                    .values_mut()
                    .next()
                    .unwrap()
                    .signature_bytes = codec::encode(&[0; 64])
            }
            "scope" => {
                let proof = state
                    .wire_closures
                    .as_mut()
                    .unwrap()
                    .records
                    .values_mut()
                    .next()
                    .unwrap();
                let raw = codec::decode(&proof.statement_bytes).unwrap();
                let mut body: Value = serde_json::from_slice(&raw).unwrap();
                body["service_id"] = json!("foreign");
                *proof = signed(&body, &key);
            }
            "ancestor_accepted" => {
                state
                    .wire
                    .outbox
                    .values_mut()
                    .find(|r| r.attempt_id == "P1")
                    .unwrap()
                    .acceptance_receipt = Some(
                    serde_json::from_value(accept(&p1, &key, "K1")["acceptance_receipt"].clone())
                        .unwrap(),
                );
            }
            "tail" => {
                let old = state
                    .wire
                    .outbox
                    .iter()
                    .find(|(_, r)| r.attempt_id == "P1")
                    .unwrap()
                    .0
                    .clone();
                *state.wire.tails.values_mut().next().unwrap() = old;
            }
            _ => {
                state
                    .wire
                    .outbox
                    .values_mut()
                    .find(|r| r.attempt_id == "P2")
                    .unwrap()
                    .payload = "altered synthetic".into()
            }
        });
        reject(
            &f,
            "A",
            json!({"operation":"wire_inspect"}),
            "closure_state",
        );
    }
}

#[test]
fn closure_accounts_keep_independent_pending_and_cannot_consume_foreign_proof() {
    let (f, key) = setup();
    enable(&f, "A");
    enable(&f, "B");
    f.send("A", "M1");
    f.send("B", "M1");
    let proof = close(&f, &key, "P1", "C1");
    reject(&f, "B", proof.clone(), "closure_conflict");
    f.call("A", proof);
    f.call("A", successor("P2", "P1", "C1"));
    assert_eq!(
        inspect(&f, "B")["send_order"]["pending"],
        json!({"logical_message_id":"M1","attempt_id":"P1"})
    );
    reject(&f, "B", next(), "send_order_pending");
}
