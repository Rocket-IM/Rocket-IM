use super::super::super::{permission_state, wire_types};
use super::*;
use crate::message_acceptance::{self, MessageAcceptanceStatement};

fn acceptance(key: &SigningKey, envelope: &Value, id: &str) -> SignedRecord {
    let raw = codec::decode(envelope["header_bytes"].as_str().unwrap()).unwrap();
    let payload = codec::decode(envelope["payload_bytes"].as_str().unwrap()).unwrap();
    let header: wire_types::Header = serde_json::from_slice(&raw).unwrap();
    let body = MessageAcceptanceStatement {
        protocol_version: "rim-message-acceptance-1".into(),
        service_id: header.service_id,
        conversation_id: header.conversation_id,
        acceptance_id: id.into(),
        envelope_sha256: message_acceptance::envelope_digest(&raw, &payload),
        authorization_version: header.authorization_version,
        crypto_state_ref: header.crypto_state_ref,
    };
    let raw = serde_json::to_vec(&body).unwrap();
    let mut signed = message_acceptance::SIGNING_DOMAIN.to_vec();
    signed.extend(&raw);
    SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(&key.sign(&signed).to_bytes()),
    }
}
fn receive(envelope: &Value, id: &str, receipt: &SignedRecord) -> Value {
    json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"],"acceptance_id":id,"acceptance_receipt":receipt})
}
fn remove(f: &Fixture, key: &SigningKey, id: &str, target: &str) {
    let proof:Proof=serde_json::from_value(f.call("A",json!({"operation":"permission_prepare","change_id":id,"action":{"kind":"remove_member","account_id":target}}))["change"].clone()).unwrap();
    let record = accepted(key, &proof);
    for device in ["A", "B"] {
        recover(f, device, &record);
    }
}
fn event(envelope: &Value, id: &str, receipt: Option<&SignedRecord>) -> Value {
    let mut value = json!({"stream_id":"B_stream","event_seq":"1","event_id":"E1","availability":"available","event":{"type":"message","acceptance_id":id,"envelope":envelope}});
    if let Some(receipt) = receipt {
        value["event"]["acceptance_receipt"] = json!(receipt);
    }
    value
}

#[test]
fn accepted_past_message_survives_restart_without_rolling_back_current_send_ratchet() {
    let (f, key) = setup();
    let old = f.send("A", "past")["envelope"].clone();
    let receipt = acceptance(&key, &old, "K1");
    remove(&f, &key, "removeC", "C");
    let before = f.send("B", "current_before");
    f.receive("A", &before["envelope"]);
    let state_before = f.call("B", json!({"operation":"wire_inspect"}));
    assert_eq!(
        f.call("B", receive(&old, "K1", &receipt))["historical"],
        true
    );
    assert_eq!(
        f.call("B", receive(&old, "K1", &receipt))["duplicate"],
        true
    );
    let state_after = f.call("B", json!({"operation":"wire_inspect"}));
    for field in ["epoch", "crypto_state_ref", "configuration"] {
        assert_eq!(state_before[field], state_after[field]);
    }
    let after = f.send("B", "current_after");
    f.receive("A", &after["envelope"]);
    assert_eq!(
        state_after["history"]["past_epochs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn receipt_binding_and_mls_failure_preserve_snapshot_and_good_old_message() {
    let (f, key) = setup();
    let old = f.send("A", "past")["envelope"].clone();
    let receipt = acceptance(&key, &old, "K1");
    remove(&f, &key, "removeC", "C");
    fail_atomic(
        &f,
        "B",
        receive(&old, "wrong", &receipt),
        "acceptance_conflict",
    );
    let forged = acceptance(&SigningKey::from_bytes(&[20; 32]), &old, "K1");
    fail_atomic(
        &f,
        "B",
        receive(&old, "K1", &forged),
        "acceptance_signature",
    );
    let mut bad = old.clone();
    let mut raw = codec::decode(old["payload_bytes"].as_str().unwrap()).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    bad["payload_bytes"] = json!(codec::encode(&raw));
    fail_atomic(
        &f,
        "B",
        receive(&bad, "K1", &acceptance(&key, &bad, "K1")),
        "decryption_failed",
    );
    assert_eq!(
        f.call("B", receive(&old, "K1", &receipt))["duplicate"],
        false
    );
}

#[test]
fn bare_current_cache_cannot_be_rebound_by_unsigned_or_different_accepted_id() {
    let (f, key) = setup();
    let envelope = f.send("C", "already")["envelope"].clone();
    f.receive("B", &envelope);
    fail_atomic(
        &f,
        "B",
        json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"],"acceptance_id":"fake"}),
        "acceptance_required",
    );
    let receipt = acceptance(&key, &envelope, "K1");
    assert_eq!(
        f.call("B", receive(&envelope, "K1", &receipt))["duplicate"],
        true
    );
    remove(&f, &key, "removeC", "C");
    assert_eq!(
        f.call("B", receive(&envelope, "K1", &receipt))["duplicate"],
        true
    );
    fail_atomic(
        &f,
        "B",
        receive(&envelope, "K2", &acceptance(&key, &envelope, "K2")),
        "acceptance_conflict",
    );
}

#[test]
fn missing_historical_acceptance_is_terminal_and_removed_sender_is_not_reauthorized() {
    let (f, key) = setup();
    let old = f.send("A", "unsigned")["envelope"].clone();
    let removed = f.send("C", "removed")["envelope"].clone();
    remove(&f, &key, "removeC", "C");
    let page = crate::lab::stream_source_test_support::page(vec![event(&old, "K1", None)], 1, 1);
    f.call(
        "B",
        crate::lab::stream_source_test_support::signed(&key, &page, 0, 100),
    );
    let result = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(result["sync"]["processed_cursor"], "1");
    assert_eq!(result["sync"]["pending_count"], 0);
    assert_eq!(result["deliveries"], json!([]));
    assert_eq!(
        result["results"][0]["result"]["code"],
        "historical_acceptance_required"
    );
    fail_atomic(
        &f,
        "B",
        receive(&removed, "K2", &acceptance(&key, &removed, "K2")),
        "history_sender_revoked",
    );
}

#[test]
fn acceptance_optional_fields_reject_explicit_null_before_dedupe_or_download() {
    let (f, _) = setup();
    let envelope = f.send("A", "M1")["envelope"].clone();
    f.receive("B", &envelope);
    for field in ["acceptance_id", "acceptance_receipt"] {
        let mut request = json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"]});
        request[field] = Value::Null;
        fail_atomic(&f, "B", request, "invalid_request");
    }
    let mut slot = event(&envelope, "K1", None);
    slot["event"]["acceptance_receipt"] = Value::Null;
    fail_atomic(
        &f,
        "B",
        json!({"operation":"wire_download","stream_id":"B_stream","events":[slot],"next_after_seq":"1","watermark":"1","has_more":false}),
        "invalid_request",
    );
}

#[path = "history_boundary_tests.rs"]
mod boundary;
