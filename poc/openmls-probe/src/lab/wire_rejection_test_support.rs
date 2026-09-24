//! 合成 Service 签名仅用于模块回归；权限推进仍执行原 MLS Commit 与快照保存。
use super::*;
use crate::permission::{self, receipts, Proof};

pub(super) fn sign(body: &Value, key: &SigningKey, domain: &[u8]) -> SignedRecord {
    let raw = serde_json::to_vec(body).unwrap();
    let mut input = domain.to_vec();
    input.extend(&raw);
    SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(&key.sign(&input).to_bytes()),
    }
}
pub(super) fn advance(f: &Fixture, key: &SigningKey, removed: &str) -> (Value, Value) {
    let change:Proof=serde_json::from_value(f.call("A",json!({"operation":"permission_prepare","change_id":format!("remove{removed}"),"action":{"kind":"remove_member","account_id":removed}}))["change"].clone()).unwrap();
    let state = load(f, "A");
    let (next, s) =
        permission::verify(state.permissions.checkpoint.as_ref().unwrap(), &change).unwrap();
    let body = json!({"protocol_version":"rim-permission-receipt-1","service_id":s.service_id,"conversation_id":s.conversation_id,
        "actor":s.actor,"change_id":s.change_id,"proof_sha256":receipts::proof_digest(&change).unwrap(),
        "outcome":"accepted","authorization_version":s.authorization_version,"crypto_state_ref":s.to_state_ref});
    let record = json!({"change":change,"receipt":sign(&body,key,receipts::RECEIPT_DOMAIN)});
    apply(f, "A", &record);
    (record, serde_json::to_value(next).unwrap())
}
pub(super) fn apply(f: &Fixture, device: &str, record: &Value) {
    f.call(
        device,
        json!({"operation":"permission_recover","record":record}),
    );
}
pub(super) fn body(sent: &Value, cp: &Value, id: &str, previous: Option<(&str, &str)>) -> Value {
    let raw = codec::decode(sent["envelope"]["header_bytes"].as_str().unwrap()).unwrap();
    let payload = codec::decode(sent["envelope"]["payload_bytes"].as_str().unwrap()).unwrap();
    let header: Value = serde_json::from_slice(&raw).unwrap();
    json!({"protocol_version":"rim-message-rejection-1","service_id":header["service_id"],"conversation_id":header["conversation_id"],
        "sender":header["sender"],"logical_message_id":header["logical_message_id"],"attempt_id":header["attempt_id"],
        "envelope_sha256":crate::message_acceptance::envelope_digest(&raw,&payload),
        "replaces_attempt_id":previous.map(|(attempt,_)|attempt),"predecessor_closure_id":previous.map(|(_,closure)|closure),
        "closure_id":id,"outcome":"rejected_final","code":"state_stale","required_authorization_version":cp["authorization_version"],"required_crypto_state_ref":cp["crypto_state_ref"]})
}
pub(super) fn rejection(body: &Value, key: &SigningKey) -> Value {
    json!({"operation":"wire_reject","logical_message_id":body["logical_message_id"],"attempt_id":body["attempt_id"],"rejection_receipt":sign(body,key,message_rejection::SIGNING_DOMAIN)})
}
pub(super) fn successor(attempt: &str, previous: &str, closure: &str) -> Value {
    json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":attempt,"payload":"synthetic test content","replaces_attempt_id":previous,"closure_id":closure})
}
pub(super) fn next() -> Value {
    json!({"operation":"wire_send","logical_message_id":"M2","attempt_id":"P1","payload":"synthetic test content"})
}
pub(super) fn close(f: &Fixture, key: &SigningKey, attempt: &str, id: &str) -> Value {
    let request = f.call(
        "B",
        json!({"operation":"wire_close_request","logical_message_id":"M1","attempt_id":attempt}),
    );
    let body = json!({"protocol_version":"rim-message-closure-1","service_id":"S1","conversation_id":"G1","sender":{"account_id":"B","device_id":"B"},"logical_message_id":"M1","attempt_id":attempt,
        "envelope_sha256":request["envelope_sha256"],"replaces_attempt_id":request["replaces_attempt_id"],"predecessor_closure_id":request["closure_id"],"closure_id":id,"outcome":"cancelled_before_accept"});
    json!({"operation":"wire_close","logical_message_id":"M1","attempt_id":attempt,"closure_receipt":sign(&body,key,crate::message_closure::SIGNING_DOMAIN)})
}
