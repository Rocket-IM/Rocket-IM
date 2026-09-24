//! 只在测试中用合成固定 Service 钥签原消息接受和原普通流页面。
use super::*;
use crate::permission::receipts::SignedRecord;
use ed25519_dalek::Signer;

pub(super) fn message(f: &Fixture, key: &SigningKey, seq: u64) -> Value {
    let sent = f.send("A", &format!("M{seq}"));
    message_envelope(key, &sent["envelope"], seq, &format!("K{seq:03}"))
}
pub(super) fn message_envelope(
    key: &SigningKey,
    envelope: &Value,
    seq: u64,
    acceptance: &str,
) -> Value {
    let raw = codec::decode(envelope["header_bytes"].as_str().unwrap()).unwrap();
    let payload = codec::decode(envelope["payload_bytes"].as_str().unwrap()).unwrap();
    let header: Value = serde_json::from_slice(&raw).unwrap();
    let body = json!({"protocol_version":"rim-message-acceptance-1","service_id":header["service_id"],"conversation_id":header["conversation_id"],
        "acceptance_id":acceptance,"envelope_sha256":crate::message_acceptance::envelope_digest(&raw,&payload),"authorization_version":header["authorization_version"],"crypto_state_ref":header["crypto_state_ref"]});
    let bytes = serde_json::to_vec(&body).unwrap();
    let mut signed = crate::message_acceptance::SIGNING_DOMAIN.to_vec();
    signed.extend(&bytes);
    let proof = SignedRecord {
        statement_bytes: codec::encode(&bytes),
        signature_bytes: codec::encode(&key.sign(&signed).to_bytes()),
    };
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),"availability":"available",
        "event":{"type":"message","acceptance_id":acceptance,"envelope":envelope,"acceptance_receipt":proof}})
}
pub(super) fn receipt(
    seq: u64,
    kind: &str,
    acceptance: &str,
    attempt: &str,
    account: &str,
    device: &str,
) -> Value {
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),"availability":"available",
        "event":{"type":kind,"acceptance_id":acceptance,"attempt_id":attempt,"device":{"account_id":account,"device_id":device}}})
}
pub(super) fn download(f: &Fixture, key: &SigningKey, events: Vec<Value>, after: u64, next: u64) {
    let page = super::super::stream_source_test_support::page(events, next, next);
    f.call(
        "B",
        super::super::stream_source_test_support::signed(key, &page, after, 100),
    );
}
pub(super) fn process(f: &Fixture) -> Value {
    f.call("B", json!({"operation":"wire_process"}))
}
pub(super) fn mark(f: &Fixture, events: &[&str]) -> Value {
    f.call("B", json!({"operation":"wire_read","event_ids":events}))
}
pub(super) fn inspect(f: &Fixture) -> Value {
    readonly(f, "wire_read_inspect")
}
pub(super) fn pending(f: &Fixture) -> Value {
    readonly(f, "wire_read_pending")
}
pub(super) fn readonly(f: &Fixture, operation: &str) -> Value {
    let bytes = fs::read(f.root.join("B/state.enc")).unwrap();
    let result = f.call("B", json!({"operation":operation}));
    assert!(bytes == fs::read(f.root.join("B/state.enc")).unwrap());
    result
}
