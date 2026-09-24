//! 普通签页测试装置：显式由合成 Service 钥签名，不在被测客户端补签输入。
use super::{codec, wire_tests::Fixture};
use crate::{permission::receipts::SignedRecord, stream_page};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

pub(super) fn pin(f: &Fixture, key: &SigningKey) {
    let members: Vec<_> = f.identities.iter().map(|identity| json!({
        "account_id":identity["account"],"device_id":identity["device"],"signature_key":identity["signature_key"]
    })).collect();
    let checkpoint = json!({"service_id":"S1","conversation_id":"G1","authorization_version":"1",
        "crypto_state_ref":f.call("A",json!({"operation":"wire_inspect"}))["crypto_state_ref"],
        "owner_account_id":"A","members":members});
    f.call(
        "B",
        json!({"operation":"permission_bootstrap","checkpoint":checkpoint,
        "relay_receipt_key":codec::encode(key.verifying_key().as_bytes())}),
    );
}

pub(super) fn setup() -> (Fixture, SigningKey) {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[61; 32]);
    pin(&f, &key);
    (f, key)
}

pub(super) fn slot(seq: u64) -> Value {
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),
        "availability":"available","event":{"type":"delivery","acceptance_id":format!("K{seq}"),
        "attempt_id":"P1","device":{"account_id":"B","device_id":"B"}}})
}

pub(super) fn page(events: Vec<Value>, next: u64, watermark: u64) -> Value {
    json!({"stream_id":"B_stream","events":events,"next_after_seq":next.to_string(),
        "watermark":watermark.to_string(),"has_more":next<watermark})
}

pub(super) fn statement(raw: &[u8], after: u64, limit: u64) -> Value {
    json!({"protocol_version":"RIM-STREAM-PAGE-POC-1","service_id":"S1","account_id":"B",
        "device_id":"B","stream_id":"B_stream","after_seq":after.to_string(),"limit":limit.to_string(),
        "page_sha256":codec::digest_hex(&codec::digest(raw))})
}

pub(super) fn signed_raw(key: &SigningKey, raw: &[u8], statement: &Value) -> Value {
    let body = serde_json::to_vec(statement).unwrap();
    let mut message = stream_page::SIGNING_DOMAIN.to_vec();
    message.extend(&body);
    let receipt = SignedRecord {
        statement_bytes: codec::encode(&body),
        signature_bytes: codec::encode(&key.sign(&message).to_bytes()),
    };
    json!({"operation":"wire_download_signed","page_bytes":codec::encode(raw),"receipt":receipt})
}

pub(super) fn signed(key: &SigningKey, page: &Value, after: u64, limit: u64) -> Value {
    let raw = serde_json::to_vec(page).unwrap();
    signed_raw(key, &raw, &statement(&raw, after, limit))
}
