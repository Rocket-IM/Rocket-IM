//! 真实MLS与持久快照；Service声明仅由测试固定钥签名，不代表真实Relay确认。
use super::*;
use ed25519_dalek::Signer;

pub(super) fn sign(key: &SigningKey, domain: &[u8], body: Value) -> Value {
    let raw = serde_json::to_vec(&body).unwrap();
    let mut message = domain.to_vec();
    message.extend(&raw);
    json!({"statement_bytes":codec::encode(&raw),"signature_bytes":codec::encode(&key.sign(&message).to_bytes())})
}
pub(super) fn download(
    f: &Fixture,
    key: &SigningKey,
    device: &str,
    events: Vec<Value>,
    after: u64,
    next: u64,
) {
    f.call(device, download_operation(key, device, events, after, next));
    f.call(device, json!({"operation":"wire_process"}));
}
pub(super) fn download_operation(
    key: &SigningKey,
    device: &str,
    events: Vec<Value>,
    after: u64,
    next: u64,
) -> Value {
    let page = json!({"stream_id":format!("{device}_stream"),"events":events,"next_after_seq":next.to_string(),
        "watermark":next.to_string(),"has_more":false});
    let raw = serde_json::to_vec(&page).unwrap();
    let proof = sign(
        key,
        crate::stream_page::SIGNING_DOMAIN,
        json!({"protocol_version":"RIM-STREAM-PAGE-POC-1","service_id":"S1","account_id":device,"device_id":device,
            "stream_id":format!("{device}_stream"),"after_seq":after.to_string(),"limit":"100",
            "page_sha256":codec::digest_hex(&codec::digest(&raw))}),
    );
    json!({"operation":"wire_download_signed","page_bytes":codec::encode(&raw),"receipt":proof})
}
pub(super) fn event(device: &str, seq: u64, body: Value) -> Value {
    json!({"stream_id":format!("{device}_stream"),"event_seq":seq.to_string(),"event_id":format!("{device}E{seq}"),
        "availability":"available","event":body})
}
pub(super) fn fixture(read: bool, terminal: &str) -> (Fixture, SigningKey, Value, String) {
    let (f, key) = super::super::wire_send_order_test_support::setup();
    let payload = format!("reclaim-secret-{}", "x".repeat(16 * 1024));
    let sent = f.call("A",json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P1","payload":payload}));
    let acceptance = accept(&sent, &key, "K1");
    f.call("A", acceptance.clone());
    download(&f, &key, "A", Vec::new(), 0, 0);
    download(
        &f,
        &key,
        "B",
        vec![event(
            "B",
            1,
            json!({"type":"message","acceptance_id":"K1",
        "envelope":sent["envelope"],"acceptance_receipt":acceptance["acceptance_receipt"]}),
        )],
        0,
        1,
    );
    if read {
        f.call("B", json!({"operation":"wire_read","event_ids":["BE1"]}));
    }
    let mut events = vec![event(
        "B",
        2,
        json!({"type":"delivery","acceptance_id":"K1","attempt_id":"P1",
        "device":{"account_id":"B","device_id":"B"}}),
    )];
    if read {
        events.push(event(
            "B",
            3,
            json!({"type":"read","acceptance_id":"K1","attempt_id":"P1",
        "device":{"account_id":"B","device_id":"B"}}),
        ));
    }
    let last = if read { 4 } else { 3 };
    events.push(event(
        "B",
        last,
        json!({"type":"message_availability","target_event_seq":"1","target_event_id":"BE1",
        "acceptance_id":"K1","attempt_id":"P1","availability":terminal}),
    ));
    download(&f, &key, "B", events, 1, last);
    (f, key, sent, payload)
}
pub(super) fn permit(
    f: &Fixture,
    key: &SigningKey,
    device: &str,
    sent: &Value,
    plan: &str,
    terminal: &str,
) -> Value {
    let raw = codec::decode(sent["envelope"]["header_bytes"].as_str().unwrap()).unwrap();
    let payload = codec::decode(sent["envelope"]["payload_bytes"].as_str().unwrap()).unwrap();
    let header: Value = serde_json::from_slice(&raw).unwrap();
    let processed =
        f.call(device, json!({"operation":"wire_inspect"}))["sync"]["processed_cursor"].clone();
    sign(
        key,
        crate::message_reclamation::SIGNING_DOMAIN,
        json!({"protocol_version":"rim-message-reclaim-1",
        "service_id":"S1","conversation_id":"G1","plan_id":plan,"account_id":device,"device_id":device,
        "stream_id":format!("{device}_stream"),"processed_seq":processed,"messages":[{"acceptance_id":"K1",
        "envelope_sha256":crate::message_acceptance::envelope_digest(&raw,&payload),"availability":terminal,
        "recipients":header["recipients"]}]}),
    )
}
pub(super) fn re_sign(key: &SigningKey, proof: &Value, alter: impl FnOnce(&mut Value)) -> Value {
    let mut body: Value =
        serde_json::from_slice(&codec::decode(proof["statement_bytes"].as_str().unwrap()).unwrap())
            .unwrap();
    alter(&mut body);
    sign(key, crate::message_reclamation::SIGNING_DOMAIN, body)
}
