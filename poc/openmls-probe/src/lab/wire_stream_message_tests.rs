//! 页来源完整性不等于 MLS 有效性；签页里的坏密文仍由原处理链隔离。
use super::{codec, stream_source_test_support::*};
use crate::{message_acceptance, permission::receipts::SignedRecord};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

fn accepted_slot(key: &SigningKey, envelope: &Value, seq: u64) -> Value {
    let header = codec::decode(envelope["header_bytes"].as_str().unwrap()).unwrap();
    let payload = codec::decode(envelope["payload_bytes"].as_str().unwrap()).unwrap();
    let fields: Value = serde_json::from_slice(&header).unwrap();
    let body = json!({"protocol_version":"rim-message-acceptance-1","service_id":"S1",
        "conversation_id":"G1","acceptance_id":format!("K{seq}"),
        "envelope_sha256":message_acceptance::envelope_digest(&header,&payload),
        "authorization_version":fields["authorization_version"],"crypto_state_ref":fields["crypto_state_ref"]});
    let raw = serde_json::to_vec(&body).unwrap();
    let mut message = message_acceptance::SIGNING_DOMAIN.to_vec();
    message.extend(&raw);
    let receipt = SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(&key.sign(&message).to_bytes()),
    };
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),
        "availability":"available","event":{"type":"message","acceptance_id":format!("K{seq}"),
            "envelope":envelope,"acceptance_receipt":receipt}})
}

#[test]
fn signed_page_quarantines_bad_mls_without_losing_valid_suffix() {
    let (f, key) = setup();
    let sent = f.send("A", "M1")["envelope"].clone();
    let mut bad = sent.clone();
    let mut raw = codec::decode(bad["payload_bytes"].as_str().unwrap()).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    bad["payload_bytes"] = json!(codec::encode(&raw));
    let page = page(
        vec![accepted_slot(&key, &bad, 1), accepted_slot(&key, &sent, 2)],
        2,
        2,
    );
    let downloaded = f.call("B", signed(&key, &page, 0, 100));
    assert_eq!(downloaded["status"], "downloaded");
    let processed = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(processed["sync"]["source_verified"], true);
    assert_eq!(processed["sync"]["processed_cursor"], "2");
    assert_eq!(processed["sync"]["quarantined_count"], 1);
    assert_eq!(
        processed["results"][0]["result"]["code"],
        "decryption_failed"
    );
    assert_eq!(processed["deliveries"].as_array().unwrap().len(), 1);
    assert_eq!(
        f.call("B", json!({"operation":"wire_inspect"}))["inbox_count"],
        1
    );
}

#[test]
fn signed_conflicting_message_halts_without_replacing_original_or_appending_suffix() {
    for change_id in [true, false] {
        let (f, key) = setup();
        let sent = f.send("A", "M1")["envelope"].clone();
        let original = accepted_slot(&key, &sent, 1);
        f.call(
            "B",
            signed(&key, &page(vec![original.clone()], 1, 1), 0, 100),
        );
        let mut conflict = original.clone();
        if change_id {
            conflict["event_id"] = json!("changed");
        } else {
            conflict["event"]["envelope"]["payload_bytes"] = json!(codec::encode(b"changed"));
        }
        let received = f.call(
            "B",
            signed(
                &key,
                &page(vec![conflict, accepted_slot(&key, &sent, 2)], 2, 2),
                0,
                100,
            ),
        );
        assert_eq!(received["status"], "stream_conflict");
        assert_eq!(received["sync"]["download_cursor"], "1");
        assert_eq!(received["sync"]["slot_count"], 1);
        assert_eq!(
            f.call(
                "B",
                json!({"operation":"wire_slot_inspect","event_seq":"1"})
            )["slot"],
            original
        );
        f.fails("B", json!({"operation":"wire_process"}), "stream_conflict");
    }
}
