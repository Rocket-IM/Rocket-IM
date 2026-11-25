//! 合成固定种子仅用于公开协议向量，负例重新签名以区分结构校验与验签。
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[23; 32])
}
fn proof(raw: &[u8], domain: &[u8]) -> SignedRecord {
    let mut payload = domain.to_vec();
    payload.extend(raw);
    SignedRecord {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(key().sign(&payload).to_bytes()),
    }
}
fn intent() -> Value {
    let target = json!({"account_id":"bob","device_id":"b2","signature_key":STANDARD.encode(key().verifying_key().as_bytes())});
    let actor = json!({"account_id":"bob","device_id":"b1","signature_key":STANDARD.encode(SigningKey::from_bytes(&[42;32]).verifying_key().as_bytes())});
    let floor =
        json!({"authorization_version":"9007199254740993","crypto_state_ref":"11".repeat(32)});
    json!({"protocol_version":"rim-recovery-request-1","kind":"intent","scope":{"service_id":"vector-service","conversation_id":"G1","group_id":STANDARD.encode(b"actual-group")},
        "request_id":"recover-vector","signer":target,"actor":actor,"nonce":"12".repeat(32),"change_id":"change-vector",
        "root_admission":{"change_id":"root-add","record_sha256":"13".repeat(32)},"current_admission":{"change_id":"previous-recovery","record_sha256":"14".repeat(32)},
        "predecessor":floor,"known_floor":floor,"directory_refs":[{"account_id":"bob","version":"2","sha256":"15".repeat(32)}],
        "key_package_sha256":"16".repeat(32),"history_policy":"from_recovery","issued_at_unix_secs":"1791900000","expires_at_unix_secs":"1791900300"})
}
#[test]
fn recovery_signed_byte_vector() {
    let value = intent();
    let raw = serde_json::to_vec(&value).unwrap();
    let signed = proof(&raw, REQUEST_DOMAIN);
    assert_eq!(
        serde_json::to_value(parse_intent(&signed).unwrap()).unwrap(),
        value
    );
    let vector = json!({"request":value,"proof":signed,"signed_record_sha256":signed_digest(&signed).unwrap()});
    println!("RECOVERY_VECTOR={vector}");
    let saved: Value = serde_json::from_str(include_str!(
        "../../../../api/realtime/join-recovery-vectors.json"
    ))
    .unwrap();
    assert_eq!(saved["positive"], vector);
    assert!(parse_request(&proof(&raw, CHANGE_DOMAIN)).is_err());
    assert!(parse_request(&proof(&raw, crate::key_package::REQUEST_DOMAIN)).is_err());
    let spaced = serde_json::to_vec_pretty(&value).unwrap();
    let alternative = proof(&spaced, REQUEST_DOMAIN);
    assert_eq!(
        parse_request(&alternative).unwrap(),
        parse_request(&signed).unwrap()
    );
    assert_ne!(
        signed_digest(&alternative).unwrap(),
        signed_digest(&signed).unwrap()
    );
    assert!(parse_request(&SignedRecord {
        statement_bytes: alternative.statement_bytes,
        signature_bytes: signed.signature_bytes.clone()
    })
    .is_err());
}
#[test]
fn recovery_strict_structure_even_with_valid_signature() {
    for (name, value) in [
        ("protocol_version", json!("rim-recovery-request-2")),
        ("history_policy", json!("from_join")),
        ("unknown", json!(true)),
        ("expires_at_unix_secs", json!("1791900000")),
        ("issued_at_unix_secs", json!(1791900000)),
        ("nonce", json!("AB".repeat(32))),
    ] {
        let mut input = intent();
        input[name] = value;
        assert!(
            parse_request(&proof(&serde_json::to_vec(&input).unwrap(), REQUEST_DOMAIN)).is_err(),
            "{name}"
        );
    }
    let mut input = intent();
    input["actor"] = input["signer"].clone();
    assert!(parse_request(&proof(&serde_json::to_vec(&input).unwrap(), REQUEST_DOMAIN)).is_err());
    let raw = serde_json::to_string(&intent()).unwrap();
    for raw in [
        raw.replacen('{', "{\"kind\":\"intent\",", 1),
        format!("{raw} {{}}"),
        raw.replace("9007199254740993", "09007199254740993"),
    ] {
        assert!(parse_request(&proof(raw.as_bytes(), REQUEST_DOMAIN)).is_err());
    }
    let mut signed = proof(&serde_json::to_vec(&intent()).unwrap(), REQUEST_DOMAIN);
    signed.signature_bytes.push('=');
    assert!(parse_request(&signed).is_err());
}
#[test]
fn recovery_control_requires_explicit_nullable_reason() {
    let intent = intent();
    let mut value = json!({"protocol_version":"rim-recovery-request-1","kind":"close","scope":intent["scope"],"request_id":"close-vector",
        "signer":intent["signer"],"nonce":"17".repeat(32),"recovery_id":"recover-vector","change_id":"change-vector","intent_sha256":"18".repeat(32),"reason":"cancelled"});
    assert!(parse_request(&proof(&serde_json::to_vec(&value).unwrap(), REQUEST_DOMAIN)).is_ok());
    value["reason"] = Value::Null;
    assert!(parse_request(&proof(&serde_json::to_vec(&value).unwrap(), REQUEST_DOMAIN)).is_err());
    value["kind"] = json!("claim");
    assert!(parse_request(&proof(&serde_json::to_vec(&value).unwrap(), REQUEST_DOMAIN)).is_ok());
    value.as_object_mut().unwrap().remove("reason");
    assert!(parse_request(&proof(&serde_json::to_vec(&value).unwrap(), REQUEST_DOMAIN)).is_err());
}

#[test]
fn recovery_w1_frozen_requests_and_receipts() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../api/realtime/join-recovery-witness-vectors.json"
    ))
    .unwrap();
    for name in ["intent", "claim", "close"] {
        let entry = &vectors["format_envelopes"][name];
        let signed: SignedRecord = serde_json::from_value(entry["envelope"].clone()).unwrap();
        let parsed = parse_request(&signed).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(serde_json::to_value(parsed).unwrap(), entry["decoded"]);
        assert_eq!(
            signed_digest(&signed).unwrap(),
            entry["signed_record_sha256"]
        );
    }
    let source = vectors["test_identities"]["service"]["member"]["signature_key"]
        .as_str()
        .unwrap();
    for name in ["allocation", "accepted", "closed_branch"] {
        let entry = &vectors["format_envelopes"][name];
        let signed: SignedRecord = serde_json::from_value(entry["envelope"].clone()).unwrap();
        let parsed = verify_receipt(source, &signed).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(serde_json::to_value(parsed).unwrap(), entry["decoded"]);
    }
}
