use super::*;
use std::{
    fs,
    os::unix::fs::symlink,
    sync::atomic::{AtomicU64, Ordering},
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rim-receipt-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn run(value: Value) -> Result<Value, PermissionError> {
    execute(&value.to_string())
}
#[test]
fn service_key_create_read_sign_and_wrong_runtime_pin_are_checked() {
    let f = Fixture::new();
    let path = f.0.join("service.key");
    let init = run(json!({"operation":"init","key_path":path})).unwrap();
    let pin = init["result"]["signature_key"].clone();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(run(json!({"operation":"init","key_path":path})).is_err());
    assert_eq!(
        init,
        run(json!({"operation":"public_key","key_path":path})).unwrap()
    );
    let statement = json!({"protocol_version":"rim-permission-receipt-1","service_id":"S1","conversation_id":"G1","actor":{"account_id":"A","device_id":"A1"},"change_id":"C1","proof_sha256":"a".repeat(64),"outcome":"closed","authorization_version":"1","crypto_state_ref":"b".repeat(64)});
    let signed=run(json!({"operation":"sign","key_path":path,"expected_signature_key":pin,"statement":statement})).unwrap();
    assert!(signed["result"]["receipt"]["signature_bytes"].is_string());
    assert!(run(json!({"operation":"sign","key_path":path,"statement":statement})).is_err());
    let other = run(json!({"operation":"init","key_path":f.0.join("other.key")})).unwrap()
        ["result"]["signature_key"]
        .clone();
    assert_eq!(run(json!({"operation":"sign","key_path":path,"expected_signature_key":other,"statement":statement})).unwrap_err().code,"receipt_key_mismatch");
}
#[test]
fn service_key_rejects_symlink_loose_permissions_and_wrong_length() {
    let f = Fixture::new();
    let path = f.0.join("service.key");
    run(json!({"operation":"init","key_path":path})).unwrap();
    let link = f.0.join("link");
    symlink(&path, &link).unwrap();
    assert!(run(json!({"operation":"public_key","key_path":link})).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(run(json!({"operation":"public_key","key_path":path})).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, [0; 31]).unwrap();
    assert!(run(json!({"operation":"public_key","key_path":path})).is_err());
}

#[test]
fn message_acceptance_uses_fixed_raw_digest_and_explicit_signing_domain() {
    use crate::message_acceptance;
    use crate::permission::receipts::{SignedRecord, RECEIPT_DOMAIN};
    let vectors: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../api/realtime/vectors.json"
    )))
    .unwrap();
    let vector = &vectors["message_envelope_digest_vector"];
    let raw_header = STANDARD
        .decode(vector["envelope"]["header_bytes"].as_str().unwrap())
        .unwrap();
    let raw_payload = STANDARD
        .decode(vector["envelope"]["payload_bytes"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        message_acceptance::envelope_digest(&raw_header, &raw_payload),
        vector["sha256"].as_str().unwrap()
    );
    let mut prefixed = vec![b' '];
    prefixed.extend(&raw_header);
    assert_ne!(
        message_acceptance::envelope_digest(&prefixed, &raw_payload),
        vector["sha256"].as_str().unwrap()
    );
    let f = Fixture::new();
    let path = f.0.join("key");
    let init = run(json!({"operation":"init","key_path":path})).unwrap();
    let pin = init["result"]["signature_key"].as_str().unwrap();
    let request = json!({"operation":"sign","key_path":path,"expected_signature_key":pin,"statement":vector["statement"]});
    let result = run(request.clone()).unwrap();
    let record: SignedRecord = serde_json::from_value(result["result"]["receipt"].clone()).unwrap();
    assert_eq!(
        message_acceptance::verify(pin, &record)
            .unwrap()
            .authorization_version,
        "9007199254740993"
    );
    let raw = STANDARD.decode(&record.statement_bytes).unwrap();
    let mut wrong_domain = RECEIPT_DOMAIN.to_vec();
    wrong_domain.extend(&raw);
    let wrong = SignedRecord {
        statement_bytes: record.statement_bytes.clone(),
        signature_bytes: STANDARD.encode(load(&path).unwrap().sign(&wrong_domain).to_bytes()),
    };
    assert_eq!(
        message_acceptance::verify(pin, &wrong).unwrap_err().code,
        "acceptance_signature"
    );
    let mut extra = request.clone();
    extra["statement"]["extra"] = json!(true);
    assert!(run(extra).is_err());
    let mut unknown = request.clone();
    unknown["statement"]["protocol_version"] = json!("arbitrary");
    assert!(run(unknown).is_err());
    let duplicate=request.to_string().replacen("\"protocol_version\":\"rim-message-acceptance-1\"","\"protocol_version\":\"rim-message-acceptance-1\",\"protocol_version\":\"rim-message-acceptance-1\"",1);
    assert!(execute(&duplicate).is_err());
}

#[test]
fn message_closure_signer_requires_explicit_null_and_dedicated_domain() {
    use crate::message_closure;
    use crate::permission::receipts::SignedRecord;
    let f = Fixture::new();
    let path = f.0.join("service.key");
    let pin = run(json!({"operation":"init","key_path":path})).unwrap()["result"]["signature_key"]
        .clone();
    let body = json!({"protocol_version":"rim-message-closure-1","service_id":"S1","conversation_id":"G1",
        "sender":{"account_id":"A","device_id":"A"},"logical_message_id":"M1","attempt_id":"P1",
        "envelope_sha256":"a".repeat(64),"replaces_attempt_id":null,"predecessor_closure_id":null,
        "closure_id":"C1","outcome":"cancelled_before_accept"});
    let result = run(
        json!({"operation":"sign","key_path":path,"expected_signature_key":pin,"statement":body}),
    )
    .unwrap();
    let proof: SignedRecord = serde_json::from_value(result["result"]["receipt"].clone()).unwrap();
    let fact = message_closure::verify(pin.as_str().unwrap(), &proof).unwrap();
    assert!(fact.replaces_attempt_id.is_none());
    let raw = STANDARD.decode(&proof.statement_bytes).unwrap();
    let value: Value = serde_json::from_slice(&raw).unwrap();
    assert!(value
        .as_object()
        .unwrap()
        .contains_key("predecessor_closure_id"));
    assert!(crate::permission::receipts::signature(
        pin.as_str().unwrap(),
        crate::message_acceptance::SIGNING_DOMAIN,
        &raw,
        &proof.signature_bytes
    )
    .is_err());
    for field in ["replaces_attempt_id", "predecessor_closure_id"] {
        let mut missing = body.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(run(json!({"operation":"sign","key_path":path,"expected_signature_key":pin,"statement":missing})).is_err());
    }
    let mut rejected = body;
    rejected["outcome"] = json!("rejected_final");
    assert_eq!(run(json!({"operation":"sign","key_path":path,"expected_signature_key":pin,"statement":rejected})).unwrap_err().code,"closure_invalid");
}

#[test]
fn message_rejection_signer_preserves_required_nulls_and_uses_distinct_domain() {
    use crate::permission::receipts::SignedRecord;
    use crate::{message_closure, message_rejection};
    let f = Fixture::new();
    let path = f.0.join("service.key");
    let pin = run(json!({"operation":"init","key_path":path})).unwrap()["result"]["signature_key"]
        .clone();
    let body = json!({"protocol_version":"rim-message-rejection-1","service_id":"S1","conversation_id":"G1","sender":{"account_id":"A","device_id":"A"},
        "logical_message_id":"M1","attempt_id":"P1","envelope_sha256":"a".repeat(64),"replaces_attempt_id":null,"predecessor_closure_id":null,
        "closure_id":"R1","outcome":"rejected_final","code":"state_stale","required_authorization_version":"18446744073709551615","required_crypto_state_ref":"b".repeat(64)});
    let signed = run(
        json!({"operation":"sign","key_path":path,"expected_signature_key":pin,"statement":body}),
    )
    .unwrap();
    let proof: SignedRecord = serde_json::from_value(signed["result"]["receipt"].clone()).unwrap();
    let fact = message_rejection::verify(pin.as_str().unwrap(), &proof).unwrap();
    assert_eq!(fact.required_authorization_version, u64::MAX.to_string());
    let raw = STANDARD.decode(&proof.statement_bytes).unwrap();
    let value: Value = serde_json::from_slice(&raw).unwrap();
    assert!(value
        .as_object()
        .unwrap()
        .contains_key("replaces_attempt_id"));
    assert!(value["replaces_attempt_id"].is_null());
    assert!(crate::permission::receipts::signature(
        pin.as_str().unwrap(),
        message_closure::SIGNING_DOMAIN,
        &raw,
        &proof.signature_bytes
    )
    .is_err());
    for field in [
        "replaces_attempt_id",
        "predecessor_closure_id",
        "code",
        "required_authorization_version",
    ] {
        let mut bad = body.clone();
        match field {
            "code" => bad[field] = json!("state_conflict"),
            "required_authorization_version" => bad[field] = json!("18446744073709551616"),
            _ => {
                bad.as_object_mut().unwrap().remove(field);
            }
        }
        assert!(run(
            json!({"operation":"sign","key_path":path,"expected_signature_key":pin,"statement":bad})
        )
        .is_err());
    }
}
