use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};

fn statement() -> PageStatement {
    PageStatement {
        protocol_version: "RIM-STREAM-PAGE-POC-1".into(),
        service_id: "S1".into(),
        account_id: "A".into(),
        device_id: "A1".into(),
        stream_id: "stream1".into(),
        after_seq: "9007199254740993".into(),
        limit: "100".into(),
        page_sha256: "a".repeat(64),
    }
}

fn sign(raw: &[u8], domain: &[u8]) -> (String, SignedRecord) {
    let key = SigningKey::from_bytes(&[69; 32]);
    let mut message = domain.to_vec();
    message.extend(raw);
    (
        STANDARD.encode(key.verifying_key().as_bytes()),
        SignedRecord {
            statement_bytes: STANDARD.encode(raw),
            signature_bytes: STANDARD.encode(key.sign(&message).to_bytes()),
        },
    )
}

#[test]
fn original_statement_bytes_and_domain_are_required() {
    let statement = statement();
    let raw = serde_json::to_vec_pretty(&statement).unwrap();
    let (key, receipt) = sign(&raw, SIGNING_DOMAIN);
    assert_eq!(verify(&key, &receipt).unwrap(), statement);
    let mut reserialized = receipt.clone();
    reserialized.statement_bytes = STANDARD.encode(serde_json::to_vec(&statement).unwrap());
    assert_eq!(
        verify(&key, &reserialized).unwrap_err().code,
        "stream_page_signature"
    );
    let (key, wrong_domain) = sign(&raw, crate::rebuild_stream::PAGE_DOMAIN);
    assert_eq!(
        verify(&key, &wrong_domain).unwrap_err().code,
        "stream_page_signature"
    );
}

#[test]
fn duplicate_and_unknown_fields_and_large_ids_do_not_parse() {
    let original = serde_json::to_string(&statement()).unwrap();
    for raw in [
        original.replacen('{', "{\"service_id\":\"S1\",", 1),
        original.replacen('{', "{\"extra\":true,", 1),
    ] {
        let (key, receipt) = sign(raw.as_bytes(), SIGNING_DOMAIN);
        assert_eq!(
            verify(&key, &receipt).unwrap_err().code,
            "stream_page_invalid"
        );
    }
    let mut bad = statement();
    bad.account_id = "a".repeat(65);
    let (key, receipt) = sign(&serde_json::to_vec(&bad).unwrap(), SIGNING_DOMAIN);
    assert_eq!(
        verify(&key, &receipt).unwrap_err().code,
        "stream_page_invalid"
    );
}
