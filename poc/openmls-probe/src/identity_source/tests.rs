use super::*;
use crate::permission::{receipts::SignedRecord, Member};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
fn doc() -> Document {
    Document::Permit(Permit {
        service_id: "service".into(),
        issuer: "business".into(),
        audience: "im".into(),
        subject: "subject".into(),
        permit_id: "permit".into(),
        target: Member {
            account_id: "alice".into(),
            device_id: "a1".into(),
            signature_key: STANDARD
                .encode(SigningKey::from_bytes(&[2; 32]).verifying_key().as_bytes()),
        },
        challenge_sha256: "0".repeat(64),
        challenge_nonce: STANDARD.encode([3; 32]),
        purpose: "first_device".into(),
        issued_at_ms: "1000".into(),
        expires_at_ms: "301000".into(),
    })
}
#[test]
fn exact_bytes_domain_and_unknown_fields() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let value = doc();
    let raw = serde_json::to_vec(&value).unwrap();
    let mut signed = value.domain().to_vec();
    signed.extend(&raw);
    let record = SignedRecord {
        statement_bytes: STANDARD.encode(&raw),
        signature_bytes: STANDARD.encode(key.sign(&signed).to_bytes()),
    };
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    assert_eq!(verify(&record, &public).unwrap(), value);
    let mut bad = record.clone();
    bad.statement_bytes = STANDARD.encode(serde_json::to_vec_pretty(&value).unwrap());
    assert!(verify(&bad, &public).is_err());
    let mut json = serde_json::to_value(&value).unwrap();
    json["extra"] = true.into();
    bad.statement_bytes = STANDARD.encode(serde_json::to_vec(&json).unwrap());
    assert!(parse(&bad).is_err());
    let mut wrong = b"Rocket-IM/POC/device-registration/v1\0".to_vec();
    wrong.extend(raw);
    bad = record;
    bad.signature_bytes = STANDARD.encode(key.sign(&wrong).to_bytes());
    assert!(verify(&bad, &public).is_err());
}
#[test]
fn fixed_versions_and_bounds() {
    let Document::Permit(mut p) = doc() else {
        panic!()
    };
    p.expires_at_ms = "301001".into();
    assert!(Document::Permit(p.clone()).validate().is_err());
    p.expires_at_ms = "1000".into();
    assert!(Document::Permit(p.clone()).validate().is_err());
    p.expires_at_ms = "001001".into();
    assert!(Document::Permit(p).validate().is_err());
}
