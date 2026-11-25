//! 固定种子只用于公开测试向量；运行签发器仍使用系统随机源。
use super::*;
use crate::{
    device_registration,
    permission::{commit_digest, receipts::SignedRecord, Member},
};
use ed25519_dalek::{Signer, SigningKey};
fn signed(doc: &Document, key: &SigningKey) -> SignedRecord {
    let raw = serde_json::to_vec(doc).unwrap();
    let mut message = doc.domain().to_vec();
    message.extend(&raw);
    SignedRecord {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(key.sign(&message).to_bytes()),
    }
}
fn generated() -> Value {
    let business = SigningKey::from_bytes(&[1; 32]);
    let device = SigningKey::from_bytes(&[2; 32]);
    let service = SigningKey::from_bytes(&[3; 32]);
    let public = |key: &SigningKey| STANDARD.encode(key.verifying_key().as_bytes());
    let member = Member {
        account_id: "alice".into(),
        device_id: "a1".into(),
        signature_key: public(&device),
    };
    let requester = Member {
        account_id: "bob".into(),
        device_id: "b1".into(),
        signature_key: public(&service),
    };
    let roots = Roots {
        service_id: "service".into(),
        issuer: "business".into(),
        audience: "im".into(),
        business_key: public(&business),
        receipt_key: public(&service),
    };
    let challenge = device_registration::Challenge {
        protocol_version: "rim-device-registration-1".into(),
        service_id: "service".into(),
        account_id: "alice".into(),
        device_id: "a1".into(),
        registration_id: "registration".into(),
        signature_key: public(&device),
        purpose: "register_device".into(),
        challenge_nonce: STANDARD.encode([4; 32]),
        issued_at_ms: "1000".into(),
        expires_at_ms: "301000".into(),
    };
    let raw = serde_json::to_vec(&challenge).unwrap();
    let mut bytes = device_registration::SIGNING_DOMAIN.to_vec();
    bytes.extend(&raw);
    let registration = SignedRecord {
        statement_bytes: STANDARD.encode(&raw),
        signature_bytes: STANDARD.encode(device.sign(&bytes).to_bytes()),
    };
    let permit = Document::Permit(Permit {
        service_id: "service".into(),
        issuer: "business".into(),
        audience: "im".into(),
        subject: "subject".into(),
        permit_id: "permit".into(),
        target: member.clone(),
        challenge_sha256: commit_digest(&raw),
        challenge_nonce: challenge.challenge_nonce.clone(),
        purpose: "first_device".into(),
        issued_at_ms: "1000".into(),
        expires_at_ms: "301000".into(),
    });
    let permit_record = signed(&permit, &business);
    let snapshot = Snapshot {
        protocol_version: "rim-authorized-device-directory-1".into(),
        service_id: "service".into(),
        account_id: "alice".into(),
        version: "1".into(),
        previous_sha256: "0".repeat(64),
        devices: vec![Entry {
            registration,
            permit: permit_record.clone(),
            approval: None,
            accepted_at_ms: "2000".into(),
            status: "active".into(),
        }],
    };
    let approval = Document::Approval(Approval {
        service_id: "service".into(),
        approval_id: "approval".into(),
        actor: member.clone(),
        target: Member {
            device_id: "a2".into(),
            ..member.clone()
        },
        permit_sha256: crate::key_package::digest(&permit_record).unwrap(),
        previous_version: "1".into(),
        previous_sha256: directory::hash(&snapshot).unwrap(),
        expires_at_ms: "301000".into(),
    });
    let response = Document::Directory(Response {
        service_id: "service".into(),
        requester: requester.clone(),
        account_id: "alice".into(),
        request_id: "request".into(),
        challenge: "4".repeat(64),
        snapshots: vec![snapshot.clone()],
    });
    let head = Document::Head(Head {
        service_id: "service".into(),
        actor: member,
        requester,
        account_id: "alice".into(),
        request_id: "request".into(),
        challenge: "4".repeat(64),
        version: "1".into(),
        snapshot_sha256: directory::hash(&snapshot).unwrap(),
    });
    let positives=vec![(&permit,&business),(&approval,&device),(&response,&service),(&head,&device)].into_iter().map(|(doc,key)|json!({"document":doc,"domain_base64":STANDARD.encode(doc.domain()),"key":public(key),"proof":signed(doc,key)})).collect::<Vec<_>>();
    let mut bad = signed(&permit, &business);
    bad.signature_bytes = STANDARD.encode([0; 64]);
    let mut unknown = serde_json::to_value(&permit).unwrap();
    unknown["body"]["unknown"] = true.into();
    let raw_unknown = serde_json::to_vec(&unknown).unwrap();
    let mut bytes = permit.domain().to_vec();
    bytes.extend(&raw_unknown);
    let invalid_fields = SignedRecord {
        statement_bytes: STANDARD.encode(raw_unknown),
        signature_bytes: STANDARD.encode(business.sign(&bytes).to_bytes()),
    };
    json!({"format":"rim-identity-source-vectors-1","test_only_seeds":"business=01x32; device=02x32; service=03x32; never runtime keys","roots":roots,"positive":positives,"negative":[{"name":"bad_signature","key":public(&business),"proof":bad},{"name":"wrong_root","key":public(&service),"proof":signed(&permit,&business)},{"name":"unknown_field_even_with_valid_signature","key":public(&business),"proof":invalid_fields}]})
}
#[test]
fn frozen_vectors_and_full_first_directory() {
    let expected = generated();
    if let Ok(path) = std::env::var("RIM_WRITE_IDENTITY_VECTORS") {
        std::fs::write(
            path,
            serde_json::to_string_pretty(&expected).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    let recorded: Value = serde_json::from_str(include_str!(
        "../../../../api/realtime/identity-source-vectors.json"
    ))
    .unwrap();
    assert_eq!(expected, recorded);
    let roots: Roots = serde_json::from_value(recorded["roots"].clone()).unwrap();
    for case in recorded["positive"].as_array().unwrap() {
        let proof: SignedRecord = serde_json::from_value(case["proof"].clone()).unwrap();
        let doc = verify(&proof, case["key"].as_str().unwrap()).unwrap();
        if let Document::Directory(r) = doc {
            directory::verify_chain(&r.snapshots, &roots).unwrap();
        }
    }
    for case in recorded["negative"].as_array().unwrap() {
        let proof: SignedRecord = serde_json::from_value(case["proof"].clone()).unwrap();
        assert!(verify(&proof, case["key"].as_str().unwrap()).is_err());
    }
}
