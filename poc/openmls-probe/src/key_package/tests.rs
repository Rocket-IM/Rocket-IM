//! 固定公开种子仅用于协议向量；运行装置始终生成独立随机身份。
use super::*;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};

#[test]
fn key_package_vectors() {
    let key = SigningKey::from_bytes(&std::array::from_fn(|i| i as u8));
    let request = Request {
        protocol_version: "rim-key-package-request-1".into(),
        service_id: "vector-service".into(),
        request_id: "directory-1".into(),
        actor: Member {
            account_id: "alice".into(),
            device_id: "a1".into(),
            signature_key: STANDARD.encode(key.verifying_key().as_bytes()),
        },
        action: Action::Directory {
            account_id: "alice".into(),
            challenge: "01".repeat(32),
        },
    };
    let raw = serde_json::to_vec(&request).unwrap();
    let mut bytes = REQUEST_DOMAIN.to_vec();
    bytes.extend(&raw);
    let proof = SignedRecord {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(key.sign(&bytes).to_bytes()),
    };
    assert_eq!(parse(&proof).unwrap(), request);
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../api/realtime/key-package-vectors.json"
    ))
    .unwrap();
    assert_eq!(vectors["positive"].as_array().unwrap().len(), 1);
    if let Some(saved) = vectors["positive"].as_array().unwrap().first() {
        assert_eq!(saved["proof"], json!(proof));
        assert_eq!(saved["proof_sha256"], digest(&proof).unwrap());
    }
    println!(
        "KEY_PACKAGE_VECTOR={}",
        json!({"name":"signed-directory-challenge","request":request,"proof":proof,"proof_sha256":digest(&proof).unwrap()})
    );
    for vector in vectors["negative"].as_array().unwrap() {
        let mut modified = json!(request);
        for (path, value) in vector["mutation"].as_object().unwrap() {
            let parts: Vec<_> = path.split('.').collect();
            if parts.len() == 1 {
                modified[parts[0]] = value.clone();
            } else {
                modified[parts[0]][parts[1]] = value.clone();
            }
        }
        let raw = serde_json::to_vec(&modified).unwrap();
        let bad = SignedRecord {
            statement_bytes: STANDARD.encode(&raw),
            signature_bytes: proof.signature_bytes.clone(),
        };
        assert!(parse(&bad).is_err(), "{}", vector["name"]);
    }
    for v in vectors["lifetime_vectors"].as_array().unwrap() {
        let material = material::Material {
            key_package_sha256: "0".repeat(64),
            key_package_ref: "unused".into(),
            init_key: "unused".into(),
            leaf_key: "unused".into(),
            suite: "1".into(),
            not_before: v["not_before"].as_str().unwrap().into(),
            not_after: v["not_after"].as_str().unwrap().into(),
        };
        let lifetime = openmls::prelude::Lifetime::init(
            material.not_before.parse().unwrap(),
            material.not_after.parse().unwrap(),
        );
        assert_eq!(
            lifetime
                .validate_with_time(
                    std::time::UNIX_EPOCH
                        + std::time::Duration::from_secs(
                            v["now"].as_str().unwrap().parse().unwrap()
                        )
                )
                .is_ok(),
            v["accepted"].as_bool().unwrap()
        );
        assert_eq!(
            material::current(&material, v["now"].as_str().unwrap().parse().unwrap()).is_ok(),
            v["accepted"].as_bool().unwrap()
        );
    }
}
