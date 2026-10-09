use super::*;
use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;

fn fixture() -> (SignatureKeyPair, Challenge) {
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let statement = Challenge {
        protocol_version: "rim-device-registration-1".into(),
        service_id: "service_a".into(),
        account_id: "account_a".into(),
        device_id: "device_a".into(),
        registration_id: "registration_a".into(),
        signature_key: STANDARD.encode(signer.public()),
        purpose: "register_device".into(),
        challenge_nonce: STANDARD.encode([7_u8; 32]),
        issued_at_ms: "1700000000000".into(),
        expires_at_ms: "1700000300000".into(),
    };
    (signer, statement)
}

fn encode(statement: &Challenge) -> String {
    STANDARD.encode(serde_json::to_vec(statement).unwrap())
}

#[test]
fn exact_raw_challenge_and_completed_proof_remain_verifiable() {
    let (signer, statement) = fixture();
    let raw = format!(" \n{}\n ", serde_json::to_string(&statement).unwrap());
    let encoded = STANDARD.encode(raw);
    let proof = sign_challenge(&encoded, &signer).unwrap();
    assert_eq!(proof.statement_bytes, encoded);
    assert_eq!(verify_proof(&proof).unwrap(), statement);
    // 公共校验器不按当前时钟拒绝曾有效的原件；Service 仍检查首次接受期限。
    assert_eq!(verify_proof(&proof).unwrap(), statement);
}

#[test]
fn copied_public_identity_without_private_key_does_not_verify() {
    let (_, statement) = fixture();
    let other = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let raw = serde_json::to_vec(&statement).unwrap();
    let mut message = SIGNING_DOMAIN.to_vec();
    message.extend(&raw);
    let proof = receipts::SignedRecord {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(other.sign(&message).unwrap()),
    };
    assert_eq!(
        verify_proof(&proof).unwrap_err().code,
        "registration_signature"
    );
    assert_eq!(
        sign_challenge(&encode(&statement), &other)
            .unwrap_err()
            .code,
        "registration_signature"
    );
}

#[test]
fn domain_and_context_tampering_cannot_reuse_signature() {
    let (signer, mut statement) = fixture();
    let encoded = encode(&statement);
    let mut proof = sign_challenge(&encoded, &signer).unwrap();
    for (field, value) in [
        ("service_id", "other_service"),
        ("account_id", "other_account"),
        ("device_id", "other_device"),
        ("registration_id", "other_registration"),
    ] {
        let mut changed = serde_json::to_value(&statement).unwrap();
        changed[field] = json!(value);
        proof.statement_bytes = STANDARD.encode(serde_json::to_vec(&changed).unwrap());
        assert_eq!(
            verify_proof(&proof).unwrap_err().code,
            "registration_signature"
        );
    }
    statement.purpose = "send_message".into();
    assert_eq!(
        parse_challenge(&encode(&statement)).unwrap_err().code,
        "registration_invalid"
    );
    proof.statement_bytes = encoded.clone();
    proof.signature_bytes =
        STANDARD.encode(signer.sign(&STANDARD.decode(encoded).unwrap()).unwrap());
    assert_eq!(
        verify_proof(&proof).unwrap_err().code,
        "registration_signature"
    );
}

#[test]
fn nonce_key_period_and_canonical_encoding_are_bounded() {
    let (_, statement) = fixture();
    let mut bad = statement.clone();
    bad.challenge_nonce = STANDARD.encode([7_u8; 31]);
    assert!(parse_challenge(&encode(&bad)).is_err());
    bad = statement.clone();
    bad.signature_key = STANDARD.encode([0_u8; 32]);
    assert!(parse_challenge(&encode(&bad)).is_err());
    for expires in [
        "1700000000000",
        "1699999999999",
        "1700000300001",
        "01700000300000",
        "18446744073709551616",
    ] {
        bad = statement.clone();
        bad.expires_at_ms = expires.into();
        assert!(parse_challenge(&encode(&bad)).is_err());
    }
    let encoded = encode(&statement);
    assert!(parse_challenge(&format!("{encoded}\n")).is_err());
    assert!(parse_challenge(&STANDARD.encode(vec![b' '; STATEMENT_LIMIT + 1])).is_err());
}

#[test]
fn duplicate_unknown_fields_and_invalid_dispatch_are_rejected() {
    let (signer, statement) = fixture();
    let raw = serde_json::to_string(&statement).unwrap();
    let duplicate = raw.replacen('{', "{\"service_id\":\"other\",", 1);
    assert!(parse_challenge(&STANDARD.encode(duplicate)).is_err());
    let mut value = serde_json::to_value(&statement).unwrap();
    value["verified"] = json!(true);
    assert!(parse_challenge(&STANDARD.encode(serde_json::to_vec(&value).unwrap())).is_err());
    let proof = sign_challenge(&encode(&statement), &signer).unwrap();
    let response = crate::permission::execute(
        &json!({"operation":"verify_device_registration","proof":proof}).to_string(),
    )
    .unwrap();
    assert_eq!(
        response["result"]["statement"],
        serde_json::to_value(statement).unwrap()
    );
    assert!(execute(
        &json!({"operation":"verify_device_registration","proof":proof,"directory":"forbidden"})
            .to_string()
    )
    .is_err());
    assert!(execute(&json!({"operation":"send_message","proof":proof}).to_string()).is_err());
}

#[test]
fn copied_public_material_cannot_decrypt_captured_ciphertext_at_the_same_epoch() {
    use openmls::framing::errors::MessageDecryptionError;
    use openmls::prelude::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    let alice = OpenMlsRustCrypto::default();
    let bob = OpenMlsRustCrypto::default();
    let attacker = OpenMlsRustCrypto::default();
    let (alice_identity, alice_signer) = crate::identity(b"public-alice-id", &alice).unwrap();
    let (bob_identity, bob_signer) = crate::identity(b"public-bob-id", &bob).unwrap();
    let bob_package = crate::key_package(bob_identity, &bob_signer, &bob).unwrap();
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(crate::CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut real = MlsGroup::new(&alice, &alice_signer, &config, alice_identity).unwrap();
    let (_, welcome, _) = real
        .add_members(&alice, &alice_signer, &[bob_package.key_package().clone()])
        .unwrap();
    real.merge_pending_commit(&alice).unwrap();
    let mut receiver =
        crate::join(&bob, config.join_config(), &welcome.to_bytes().unwrap()).unwrap();
    let payload = b"synthetic-captured-history-message";
    let ciphertext = real
        .create_message(&alice, &alice_signer, payload)
        .unwrap()
        .to_bytes()
        .unwrap();
    crate::receive_application(&mut receiver, &bob, &ciphertext, payload).unwrap();

    // 攻击者复制公开身份名称、群ID和Bob公开KeyPackage，仍没有原设备或群秘密。
    // 对照主动达到同一epoch，避免用WrongEpoch或业务访问拒绝冒充解密失败。
    let (copy_identity, copy_signer) = crate::identity(b"public-alice-id", &attacker).unwrap();
    let mut copy = MlsGroup::new_with_group_id(
        &attacker,
        &copy_signer,
        &config,
        real.group_id().clone(),
        copy_identity,
    )
    .unwrap();
    copy.add_members(
        &attacker,
        &copy_signer,
        &[bob_package.key_package().clone()],
    )
    .unwrap();
    copy.merge_pending_commit(&attacker).unwrap();
    assert_eq!(copy.group_id(), real.group_id());
    assert_eq!(copy.epoch(), real.epoch());
    let error = copy
        .process_message(&attacker, crate::protocol_message(&ciphertext).unwrap())
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::AeadError
        ))
    ));
}
