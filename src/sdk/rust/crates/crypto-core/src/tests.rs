use super::*;

fn device(service: &str, account: &str, name: &str) -> Device {
    Device::new(service.into(), account.into(), name.into()).unwrap()
}

fn offer(a: &mut Device, b: &Device, conversation: &str) -> Vec<u8> {
    a.create_group(
        conversation.into(),
        "B".into(),
        "B1".into(),
        b.identity_key().unwrap(),
        b.key_package().unwrap(),
    )
    .unwrap()
}

fn pair(conversation: &str) -> (Device, Device) {
    let mut a = device("S1", "A", "A1");
    let mut b = device("S1", "B", "B1");
    let welcome = offer(&mut a, &b, conversation);
    b.join_group(
        conversation.into(),
        "A".into(),
        "A1".into(),
        a.identity_key().unwrap(),
        welcome,
    )
    .unwrap();
    (a, b)
}

fn code<T>(result: Result<T>, expected: ErrorCode, poisoned: bool) {
    match result {
        Ok(_) => panic!("expected fixed SDK error"),
        Err(error) => assert_eq!(
            error,
            Error {
                code: expected,
                device_poisoned: poisoned
            }
        ),
    }
}

#[test]
fn identities_are_independent_and_key_package_has_one_stable_active_value() {
    let a = device("S1", "A", "A1");
    let another = device("S1", "A", "A1");
    assert_eq!(a.identity_key().unwrap().len(), 32);
    assert_ne!(a.identity_key().unwrap(), another.identity_key().unwrap());
    assert_eq!(a.key_package().unwrap(), a.key_package().unwrap());
    assert!(a.key_package().unwrap().len() <= MAX_PROTOCOL_BYTES);
    for invalid in ["", "has space", "用户", "a:b"] {
        code(
            Device::new(invalid.into(), "A".into(), "A1".into()),
            ErrorCode::InvalidArgument,
            false,
        );
    }
    code(
        Device::new("x".repeat(65), "A".into(), "A1".into()),
        ErrorCode::InvalidArgument,
        false,
    );
    Device::new("x".repeat(64), "A".into(), "A1".into()).unwrap();
}

#[test]
fn actual_two_device_protocol_roundtrips_binary_utf8_and_maximum_payload() {
    let (mut a, mut b) = pair("G1");
    for plaintext in [
        vec![0, 1, 255, 0],
        "跨端发布验证".as_bytes().to_vec(),
        vec![7; MAX_MESSAGE_BYTES],
    ] {
        let ciphertext = a.encrypt(plaintext.clone()).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(b.decrypt(ciphertext).unwrap(), plaintext);
    }
    let response = b.encrypt(b"return from B".to_vec()).unwrap();
    assert_eq!(a.decrypt(response).unwrap(), b"return from B");
}

#[test]
fn create_rejects_wrong_key_identity_and_service_before_mutating_state() {
    let mut a = device("S1", "A", "A1");
    let b = device("S1", "B", "B1");
    let b_other_service = device("S2", "B", "B1");
    let key = a.identity_key().unwrap();
    let package = a.key_package().unwrap();
    for (account, peer_key, peer_package) in [
        ("C", b.identity_key().unwrap(), b.key_package().unwrap()),
        (
            "B",
            b_other_service.identity_key().unwrap(),
            b.key_package().unwrap(),
        ),
        (
            "B",
            b_other_service.identity_key().unwrap(),
            b_other_service.key_package().unwrap(),
        ),
    ] {
        code(
            a.create_group(
                "G1".into(),
                account.into(),
                "B1".into(),
                peer_key,
                peer_package,
            ),
            ErrorCode::IdentityMismatch,
            false,
        );
        assert_eq!(a.identity_key().unwrap(), key);
        assert_eq!(a.key_package().unwrap(), package);
    }
    code(
        a.create_group(
            "G1".into(),
            "B".into(),
            "B1".into(),
            b.identity_key().unwrap(),
            vec![0; 40],
        ),
        ErrorCode::InvalidEncoding,
        false,
    );
    offer(&mut a, &b, "G1");
    code(a.key_package(), ErrorCode::AlreadyGrouped, false);
}

#[test]
fn missing_group_existing_group_and_invalid_payload_keep_valid_state() {
    let mut fresh = device("S1", "A", "A1");
    code(fresh.encrypt(vec![1]), ErrorCode::GroupRequired, false);
    code(fresh.decrypt(vec![1]), ErrorCode::GroupRequired, false);
    assert!(fresh.key_package().is_ok());
    let (mut a, mut b) = pair("G1");
    code(a.encrypt(Vec::new()), ErrorCode::InvalidArgument, false);
    code(
        a.encrypt(vec![1; MAX_MESSAGE_BYTES + 1]),
        ErrorCode::LimitExceeded,
        false,
    );
    code(
        a.create_group(
            "G2".into(),
            "B".into(),
            "B1".into(),
            b.identity_key().unwrap(),
            vec![1],
        ),
        ErrorCode::AlreadyGrouped,
        false,
    );
    code(
        b.join_group(
            "G1".into(),
            "A".into(),
            "A1".into(),
            a.identity_key().unwrap(),
            vec![1],
        ),
        ErrorCode::AlreadyGrouped,
        false,
    );
    assert_eq!(b.decrypt(a.encrypt(vec![9]).unwrap()).unwrap(), vec![9]);
}

#[test]
fn welcome_encoding_failure_preserves_key_package_but_wrong_creator_poison_closes() {
    let mut a = device("S1", "A", "A1");
    let mut b = device("S1", "B", "B1");
    let package = b.key_package().unwrap();
    let welcome = offer(&mut a, &b, "G1");
    code(
        b.join_group(
            "G1".into(),
            "A".into(),
            "A1".into(),
            a.identity_key().unwrap(),
            vec![0, 1, 2],
        ),
        ErrorCode::InvalidEncoding,
        false,
    );
    assert_eq!(b.key_package().unwrap(), package);
    let wrong = device("S1", "C", "C1");
    code(
        b.join_group(
            "G1".into(),
            "A".into(),
            "A1".into(),
            wrong.identity_key().unwrap(),
            welcome,
        ),
        ErrorCode::IdentityMismatch,
        true,
    );
    code(b.identity_key(), ErrorCode::Poisoned, true);
    code(b.key_package(), ErrorCode::Poisoned, true);
    b.close().unwrap();
    b.close().unwrap();
    code(b.identity_key(), ErrorCode::Closed, false);
}

#[test]
fn welcome_wrong_conversation_is_explicit_fatal_scope_error() {
    let mut a = device("S1", "A", "A1");
    let mut b = device("S1", "B", "B1");
    let welcome = offer(&mut a, &b, "G1");
    code(
        b.join_group(
            "G2".into(),
            "A".into(),
            "A1".into(),
            a.identity_key().unwrap(),
            welcome,
        ),
        ErrorCode::ScopeMismatch,
        true,
    );
    code(b.encrypt(vec![1]), ErrorCode::Poisoned, true);
}

#[test]
fn malformed_or_other_group_ciphertext_does_not_consume_receive_state() {
    let (mut a, mut b) = pair("G1");
    let (mut other, _) = pair("G2");
    code(b.decrypt(vec![1, 2, 3]), ErrorCode::InvalidEncoding, false);
    code(
        b.decrypt(vec![0; MAX_PROTOCOL_BYTES + 1]),
        ErrorCode::LimitExceeded,
        false,
    );
    code(
        b.decrypt(other.encrypt(vec![9]).unwrap()),
        ErrorCode::ScopeMismatch,
        false,
    );
    assert_eq!(
        b.decrypt(a.encrypt(b"still valid".to_vec()).unwrap())
            .unwrap(),
        b"still valid"
    );
}

#[test]
fn tamper_and_duplicate_fail_closed_after_protocol_processing() {
    let (mut a, mut b) = pair("G1");
    let mut ciphertext = a.encrypt(vec![2; 100]).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    code(b.decrypt(ciphertext), ErrorCode::CryptoFailure, true);
    code(
        b.decrypt(a.encrypt(vec![3]).unwrap()),
        ErrorCode::Poisoned,
        true,
    );
    let (mut a, mut b) = pair("G2");
    let ciphertext = a.encrypt(vec![4]).unwrap();
    assert_eq!(b.decrypt(ciphertext.clone()).unwrap(), vec![4]);
    code(b.decrypt(ciphertext), ErrorCode::CryptoFailure, true);
    code(b.key_package(), ErrorCode::Poisoned, true);
}

#[test]
fn close_is_idempotent_and_does_not_change_another_instance() {
    let mut a = device("S1", "A", "A1");
    let b = device("S1", "B", "B1");
    let before = b.identity_key().unwrap();
    a.close().unwrap();
    a.close().unwrap();
    code(a.identity_key(), ErrorCode::Closed, false);
    code(a.key_package(), ErrorCode::Closed, false);
    code(a.encrypt(vec![1]), ErrorCode::Closed, false);
    code(a.decrypt(vec![1]), ErrorCode::Closed, false);
    assert_eq!(b.identity_key().unwrap(), before);
}
