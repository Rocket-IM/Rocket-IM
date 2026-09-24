use super::*;

const CLIENT: [u8; 32] = [31; 32];
const ANCHOR: [u8; 32] = [32; 32];

fn request() -> Request {
    Request {
        protocol_version: PROTOCOL.to_owned(),
        scope: Scope {
            service: "service-a".to_owned(),
            account: "account-a".to_owned(),
            device: "device-a".to_owned(),
            identity_key: public_key(&CLIENT),
            store_id: hash_bytes(b"store-a"),
        },
        challenge: hash_bytes(b"challenge-a"),
        action: Action::Reserve,
        expected_revision: "0".to_owned(),
        txn: hash_bytes(b"txn-a"),
        head: "absent".to_owned(),
        target: "absent".to_owned(),
    }
}

fn response(request: &Request, signed: &Signed) -> Response {
    Response {
        closure: None,
        protocol_version: PROTOCOL.to_owned(),
        scope: request.scope.clone(),
        challenge: request.challenge.clone(),
        request_sha256: request_digest(signed).unwrap(),
        action: request.action,
        status: Status::Reserved,
        head: request.head.clone(),
        active_txn: Some(request.txn.clone()),
        revision: "1".to_owned(),
    }
}

#[test]
fn signed_request_and_challenge_bound_response_round_trip() {
    let request = request();
    let signed = sign_request(&request, &CLIENT).unwrap();
    assert_eq!(
        verify_request(&signed, &public_key(&CLIENT)).unwrap(),
        request
    );
    let response = response(&request, &signed);
    let signed_response = sign_response(&response, &ANCHOR).unwrap();
    assert_eq!(
        verify_response(&signed_response, &public_key(&ANCHOR), &signed).unwrap(),
        response
    );
    let mut changed = request;
    changed.challenge = hash_bytes(b"next challenge");
    let next = sign_request(&changed, &CLIENT).unwrap();
    assert_eq!(
        verify_response(&signed_response, &public_key(&ANCHOR), &next)
            .unwrap_err()
            .code,
        "anchor_response_binding"
    );
}

#[test]
fn wrong_key_forgery_and_domain_substitution_fail() {
    let request = request();
    let signed = sign_request(&request, &CLIENT).unwrap();
    assert_eq!(
        verify_request(&signed, &public_key(&ANCHOR))
            .unwrap_err()
            .code,
        "anchor_signature"
    );
    let forged = sign(&request, &CLIENT, RESPONSE_DOMAIN).unwrap();
    assert_eq!(
        verify_request(&forged, &public_key(&CLIENT))
            .unwrap_err()
            .code,
        "anchor_signature"
    );
    let mut forged = signed.clone();
    let mut signature = STANDARD.decode(&forged.signature_bytes).unwrap();
    signature[0] ^= 1;
    forged.signature_bytes = STANDARD.encode(signature);
    assert_eq!(
        verify_request(&forged, &public_key(&CLIENT))
            .unwrap_err()
            .code,
        "anchor_signature"
    );
    let mut changed = request.clone();
    changed.txn = hash_bytes(b"replacement txn");
    forged = signed.clone();
    forged.statement_bytes = STANDARD.encode(serde_json::to_vec(&changed).unwrap());
    assert!(verify_request(&forged, &public_key(&CLIENT)).is_err());
    let response = sign_response(&response(&request, &signed), &ANCHOR).unwrap();
    assert!(verify_request(&response, &public_key(&ANCHOR)).is_err());
}

#[test]
fn every_scope_field_is_bound_to_the_response() {
    let original = request();
    let signed = sign_request(&original, &CLIENT).unwrap();
    let good_response = response(&original, &signed);
    for index in 0..5 {
        let mut changed = good_response.clone();
        match index {
            0 => changed.scope.service.push('b'),
            1 => changed.scope.account.push('b'),
            2 => changed.scope.device.push('b'),
            3 => changed.scope.identity_key = public_key(&ANCHOR),
            _ => changed.scope.store_id = hash_bytes(b"other-store"),
        }
        let wrong = sign_response(&changed, &ANCHOR).unwrap();
        assert_eq!(
            verify_response(&wrong, &public_key(&ANCHOR), &signed)
                .unwrap_err()
                .code,
            "anchor_response_binding"
        );
    }
}

#[test]
fn strict_fields_hex_base64_and_capacity_are_enforced() {
    let original = request();
    for value in [
        "a".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
        "0".repeat(65),
        "é".repeat(32),
    ] {
        assert!(decode_hex(&value).is_err());
    }
    let mut changed = original.clone();
    changed.scope.account = "a".repeat(129);
    assert!(sign_request(&changed, &CLIENT).is_err());
    changed = original.clone();
    changed.protocol_version.push('2');
    assert!(sign_request(&changed, &CLIENT).is_err());
    changed = original.clone();
    changed.target = hash_bytes(b"premature target");
    assert!(sign_request(&changed, &CLIENT).is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    value["unexpected"] = serde_json::json!(true);
    let signed = sign(&value, &CLIENT, REQUEST_DOMAIN).unwrap();
    assert!(verify_request(&signed, &public_key(&CLIENT)).is_err());
    let mut signed = sign_request(&original, &CLIENT).unwrap();
    signed.statement_bytes.push('\n');
    assert!(verify_request(&signed, &public_key(&CLIENT)).is_err());
    signed.statement_bytes = "A".repeat(STATEMENT_LIMIT.div_ceil(3) * 4 + 4);
    assert!(verify_request(&signed, &public_key(&CLIENT)).is_err());
}

#[test]
fn finish_accepts_unchanged_digest_but_never_absent_target() {
    let mut request = request();
    request.action = Action::Finish;
    assert!(request.validate().is_err());
    request.head = hash_bytes(b"unchanged read state");
    request.target = request.head.clone();
    assert!(sign_request(&request, &CLIENT).is_ok());
}

#[test]
fn invalid_revision_and_action_status_are_rejected() {
    let request = request();
    let signed = sign_request(&request, &CLIENT).unwrap();
    let mut response = response(&request, &signed);
    for revision in ["01", "-1", "1.0", "18446744073709551616"] {
        response.revision = revision.to_owned();
        assert!(sign_response(&response, &ANCHOR).is_err());
    }
    response.revision = u64::MAX.to_string();
    assert!(sign_response(&response, &ANCHOR).is_ok());
    response.status = Status::Finished;
    assert!(sign_response(&response, &ANCHOR).is_err());
}
