use super::*;
#[path = "test_fixture.rs"]
mod fixture;
use fixture::*;

#[test]
fn valid_registration_dispatch_preserves_exact_successor_and_large_permission_version() {
    let (trusted, registration) = fixture();
    let request = verify_registration(&trusted, &registration).unwrap();
    assert_eq!(request.successor_scope, registration.plan.successor_scope);
    assert_eq!(request.initial_cursor, "0");
    let result = permission::execute(
        &json!({"operation":"verify_rebuild_stream",
        "trusted":trusted,"registration":registration})
        .to_string(),
    )
    .unwrap();
    assert_eq!(
        result["result"]["request"],
        serde_json::to_value(request).unwrap()
    );
    assert_eq!(
        result["result"]["request_sha256"],
        request_digest(&registration.request).unwrap()
    );
}

#[test]
fn registration_rejects_supplied_trust_rebinding_even_with_valid_original_signatures() {
    let (trusted, registration) = fixture();
    for variant in 0..4 {
        let mut wrong = trusted.clone();
        match variant {
            0 => wrong.old_scope.store_id = anchor::hash_bytes(b"other old store"),
            1 => wrong.anchor_public_key = anchor::public_key(&[89; 32]),
            2 => wrong.trust.relay_receipt_key = public(&[90; 32]),
            _ => wrong.trust.checkpoint.crypto_state_ref = anchor::hash_bytes(b"other checkpoint"),
        }
        assert_eq!(
            verify_registration(&wrong, &registration).unwrap_err().code,
            "rebuild_stream_denied"
        );
    }
}

#[test]
fn registration_rejects_cancelled_unlinked_or_cross_request_anchor_facts() {
    let (trusted, registration) = fixture();
    let original: rebuild::Response = serde_json::from_slice(
        &STANDARD
            .decode(&registration.anchor_response.statement_bytes)
            .unwrap(),
    )
    .unwrap();
    for variant in 0..4 {
        let mut changed = registration.clone();
        let mut response = original.clone();
        match variant {
            0 => {
                response.status = rebuild::Status::Duplicate;
                response.cancelled = true;
            }
            1 => response.status = rebuild::Status::Unlinked,
            2 => response.request_sha256 = anchor::hash_bytes(b"other request"),
            _ => response.challenge = anchor::hash_bytes(b"other challenge"),
        }
        changed.anchor_response = anchor_response(&response);
        assert!(
            verify_registration(&trusted, &changed).is_err(),
            "variant {variant}"
        );
    }
    let mut duplicate = registration.clone();
    let mut response = original;
    response.status = rebuild::Status::Duplicate;
    duplicate.anchor_response = anchor_response(&response);
    verify_registration(&trusted, &duplicate).unwrap();
}

#[test]
fn registration_requires_exact_add_device_key_package_and_accepted_service_receipt() {
    let (trusted, registration) = fixture();
    for variant in 0..7 {
        let mut changed = registration.clone();
        let mut statement: permission::Statement = serde_json::from_slice(
            &STANDARD
                .decode(&changed.join_record.change.statement_bytes)
                .unwrap(),
        )
        .unwrap();
        match variant {
            0 => {
                if let permission::Action::AddDevice {
                    key_package_sha256, ..
                } = &mut statement.action
                {
                    *key_package_sha256 = anchor::hash_bytes(b"wrong package");
                }
            }
            1 => {
                if let permission::Action::AddDevice { member, .. } = &mut statement.action {
                    member.signature_key = public(&[91; 32]);
                }
            }
            2 => {
                if let permission::Action::AddDevice { member, .. } = &mut statement.action {
                    member.device_id = "A4".into();
                }
            }
            3 => {
                if let permission::Action::AddDevice { history_policy, .. } = &mut statement.action
                {
                    *history_policy = "all_history".into();
                }
            }
            4 => statement.from_state_ref = anchor::hash_bytes(b"other predecessor"),
            5 => statement.actor.device_id = "A9".into(),
            _ => {
                changed.approval = rebuild::sign_approval(&changed.plan, &[92; 32]).unwrap();
            }
        }
        replace_join(&mut changed, &statement);
        assert!(
            verify_registration(&trusted, &changed).is_err(),
            "variant {variant}"
        );
    }
    let mut closed = registration.clone();
    let mut receipt: receipts::ReceiptStatement = decoded(&closed.join_record.receipt);
    receipt.outcome = receipts::Outcome::Closed;
    closed.join_record.receipt = signed(&receipt, receipts::RECEIPT_DOMAIN, &SERVICE);
    assert_eq!(
        verify_registration(&trusted, &closed).unwrap_err().code,
        "rebuild_stream_denied"
    );
    closed.join_record.receipt = signed(&receipt, receipts::RECEIPT_DOMAIN, &[93; 32]);
    assert!(verify_registration(&trusted, &closed).is_err());
}

#[test]
fn request_signature_binds_raw_bytes_domain_scope_and_initial_cursor() {
    let (trusted, registration) = fixture();
    let original: RequestStatement = decoded(&registration.request);
    for variant in 0..6 {
        let mut changed = registration.clone();
        let mut request = original.clone();
        match variant {
            0 => request.initial_cursor = "1".into(),
            1 => request.successor_scope.store_id = anchor::hash_bytes(b"other store"),
            2 => request.conversation_id = "G1".into(),
            3 => request.plan_sha256 = anchor::hash_bytes(b"other plan"),
            4 => request.join_proof_sha256 = anchor::hash_bytes(b"other join"),
            _ => request.successor_scope.identity_key = anchor::public_key(&[94; 32]),
        }
        changed.request = signed(&request, REQUEST_DOMAIN, &SUCCESSOR);
        assert!(
            verify_registration(&trusted, &changed).is_err(),
            "variant {variant}"
        );
    }
    let mut wrong_domain = registration.clone();
    wrong_domain.request = signed(&original, PULL_DOMAIN, &SUCCESSOR);
    assert_eq!(
        verify_registration(&trusted, &wrong_domain)
            .unwrap_err()
            .code,
        "rebuild_stream_signature"
    );
    let mut whitespace = registration.clone();
    let mut raw = b" ".to_vec();
    raw.extend(
        STANDARD
            .decode(&whitespace.request.statement_bytes)
            .unwrap(),
    );
    whitespace.request.statement_bytes = STANDARD.encode(raw);
    assert_eq!(
        verify_registration(&trusted, &whitespace).unwrap_err().code,
        "rebuild_stream_signature"
    );
    assert_ne!(
        request_digest(&whitespace.request).unwrap(),
        request_digest(&registration.request).unwrap()
    );
}

#[test]
fn signed_digest_rejects_short_signatures_and_oversized_or_noncanonical_base64() {
    let (_, registration) = fixture();
    for variant in 0..3 {
        let mut record = registration.request.clone();
        match variant {
            0 => record.signature_bytes = STANDARD.encode([1; 63]),
            1 => record.statement_bytes = STANDARD.encode(vec![b'a'; STATEMENT_LIMIT + 1]),
            _ => record.signature_bytes.push('\n'),
        }
        assert!(signed_digest(&record).is_err());
    }
    let record = SignedRecord {
        statement_bytes: STANDARD.encode(b"{\"x\":1}"),
        signature_bytes: STANDARD.encode([1; 64]),
    };
    assert_eq!(
        signed_digest(&record).unwrap(),
        "cdb8c979d86e1d76a250839cd11844179c69b00f923629145198d0d2891cabf7"
    );
}

#[test]
fn pull_requires_exact_binding_identity_and_canonical_pagination() {
    let (_, registration) = fixture();
    let binding = binding(&registration);
    let original = pull(&binding);
    let request = signed(&original, PULL_DOMAIN, &SUCCESSOR);
    assert_eq!(
        verify_pull(&binding, &request).unwrap().after_seq,
        "9007199254740993"
    );
    let result = permission::execute(
        &json!({"operation":"verify_rebuild_pull","binding":binding,"request":request}).to_string(),
    )
    .unwrap();
    assert_eq!(
        result["result"]["request_sha256"],
        signed_digest(&request).unwrap()
    );
    for variant in 0..9 {
        let mut changed = original.clone();
        match variant {
            0 => changed.stream_id = anchor::hash_bytes(b"old stream"),
            1 => changed.conversation_id = "G1".into(),
            2 => changed.successor_scope.device = "A1".into(),
            3 => changed.service_id = "S2".into(),
            4 => changed.after_seq = "01".into(),
            5 => changed.after_seq = "18446744073709551616".into(),
            6 => changed.limit = "0".into(),
            7 => changed.limit = "101".into(),
            _ => changed.challenge = "A".repeat(64),
        }
        assert!(
            verify_pull(&binding, &signed(&changed, PULL_DOMAIN, &SUCCESSOR)).is_err(),
            "variant {variant}"
        );
    }
    assert_eq!(
        verify_pull(&binding, &signed(&original, REQUEST_DOMAIN, &SUCCESSOR))
            .unwrap_err()
            .code,
        "rebuild_stream_signature"
    );
    assert_eq!(
        verify_pull(&binding, &signed(&original, PULL_DOMAIN, &AUTHOR))
            .unwrap_err()
            .code,
        "rebuild_stream_signature"
    );
}

#[test]
fn service_binding_and_page_signatures_reject_wrong_key_domain_and_added_fields() {
    let (_, registration) = fixture();
    let binding = binding(&registration);
    let signed_binding = signed(&binding, BINDING_DOMAIN, &SERVICE);
    assert_eq!(
        verify_binding(&public(&SERVICE), &signed_binding).unwrap(),
        binding
    );
    assert!(verify_binding(&public(&AUTHOR), &signed_binding).is_err());
    let pull = pull(&binding);
    let page = page(&pull, &signed(&pull, PULL_DOMAIN, &SUCCESSOR));
    let receipt = signed(&page, PAGE_DOMAIN, &SERVICE);
    assert_eq!(verify_page(&public(&SERVICE), &receipt).unwrap(), page);
    assert!(verify_page(&public(&SERVICE), &signed(&page, BINDING_DOMAIN, &SERVICE)).is_err());
    let mut extra = serde_json::to_value(&page).unwrap();
    extra["events"] = json!([]);
    assert!(verify_page(&public(&SERVICE), &signed(&extra, PAGE_DOMAIN, &SERVICE)).is_err());
    let mut invalid = binding.clone();
    invalid.initial_cursor = "1".into();
    assert!(verify_binding(
        &public(&SERVICE),
        &signed(&invalid, BINDING_DOMAIN, &SERVICE)
    )
    .is_err());
}

#[test]
fn service_signer_accepts_only_typed_binding_and_page_protocols() {
    let mut random = [0; 16];
    getrandom::getrandom(&mut random).unwrap();
    let path =
        std::env::temp_dir().join(format!("rim-stream-sign-{}", anchor::encode_hex(&random)));
    let init =
        crate::relay_receipt::execute(&json!({"operation":"init","key_path":path}).to_string())
            .unwrap();
    let pin = init["result"]["signature_key"].as_str().unwrap();
    let (_, registration) = fixture();
    let binding = binding(&registration);
    let pull = pull(&binding);
    let page = page(&pull, &signed(&pull, PULL_DOMAIN, &SUCCESSOR));
    for statement in [
        serde_json::to_value(&binding).unwrap(),
        serde_json::to_value(&page).unwrap(),
    ] {
        let request = json!({"operation":"sign","key_path":path,"expected_signature_key":pin,"statement":statement});
        let result = crate::relay_receipt::execute(&request.to_string()).unwrap();
        let receipt: SignedRecord =
            serde_json::from_value(result["result"]["receipt"].clone()).unwrap();
        if statement["protocol_version"] == "rim-rebuild-stream-binding-1" {
            assert_eq!(verify_binding(pin, &receipt).unwrap(), binding);
        } else {
            assert_eq!(verify_page(pin, &receipt).unwrap(), page);
        }
        let mut arbitrary = request.clone();
        arbitrary["statement"]["protocol_version"] = json!("arbitrary");
        assert!(crate::relay_receipt::execute(&arbitrary.to_string()).is_err());
        let mut extra = request;
        extra["statement"]["extra"] = json!(true);
        assert!(crate::relay_receipt::execute(&extra.to_string()).is_err());
    }
    let request: RequestStatement = decoded(&registration.request);
    assert!(crate::relay_receipt::execute(
        &json!({"operation":"sign","key_path":path,
        "expected_signature_key":pin,"statement":request})
        .to_string()
    )
    .is_err());
    std::fs::remove_file(path).unwrap();
}
