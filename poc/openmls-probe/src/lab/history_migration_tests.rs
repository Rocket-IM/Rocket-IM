//! 真正接收的历史副本、独立HPKE通道及快照原子性。
use super::*;
use crate::{
    history_transfer as public,
    lab::{history_state, state::DeviceState, CrashPoint},
    permission::receipts::SignedRecord,
};
use ed25519_dalek::Signer;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

#[path = "sent_history_tests.rs"]
mod sent_history_tests;

fn mutate(f: &Fixture, device: &str, action: impl FnOnce(&mut DeviceState)) {
    let locked = LockedDevice::open(&f.root.join(device)).unwrap();
    let mut state = locked
        .load(&Context {
            service: "S1".into(),
            account: if device.starts_with('B') {
                "B".into()
            } else {
                device.into()
            },
            device: device.into(),
        })
        .unwrap()
        .unwrap();
    action(&mut state);
    locked.save(&mut state, CrashPoint::None).unwrap();
}
fn acceptance(key: &SigningKey, envelope: &Value, id: &str) -> SignedRecord {
    let raw = codec::decode(envelope["header_bytes"].as_str().unwrap()).unwrap();
    let payload = codec::decode(envelope["payload_bytes"].as_str().unwrap()).unwrap();
    let header: crate::lab::wire_types::Header = serde_json::from_slice(&raw).unwrap();
    signed(
        key,
        crate::message_acceptance::SIGNING_DOMAIN,
        &json!({"protocol_version":"rim-message-acceptance-1","service_id":header.service_id,"conversation_id":header.conversation_id,"acceptance_id":id,
        "envelope_sha256":crate::message_acceptance::envelope_digest(&raw,&payload),"authorization_version":header.authorization_version,"crypto_state_ref":header.crypto_state_ref}),
    )
}
fn signed(key: &SigningKey, domain: &[u8], body: &Value) -> SignedRecord {
    let raw = serde_json::to_vec(body).unwrap();
    let mut bytes = domain.to_vec();
    bytes.extend(&raw);
    SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(&key.sign(&bytes).to_bytes()),
    }
}
fn receive_copy(f: &Fixture, key: &SigningKey, id: &str, payload: &str) -> Value {
    let envelope=call(f,"A",json!({"operation":"wire_send","logical_message_id":id,"attempt_id":"P1","payload":payload}))["envelope"].clone();
    call(
        f,
        "A",
        json!({"operation":"wire_accept","logical_message_id":id,"attempt_id":"P1",
        "acceptance_receipt":acceptance(key,&envelope,id)}),
    );
    call(
        f,
        "B",
        json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"],"acceptance_id":id,"acceptance_receipt":acceptance(key,&envelope,id)}),
    );
    envelope
}
fn fixture() -> (Fixture, SigningKey) {
    let (f, key) = setup();
    receive_copy(&f, &key, "old1", "第一条选定历史");
    receive_copy(&f, &key, "old2", "second selected history");
    let b2 = init(&f, &key, "B2");
    let prepared = prepare(&f, "B", &b2, "addB2");
    accept(&f, &key, &prepared, &["A", "B", "C"]);
    join(&f, &key, "B2", &prepared);
    (f, key)
}
fn select(f: &Fixture, ids: &[&str]) -> Value {
    let refs = call(f, "B", json!({"operation":"history_inspect"}))["exportable"].clone();
    json!(refs
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| ids.contains(&r["acceptance_id"].as_str().unwrap()))
        .collect::<Vec<_>>())
}
fn begin(f: &Fixture, id: &str, selection: Value) -> SignedRecord {
    serde_json::from_value(call(f,"B2",json!({"operation":"history_request","transfer_id":id,"source":{"account_id":"B","device_id":"B"},"selection":selection}))["request"].clone()).unwrap()
}
fn export(f: &Fixture, request: &SignedRecord) -> public::Package {
    serde_json::from_value(
        call(
            f,
            "B",
            json!({"operation":"history_export","request":request}),
        )["package"]
            .clone(),
    )
    .unwrap()
}
fn service_receipt(
    key: &SigningKey,
    request: &SignedRecord,
    package: &public::Package,
) -> SignedRecord {
    let s: public::RequestStatement =
        serde_json::from_slice(&codec::decode(&request.statement_bytes).unwrap()).unwrap();
    signed(
        key,
        public::RECEIPT_DOMAIN,
        &json!({"protocol_version":"rim-history-receipt-1","service_id":s.service_id,"conversation_id":s.conversation_id,"transfer_id":s.transfer_id,
        "request_sha256":public::request_digest(request).unwrap(),"package_sha256":public::package_digest(package).unwrap(),"authorization_version":s.authorization_version,"crypto_state_ref":s.crypto_state_ref,
        "accepted_at_unix_ms":(history_state::now().unwrap()*1000).to_string(),"expires_at_unix_secs":s.expires_at_unix_secs}),
    )
}
fn import_op(key: &SigningKey, request: &SignedRecord, package: &public::Package) -> Value {
    json!({"operation":"history_import","request":request,"package":package,"receipt":service_receipt(key,request,package)})
}
fn future_state(f: &Fixture, device: &str) -> Value {
    let mut result = Value::Null;
    mutate(
        f,
        device,
        |s| result = json!({"provider":crate::lab::permission_state::entries(&s.provider).unwrap(),"wire":s.wire,"sync":s.wire_sync,"permissions":s.permissions,"roster":s.roster}),
    );
    result
}

#[test]
fn migration_uses_selected_received_copies_and_preserves_future_state_across_restart() {
    let (f, key) = fixture();
    let request = begin(&f, "T1", select(&f, &["old1"]));
    assert_eq!(begin(&f, "T1", select(&f, &["old1"])), request);
    let package = export(&f, &request);
    assert_eq!(export(&f, &request), package);
    let before = future_state(&f, "B2");
    let op = import_op(&key, &request, &package);
    assert_eq!(call(&f, "B2", op.clone())["imported_count"], 1);
    assert_eq!(call(&f, "B2", op)["imported_count"], 0);
    assert_eq!(future_state(&f, "B2"), before);
    mutate(&f, "B2", |s| {
        assert!(s.history_transfers.requests["T1"].private_key.is_none())
    });
    let request = begin(&f, "T2", select(&f, &["old1", "old2"]));
    let package = export(&f, &request);
    assert_eq!(
        call(&f, "B2", import_op(&key, &request, &package))["imported_count"],
        1
    );
    let inspect = call(&f, "B2", json!({"operation":"history_inspect"}));
    assert_eq!(inspect["imported_count"], 2);
    assert_eq!(inspect["exportable"], json!([]));
    assert_eq!(
        inspect["copies"][0]["provenance"],
        "source_authenticated_copy"
    );
    let sent = send(&f, "B2", "afterMigration");
    f.receive("A", &sent["envelope"]);
}

#[test]
fn legacy_content_is_not_invented_and_receipt_backfill_never_redecrypts() {
    let (f, key) = fixture();
    let envelope = send(&f, "A", "bare")["envelope"].clone();
    call(
        &f,
        "B",
        json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"]}),
    );
    assert_eq!(
        call(&f, "B", json!({"operation":"history_inspect"}))["missing_receipt_count"],
        1
    );
    let raw = codec::decode(envelope["header_bytes"].as_str().unwrap()).unwrap();
    let payload = codec::decode(envelope["payload_bytes"].as_str().unwrap()).unwrap();
    let selection = json!([{"acceptance_id":"bare","envelope_sha256":crate::message_acceptance::envelope_digest(&raw,&payload)}]);
    let request = begin(&f, "bareT", selection);
    fail(
        &f,
        "B",
        json!({"operation":"history_export","request":request}),
        "history_content_unavailable",
    );
    call(
        &f,
        "B",
        json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"],"acceptance_id":"bare","acceptance_receipt":acceptance(&key,&envelope,"bare")}),
    );
    export(&f, &request);
    let mut legacy_envelope = Value::Null;
    mutate(&f, "B", |s| {
        for r in s.wire.inbox.values_mut() {
            if r.acceptance_id.as_deref() == Some("old1") {
                legacy_envelope = json!(r.envelope);
                r.payload = None;
                r.acceptance_receipt = None;
            }
        }
    });
    call(
        &f,
        "B",
        json!({"operation":"wire_receive","header_bytes":legacy_envelope["header_bytes"],"payload_bytes":legacy_envelope["payload_bytes"],"acceptance_id":"old1","acceptance_receipt":acceptance(&key,&legacy_envelope,"old1")}),
    );
    assert_eq!(
        call(&f, "B", json!({"operation":"history_inspect"}))["missing_content_count"],
        1
    );
    let old = begin(&f, "legacy", select(&f, &["old2"]));
    let mut s: public::RequestStatement =
        serde_json::from_slice(&codec::decode(&old.statement_bytes).unwrap()).unwrap();
    mutate(&f, "B", |state| {
        let r = state
            .wire
            .inbox
            .values()
            .find(|r| r.acceptance_id.as_deref() == Some("old1"))
            .unwrap();
        s.selection = vec![public::Selection {
            acceptance_id: "old1".into(),
            envelope_sha256: crate::message_acceptance::envelope_digest(
                &codec::decode(&r.envelope.header_bytes).unwrap(),
                &codec::decode(&r.envelope.payload_bytes).unwrap(),
            ),
        }];
    });
    let mut signed_request = old;
    mutate(&f, "B2", |state| {
        signed_request =
            crate::lab::history_transfer::sign(state, public::REQUEST_DOMAIN, &s).unwrap()
    });
    fail(
        &f,
        "B",
        json!({"operation":"history_export","request":signed_request}),
        "history_content_unavailable",
    );
}

#[test]
fn signed_but_corrupt_ciphertext_is_rejected_without_consuming_receiver_key() {
    let (f, key) = fixture();
    let request = begin(&f, "T", select(&f, &["old1"]));
    let package = export(&f, &request);
    let mut bad = package.clone();
    let mut ct = codec::decode(&bad.ciphertext).unwrap();
    ct[0] ^= 1;
    bad.ciphertext = codec::encode(&ct);
    let mut body: public::PackageStatement =
        serde_json::from_slice(&codec::decode(&bad.statement_bytes).unwrap()).unwrap();
    body.ciphertext_sha256 =
        public::ciphertext_digest(&codec::decode(&bad.kem_output).unwrap(), &ct);
    mutate(&f, "B", |state| {
        let s = crate::lab::history_transfer::sign(state, public::PACKAGE_DOMAIN, &body).unwrap();
        bad.statement_bytes = s.statement_bytes;
        bad.signature_bytes = s.signature_bytes;
    });
    public::execute(&json!({"operation":"verify_history_transfer","checkpoint":cp(&f),"request":request,"package":bad}).to_string()).unwrap();
    fail(
        &f,
        "B2",
        import_op(&key, &request, &bad),
        "history_decryption_failed",
    );
    fail(
        &f,
        "B2",
        import_op(&SigningKey::from_bytes(&[42; 32]), &request, &package),
        "history_signature",
    );
    call(&f, "B2", import_op(&key, &request, &package));
    // 独立第三方迁移钥无法打开密文；不使用或导出任何旧MLS材料。
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let unrelated = provider
        .crypto()
        .derive_hpke_keypair(codec::CIPHERSUITE.hpke_config(), &[39; 32])
        .unwrap();
    let input = openmls_traits::types::HpkeCiphertext {
        kem_output: codec::decode(&package.kem_output).unwrap().into(),
        ciphertext: codec::decode(&package.ciphertext).unwrap().into(),
    };
    assert!(provider
        .crypto()
        .hpke_open(
            codec::CIPHERSUITE.hpke_config(),
            &input,
            &unrelated.private,
            &public::hpke_info(&request).unwrap(),
            &codec::decode(&request.statement_bytes).unwrap()
        )
        .is_err());
}

#[test]
fn cancelled_request_drops_key_even_while_permission_intent_is_pending() {
    let (f, key) = fixture();
    let request = begin(&f, "T", select(&f, &["old1"]));
    let package = export(&f, &request);
    call(
        &f,
        "B2",
        json!({"operation":"permission_prepare","change_id":"revokeB","action":{"kind":"revoke_device","account_id":"B","device_id":"B"}}),
    );
    call(
        &f,
        "B2",
        json!({"operation":"history_cancel","transfer_id":"T"}),
    );
    mutate(&f, "B2", |s| {
        assert!(s.history_transfers.requests["T"].private_key.is_none());
        assert!(
            s.history_transfers.requests["T"].status == history_state::RequestStatus::Cancelled
        );
    });
    fail(
        &f,
        "B2",
        import_op(&key, &request, &package),
        "permission_pending",
    );
    let (f, key) = fixture();
    let request = begin(&f, "T", select(&f, &["old1"]));
    let package = export(&f, &request);
    call(
        &f,
        "B2",
        json!({"operation":"history_cancel","transfer_id":"T"}),
    );
    fail(
        &f,
        "B2",
        import_op(&key, &request, &package),
        "history_cancelled",
    );
    fail(
        &f,
        "B2",
        json!({"operation":"history_request","transfer_id":"T","source":{"account_id":"B","device_id":"B"},"selection":select(&f,&["old1"])}),
        "history_cancelled",
    );
}

#[test]
fn history_conflicts_with_native_verified_message_or_existing_archive_are_atomic() {
    let (f, key) = fixture();
    let envelope = receive_copy(&f, &key, "shared", "source authenticated original");
    call(
        &f,
        "B2",
        json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"],"acceptance_id":"shared","acceptance_receipt":acceptance(&key,&envelope,"shared")}),
    );
    mutate(&f, "B", |s| {
        let r = s
            .wire
            .inbox
            .values_mut()
            .find(|r| r.acceptance_id.as_deref() == Some("shared"))
            .unwrap();
        r.payload = Some("source altered copy".into());
        r.payload_digest = codec::digest(b"source altered copy");
    });
    let request = begin(&f, "conflictNative", select(&f, &["shared"]));
    let package = export(&f, &request);
    fail(
        &f,
        "B2",
        import_op(&key, &request, &package),
        "history_conflict",
    );
    let r1 = begin(&f, "first", select(&f, &["old1"]));
    let p1 = export(&f, &r1);
    call(&f, "B2", import_op(&key, &r1, &p1));
    mutate(&f, "B", |s| {
        let r = s
            .wire
            .inbox
            .values_mut()
            .find(|r| r.acceptance_id.as_deref() == Some("old1"))
            .unwrap();
        r.payload = Some("altered".into());
        r.payload_digest = codec::digest(b"altered");
    });
    let r2 = begin(&f, "overlap", select(&f, &["old1", "old2"]));
    let p2 = export(&f, &r2);
    fail(&f, "B2", import_op(&key, &r2, &p2), "history_conflict");
    assert_eq!(
        call(&f, "B2", json!({"operation":"history_inspect"}))["imported_count"],
        1
    );
}

#[test]
fn migration_capacity_and_plaintext_budget_leave_requests_and_messages_intact() {
    let (f, key) = fixture();
    let request = begin(&f, "first", select(&f, &["old1"]));
    mutate(&f, "B2", |s| {
        for i in 1..128 {
            s.history_transfers.requests.insert(
                format!("fixture{i}"),
                history_state::RequestRecord {
                    request: request.clone(),
                    private_key: None,
                    status: history_state::RequestStatus::Cancelled,
                },
            );
        }
    });
    fail(
        &f,
        "B2",
        json!({"operation":"history_request","transfer_id":"overflow","source":{"account_id":"B","device_id":"B"},"selection":select(&f,&["old1"])}),
        "resource_exhausted",
    );
    let package = export(&f, &request);
    call(&f, "B2", import_op(&key, &request, &package));
    let (f, key) = fixture();
    for id in ["large1", "large2"] {
        receive_copy(&f, &key, id, &"x".repeat(64 * 1024));
    }
    let request = begin(&f, "large", select(&f, &["large1", "large2"]));
    fail(
        &f,
        "B",
        json!({"operation":"history_export","request":request}),
        "resource_exhausted",
    );
    assert_eq!(
        call(&f, "B", json!({"operation":"history_inspect"}))["export_count"],
        0
    );
    let request = begin(&f, "initial", select(&f, &["old1"]));
    let package = export(&f, &request);
    call(&f, "B2", import_op(&key, &request, &package));
    mutate(&f, "B2", |s| {
        let copy = s
            .history_transfers
            .copies
            .values()
            .next()
            .unwrap()
            .copy
            .clone();
        for i in 1..128 {
            s.history_transfers.copies.insert(
                format!("capacity_fixture{i}"),
                history_state::ArchivedCopy {
                    copy: copy.clone(),
                    source: permission::Identity {
                        account_id: "B".into(),
                        device_id: "B".into(),
                    },
                },
            );
        }
    });
    let request = begin(&f, "archiveOverflow", select(&f, &["old2"]));
    let package = export(&f, &request);
    fail(
        &f,
        "B2",
        import_op(&key, &request, &package),
        "resource_exhausted",
    );
    let request = begin(&f, "archiveDuplicate", select(&f, &["old1"]));
    let package = export(&f, &request);
    assert_eq!(
        call(&f, "B2", import_op(&key, &request, &package))["imported_count"],
        0
    );
}
