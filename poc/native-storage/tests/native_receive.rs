mod receive_support;
use receive_support::*;
use rocket_native_storage_probe::crypto::{
    contract::{Action, Fault},
    model::Envelope,
};

#[test]
fn receiving_and_reopening_preserve_plaintext_ratchet_and_contiguous_cursor() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let initial = inspect(&mut client);
    let first = peer.send("m1", "接收🙂\0first").unwrap();
    let response = receive(&mut client, "r1", "1", &first, Fault::None);
    assert_eq!(response.metrics.candidate_receives, 1);
    assert_eq!(response.metrics.provider_restores, 1);
    assert_ne!(response.worker_thread, response.crypto_thread);
    assert_eq!(response.events.len(), 1);
    assert_eq!(value(response)["value"]["message"]["text"], "接收🙂\0first");
    let saved = inspect(&mut client);
    assert_ne!(saved["provider_hash"], initial["provider_hash"]);
    assert_eq!(saved["processed_cursor"], "1");
    assert_eq!(saved["decryptions"], "1");
    assert_eq!(saved["outbox"], initial["outbox"]);
    value(client.close());
    drop(client);
    let mut reopened = files.open(false);
    assert_eq!(inspect(&mut reopened), saved);
    let queried = reopened.received("1");
    no_crypto(&queried);
    assert!(queried.events.is_empty());
    assert_eq!(value(queried)["message"]["text"], "接收🙂\0first");
    let second = peer.send("m2", "after-restart").unwrap();
    assert_eq!(
        value(receive(&mut reopened, "r2", "2", &second, Fault::None))["value"]["message"]["text"],
        "after-restart"
    );
    let reply = value(execute(
        &mut reopened,
        "reply",
        Action::Send {
            attempt_id: "a1".into(),
            message_id: "reply".into(),
            text: "双向仍共用provider".into(),
        },
        Fault::None,
    ));
    let envelope: Envelope = serde_json::from_value(reply["value"].clone()).unwrap();
    assert_eq!(peer.receive(&envelope).unwrap().text, "双向仍共用provider");
    value(reopened.close());
}

#[test]
fn same_sequence_cache_and_new_sequence_duplicate_never_decrypt_again() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let envelope = peer.send("m1", "saved-body").unwrap();
    let original = value(receive(&mut client, "r1", "1", &envelope, Fault::None));
    let first = inspect(&mut client);
    for id in ["r1", "new-request"] {
        let cached = receive(&mut client, id, "1", &envelope, Fault::None);
        no_crypto(&cached);
        assert!(cached.events.is_empty());
        let result = value(cached);
        assert_eq!(result["cached"], true);
        assert_eq!(result["value"], original["value"]);
        assert_eq!(inspect(&mut client), first);
    }
    let repeated = receive(&mut client, "r2", "2", &envelope, Fault::None);
    no_crypto(&repeated);
    assert!(repeated.events.is_empty());
    let repeated = value(repeated);
    assert_eq!(repeated["cached"], false);
    assert_eq!(repeated["value"]["duplicate"], true);
    let after = inspect(&mut client);
    assert_eq!(after["processed_cursor"], "2");
    assert_eq!(after["decryptions"], "1");
    assert_eq!(after["provider_hash"], first["provider_hash"]);
    assert_eq!(after["inbox"], first["inbox"]);
    assert_eq!(after["receipt_count"], 2);
    value(client.close());
    drop(client);
    let mut reopened = files.open(false);
    assert_eq!(inspect(&mut reopened), after);
    assert_eq!(value(reopened.received("2")), repeated["value"]);
    let retry = receive(&mut reopened, "after-restart", "2", &envelope, Fault::None);
    no_crypto(&retry);
    assert!(retry.events.is_empty());
    assert_eq!(value(retry)["value"], repeated["value"]);
    let next = peer.send("m2", "next").unwrap();
    value(receive(&mut reopened, "r3", "3", &next, Fault::None));
    assert_eq!(inspect(&mut reopened)["decryptions"], "2");
    value(reopened.close());
}

#[test]
fn gaps_conflicts_and_invalid_large_sequences_never_mutate_or_call_crypto() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let envelope = peer.send("m1", "safe").unwrap();
    let initial = inspect(&mut client);
    for (sequence, code) in [
        ("0", "invalid_sequence"),
        ("01", "invalid_sequence"),
        ("-1", "invalid_sequence"),
        ("18446744073709551616", "invalid_sequence"),
        ("9007199254740993", "receive_gap"),
        ("18446744073709551615", "receive_gap"),
        ("2", "receive_gap"),
    ] {
        let response = receive(&mut client, "gap", sequence, &envelope, Fault::None);
        no_crypto(&response);
        failed(response, code);
        assert_eq!(inspect(&mut client), initial);
    }
    value(receive(&mut client, "first", "1", &envelope, Fault::None));
    let saved = inspect(&mut client);
    let changed = peer.send("m1", "different ciphertext same key").unwrap();
    for (id, sequence, code) in [
        ("first", "1", "crypto_request_conflict"),
        ("other", "1", "receive_sequence_conflict"),
        ("other", "2", "receive_message_conflict"),
    ] {
        let response = receive(&mut client, id, sequence, &changed, Fault::None);
        no_crypto(&response);
        failed(response, code);
        assert_eq!(inspect(&mut client), saved);
    }
    value(client.close());
}

#[test]
fn all_receive_failure_windows_keep_old_message_and_persistent_gate_before_cache() {
    for fault in [
        Fault::AfterReserve,
        Fault::AfterCrypto,
        Fault::AfterSql,
        Fault::RefuseCommit,
    ] {
        let files = Files::new();
        let mut client = files.open(true);
        let mut peer = group(&mut client);
        let first = peer.send("m1", "committed").unwrap();
        value(receive(&mut client, "r1", "1", &first, Fault::None));
        let second = peer.send("m2", "uncommitted-plaintext-28569").unwrap();
        let before = inspect(&mut client);
        let response = receive(&mut client, "r2", "2", &second, fault);
        assert!(!response.ok);
        assert!(response.result.is_none());
        assert!(response.events.is_empty());
        assert!(response.error.unwrap().paused);
        assert_eq!(
            response.metrics.candidate_receives,
            u32::from(fault != Fault::AfterReserve)
        );
        let paused = inspect(&mut client);
        assert!(paused["pending"].is_object());
        for field in [
            "provider_hash",
            "revision",
            "decryptions",
            "processed_cursor",
            "inbox",
            "receipt_count",
            "result_count",
            "outbox",
        ] {
            assert_eq!(before[field], paused[field]);
        }
        assert!(!paused.to_string().contains("uncommitted-plaintext-28569"));
        let missing = client.received("2");
        assert!(!missing.error.as_ref().unwrap().paused);
        failed(missing, "receive_not_found");
        assert_eq!(value(client.received("1"))["message"]["text"], "committed");
        value(client.close());
        drop(client);
        let mut reopened = files.open(false);
        assert_eq!(inspect(&mut reopened), paused);
        for (id, sequence, envelope) in [
            ("r1", "1", &first),
            ("cached-other", "1", &first),
            ("dup", "2", &first),
            ("r2", "2", &second),
            ("fresh", "3", &second),
        ] {
            let response = receive(&mut reopened, id, sequence, envelope, Fault::None);
            no_crypto(&response);
            failed(response, "crypto_pending");
        }
        let response = execute(
            &mut reopened,
            "new-send",
            Action::Send {
                attempt_id: "new".into(),
                message_id: "new".into(),
                text: "new".into(),
            },
            Fault::None,
        );
        no_crypto(&response);
        failed(response, "crypto_pending");
        failed(reopened.received("2"), "receive_not_found");
        value(reopened.close());
    }
}

#[test]
fn duplicate_delivery_commit_failure_does_not_advance_cursor_or_clear_reservation() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let envelope = peer.send("m1", "already committed").unwrap();
    value(receive(&mut client, "r1", "1", &envelope, Fault::None));
    let before = inspect(&mut client);
    let result = receive(
        &mut client,
        "duplicate",
        "2",
        &envelope,
        Fault::RefuseCommit,
    );
    no_crypto(&result);
    failed(result, "commit_failed");
    let paused = inspect(&mut client);
    assert_eq!(paused["provider_hash"], before["provider_hash"]);
    assert_eq!(paused["processed_cursor"], "1");
    assert_eq!(paused["receipt_count"], 1);
    let missing = client.received("2");
    assert!(!missing.error.as_ref().unwrap().paused);
    failed(missing, "receive_not_found");
    value(client.close());
    drop(client);
    let mut reopened = files.open(false);
    assert_eq!(inspect(&mut reopened), paused);
    let retry = receive(&mut reopened, "duplicate", "2", &envelope, Fault::None);
    no_crypto(&retry);
    failed(retry, "crypto_pending");
    value(reopened.close());
}

#[test]
fn authenticated_context_failure_never_persists_or_exposes_candidate_plaintext() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let mut forged = peer.send("real-id", "private-uncommitted-61321").unwrap();
    forged.message_id = "forged-id".into();
    let before = inspect(&mut client);
    let reply = receive(&mut client, "forged", "1", &forged, Fault::None);
    assert_eq!(reply.metrics.candidate_receives, 1);
    failed(reply, "crypto_identity_mismatch");
    let after = inspect(&mut client);
    assert_eq!(after["provider_hash"], before["provider_hash"]);
    assert_eq!(after["processed_cursor"], "0");
    assert!(!after.to_string().contains("private-uncommitted-61321"));
    assert!(after["pending"].is_object());
    failed(client.received("1"), "receive_not_found");
    value(client.close());
}
