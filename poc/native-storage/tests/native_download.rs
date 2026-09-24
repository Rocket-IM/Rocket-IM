mod receive_support;
use receive_support::*;
use rockets_native_storage_probe::crypto::{
    contract::{DownloadRecord, DownloadRequest, Fault},
    model::Envelope,
    Client, Reply,
};

fn record(sequence: usize, envelope: &Envelope) -> DownloadRecord {
    DownloadRecord {
        sequence: sequence.to_string(),
        envelope: envelope.clone(),
    }
}
fn download(client: &mut Client, records: Vec<DownloadRecord>, fault: Fault) -> Reply {
    client.download(DownloadRequest { records, fault })
}
fn crypto_unchanged(before: &serde_json::Value, after: &serde_json::Value) {
    for field in [
        "revision",
        "provider_hash",
        "provider_bytes",
        "encryptions",
        "decryptions",
        "processed_cursor",
        "inbox",
        "receipt_count",
        "result_count",
        "outbox",
        "pending",
    ] {
        assert_eq!(before[field], after[field], "{field}");
    }
}

#[test]
fn downloaded_batch_survives_restart_and_is_processed_only_from_saved_records() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let before = inspect(&mut client);
    let records: Vec<_> = (1..=3)
        .map(|n| {
            record(
                n,
                &peer
                    .send(&format!("m{n}"), &format!("已下载🙂\0{n}"))
                    .unwrap(),
            )
        })
        .collect();
    let saved = download(&mut client, records.clone(), Fault::None);
    no_crypto(&saved);
    assert_eq!(saved.events.len(), 1);
    assert_eq!(saved.events[0]["kind"], "download");
    assert!(saved.trace.last().is_some_and(|v| v == "COMMIT"));
    assert_eq!(value(saved)["added"], 3);
    let snapshot = inspect(&mut client);
    crypto_unchanged(&before, &snapshot);
    assert_eq!(snapshot["download_cursor"], "3");
    assert_eq!(snapshot["downloads"].as_array().unwrap().len(), 3);
    failed(client.received("1"), "receive_not_found");
    let gap = client.process("gap", "2", Fault::None);
    no_crypto(&gap);
    failed(gap, "receive_gap");
    value(client.close());
    drop(client);
    let mut reopened = files.open(false);
    assert_eq!(inspect(&mut reopened), snapshot);
    for n in 1..=3 {
        let response = reopened.process(&format!("r{n}"), &n.to_string(), Fault::None);
        assert_eq!(response.metrics.candidate_receives, 1);
        assert_eq!(response.events.len(), 1);
        assert_eq!(
            value(response)["value"]["message"]["text"],
            format!("已下载🙂\0{n}")
        );
        assert_eq!(inspect(&mut reopened)["download_cursor"], "3");
    }
    let processed = inspect(&mut reopened);
    let cached = reopened.process("retry", "1", Fault::None);
    no_crypto(&cached);
    assert!(cached.events.is_empty());
    assert_eq!(value(cached)["cached"], true);
    assert_eq!(inspect(&mut reopened), processed);
    let cached_download = download(&mut reopened, records, Fault::None);
    no_crypto(&cached_download);
    assert!(cached_download.events.is_empty());
    assert_eq!(value(cached_download)["cached"], true);
    value(reopened.close());
}

#[test]
fn overlapping_batches_are_atomic_and_direct_receive_cannot_replace_saved_ciphertext() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let a = peer.send("a", "a").unwrap();
    let b = peer.send("b", "b").unwrap();
    let c = peer.send("c", "c").unwrap();
    value(download(
        &mut client,
        vec![record(1, &a), record(2, &b)],
        Fault::None,
    ));
    let before = inspect(&mut client);
    failed(
        download(&mut client, vec![record(2, &a), record(3, &c)], Fault::None),
        "download_sequence_conflict",
    );
    assert_eq!(inspect(&mut client), before);
    let mut foreign = c.clone();
    foreign.service = "other".into();
    failed(
        download(
            &mut client,
            vec![record(2, &b), record(3, &foreign)],
            Fault::None,
        ),
        "crypto_scope_mismatch",
    );
    assert_eq!(inspect(&mut client), before);
    failed(
        receive(&mut client, "overwrite", "1", &b, Fault::None),
        "receive_sequence_conflict",
    );
    assert_eq!(inspect(&mut client), before);
    assert_eq!(
        value(download(
            &mut client,
            vec![record(2, &b), record(3, &c)],
            Fault::None
        ))["added"],
        1
    );
    value(receive(&mut client, "first", "1", &a, Fault::None));
    value(client.process("second", "2", Fault::None));
    value(client.process("third", "3", Fault::None));
    let d = peer.send("d", "direct path").unwrap();
    value(receive(&mut client, "fourth", "4", &d, Fault::None));
    let after = inspect(&mut client);
    assert_eq!(after["download_cursor"], "4");
    assert_eq!(after["processed_cursor"], "4");
    assert_eq!(after["downloads"].as_array().unwrap().len(), 4);
    value(client.close());
}

#[test]
fn invalid_authenticated_content_stays_downloaded_without_becoming_processed() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let first = peer.send("m1", "committed").unwrap();
    value(receive(&mut client, "first", "1", &first, Fault::None));
    let mut forged = peer.send("m2", "uncommitted-secret").unwrap();
    forged.message_id = "forged-authenticated-id".into();
    let records = vec![record(2, &forged), record(3, &first)];
    value(download(&mut client, records.clone(), Fault::None));
    let before = inspect(&mut client);
    let failure = client.process("bad", "2", Fault::None);
    assert_eq!(failure.metrics.candidate_receives, 1);
    failed(failure, "crypto_identity_mismatch");
    let paused = inspect(&mut client);
    for field in [
        "downloads",
        "download_cursor",
        "processed_cursor",
        "provider_hash",
        "decryptions",
        "revision",
    ] {
        assert_eq!(paused[field], before[field]);
    }
    assert_eq!(paused["download_cursor"], "3");
    assert_eq!(paused["processed_cursor"], "1");
    assert!(paused["pending"].is_object());
    failed(client.received("2"), "receive_not_found");
    assert_eq!(value(client.received("1"))["message"]["text"], "committed");
    value(client.close());
    drop(client);
    let mut reopened = files.open(false);
    assert_eq!(inspect(&mut reopened), paused);
    for sequence in ["1", "2", "3", "4"] {
        let response = reopened.process("retry", sequence, Fault::None);
        no_crypto(&response);
        failed(response, "crypto_pending");
    }
    let retry = download(&mut reopened, records, Fault::None);
    no_crypto(&retry);
    failed(retry, "crypto_pending");
    value(reopened.close());
}

#[test]
fn download_sql_and_commit_failures_leave_no_partial_batch_and_reopen_can_retry() {
    for fault in [Fault::AfterSql, Fault::RefuseCommit] {
        let files = Files::new();
        let mut client = files.open(true);
        let mut peer = group(&mut client);
        let records = vec![
            record(1, &peer.send("m1", "one").unwrap()),
            record(2, &peer.send("m2", "two").unwrap()),
        ];
        let before = inspect(&mut client);
        let response = download(&mut client, records.clone(), fault);
        no_crypto(&response);
        assert!(!response.ok);
        assert!(response.result.is_none() && response.events.is_empty());
        assert_eq!(inspect(&mut client), before);
        if fault == Fault::RefuseCommit {
            failed(
                download(&mut client, records.clone(), Fault::None),
                "crypto_paused",
            );
        }
        value(client.close());
        drop(client);
        let mut reopened = files.open(false);
        assert_eq!(inspect(&mut reopened), before);
        value(download(&mut reopened, records, Fault::None));
        value(reopened.process("first", "1", Fault::None));
        assert_eq!(inspect(&mut reopened)["processed_cursor"], "1");
        value(reopened.close());
    }
}

#[test]
fn processing_failures_never_discard_downloaded_backlog_or_allow_pending_retries() {
    for fault in [
        Fault::AfterReserve,
        Fault::AfterCrypto,
        Fault::AfterSql,
        Fault::RefuseCommit,
    ] {
        let files = Files::new();
        let mut client = files.open(true);
        let mut peer = group(&mut client);
        let records: Vec<_> = (1..=3)
            .map(|n| record(n, &peer.send(&format!("m{n}"), "body").unwrap()))
            .collect();
        value(download(&mut client, records.clone(), Fault::None));
        value(client.process("r1", "1", Fault::None));
        let before = inspect(&mut client);
        let failure = client.process("r2", "2", fault);
        assert!(!failure.ok && failure.result.is_none() && failure.events.is_empty());
        assert!(failure.error.unwrap().paused);
        let after = inspect(&mut client);
        for field in [
            "downloads",
            "download_cursor",
            "processed_cursor",
            "provider_hash",
            "decryptions",
            "revision",
        ] {
            assert_eq!(before[field], after[field]);
        }
        assert!(after["pending"].is_object());
        value(client.close());
        drop(client);
        let mut reopened = files.open(false);
        assert_eq!(inspect(&mut reopened), after);
        let retry = reopened.process("r1", "1", Fault::None);
        no_crypto(&retry);
        failed(retry, "crypto_pending");
        failed(
            download(&mut reopened, records, Fault::None),
            "crypto_pending",
        );
        value(reopened.close());
    }
}

#[test]
fn duplicate_downloaded_delivery_advances_processing_without_another_decryption() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let envelope = peer.send("m1", "body").unwrap();
    value(download(
        &mut client,
        vec![record(1, &envelope), record(2, &envelope)],
        Fault::None,
    ));
    value(client.process("r1", "1", Fault::None));
    let before = inspect(&mut client);
    let duplicate = client.process("r2", "2", Fault::None);
    no_crypto(&duplicate);
    assert!(duplicate.events.is_empty());
    assert_eq!(value(duplicate)["value"]["duplicate"], true);
    let after = inspect(&mut client);
    assert_eq!(after["download_cursor"], "2");
    assert_eq!(after["processed_cursor"], "2");
    assert_eq!(after["decryptions"], "1");
    assert_eq!(after["provider_hash"], before["provider_hash"]);
    assert_eq!(after["downloads"], before["downloads"]);
    value(client.close());
}
