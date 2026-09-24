mod receive_support;
use receive_support::*;
use rockets_native_storage_probe::crypto::{
    contract::{DownloadRecord, DownloadRequest, Fault},
    model::Envelope,
    Client,
};
use serde_json::json;
use std::fs;

fn record(sequence: &str, envelope: &Envelope) -> DownloadRecord {
    DownloadRecord {
        sequence: sequence.into(),
        envelope: envelope.clone(),
    }
}

#[test]
fn malformed_batches_and_lossy_sequences_are_rejected_before_storage_or_crypto() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let envelope = peer.send("m1", "synthetic").unwrap();
    let before = inspect(&mut client);
    for sequence in ["0", "01", "-1", "+1", "1.0", "18446744073709551616"] {
        let refusal = client.download(DownloadRequest {
            records: vec![record(sequence, &envelope)],
            fault: Fault::None,
        });
        no_crypto(&refusal);
        failed(refusal, "invalid_sequence");
        let refusal = client.process("invalid", sequence, Fault::None);
        no_crypto(&refusal);
        failed(refusal, "invalid_sequence");
        assert_eq!(inspect(&mut client), before);
    }
    // 超出 JS 精确整数范围的规范字符串仍按真实 u64 判断缺口，不能截断。
    for sequence in ["2", "9007199254740993", "18446744073709551615"] {
        let refusal = client.download(DownloadRequest {
            records: vec![record(sequence, &envelope)],
            fault: Fault::None,
        });
        no_crypto(&refusal);
        failed(refusal, "download_gap");
        assert_eq!(inspect(&mut client), before);
    }
    let oversized: Vec<_> = (1..=17)
        .map(|n| record(&n.to_string(), &envelope))
        .collect();
    for records in [
        vec![],
        oversized,
        vec![record("1", &envelope), record("1", &envelope)],
        vec![record("2", &envelope), record("1", &envelope)],
        vec![record("1", &envelope), record("3", &envelope)],
    ] {
        let refusal = client.download(DownloadRequest {
            records,
            fault: Fault::None,
        });
        no_crypto(&refusal);
        failed(refusal, "invalid_download_batch");
        assert_eq!(inspect(&mut client), before);
    }
    let refusal = client.download(DownloadRequest {
        records: vec![record("1", &envelope)],
        fault: Fault::AfterCrypto,
    });
    no_crypto(&refusal);
    failed(refusal, "invalid_download_fault");
    let valid = json!({"records":[{"sequence":"1","envelope":envelope}]});
    assert!(serde_json::from_value::<DownloadRequest>(valid.clone()).is_ok());
    let mut unknown_request = valid.clone();
    unknown_request["unexpected"] = json!(true);
    let mut unknown_record = valid.clone();
    unknown_record["records"][0]["unexpected"] = json!(true);
    let mut unknown_envelope = valid.clone();
    unknown_envelope["records"][0]["envelope"]["unexpected"] = json!(true);
    let mut numeric_sequence = valid.clone();
    numeric_sequence["records"][0]["sequence"] = json!(9007199254740993_u64);
    let mut missing_sequence = valid.clone();
    missing_sequence["records"][0]
        .as_object_mut()
        .unwrap()
        .remove("sequence");
    let mut null_sequence = valid;
    null_sequence["records"][0]["sequence"] = serde_json::Value::Null;
    for invalid in [
        unknown_request,
        unknown_record,
        unknown_envelope,
        numeric_sequence,
        missing_sequence,
        null_sequence,
    ] {
        assert!(serde_json::from_value::<DownloadRequest>(invalid).is_err());
    }
    assert_eq!(inspect(&mut client), before);
    value(client.close());
}

#[test]
fn download_capacity_is_bounded_and_retries_do_not_need_additional_capacity() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let envelope = peer
        .send("m1", "one ciphertext at distinct delivery sequences")
        .unwrap();
    let before = inspect(&mut client);
    for start in (1..=128).step_by(16) {
        let response = client.download(DownloadRequest {
            records: (start..start + 16)
                .map(|n| record(&n.to_string(), &envelope))
                .collect(),
            fault: Fault::None,
        });
        no_crypto(&response);
        assert_eq!(value(response)["added"], 16);
    }
    let full = inspect(&mut client);
    assert_eq!(full["download_cursor"], "128");
    assert_eq!(full["downloads"].as_array().unwrap().len(), 128);
    for field in [
        "revision",
        "processed_cursor",
        "decryptions",
        "encryptions",
        "provider_hash",
        "result_count",
        "pending",
    ] {
        assert_eq!(full[field], before[field]);
    }
    let refusal = client.download(DownloadRequest {
        records: vec![record("128", &envelope), record("129", &envelope)],
        fault: Fault::None,
    });
    no_crypto(&refusal);
    failed(refusal, "crypto_limit");
    assert_eq!(inspect(&mut client), full);
    let retry = client.download(DownloadRequest {
        records: vec![record("128", &envelope)],
        fault: Fault::None,
    });
    no_crypto(&retry);
    assert!(retry.events.is_empty());
    assert_eq!(value(retry)["cached"], true);
    assert_eq!(inspect(&mut client), full);
    value(client.close());
}

#[test]
fn corrupt_download_rows_cursors_and_receipt_links_are_rejected_without_repair() {
    for mutation in [
        "DROP TABLE crypto_downloads",
        "DELETE FROM crypto_downloads WHERE sequence='1'",
        "UPDATE crypto_meta SET download_cursor='3'",
        "UPDATE crypto_meta SET download_cursor='0'",
        "UPDATE crypto_downloads SET envelope_hash='incorrect' WHERE sequence='1'",
        "UPDATE crypto_downloads SET ciphertext_hash='incorrect' WHERE sequence='1'",
        "UPDATE crypto_downloads SET (envelope_hash,ciphertext_hash,envelope_json)=(SELECT envelope_hash,ciphertext_hash,envelope_json FROM crypto_downloads WHERE sequence='2') WHERE sequence='1'",
    ] {
        let files = Files::new();
        let mut client = files.open(true);
        let mut peer = group(&mut client);
        let first = peer.send("m1", "committed").unwrap();
        let second = peer.send("m2", "downloaded only").unwrap();
        value(receive(&mut client, "r1", "1", &first, Fault::None));
        value(client.download(DownloadRequest {
            records: vec![record("2", &second)],
            fault: Fault::None,
        }));
        value(client.close());
        drop(client);
        // 仅故障夹具能在事务内修改原始行；最后一种保留行内摘要一致性，破坏跨表关联。
        let mut db = rusqlite::Connection::open(files.db()).unwrap();
        let tx = db.transaction().unwrap();
        tx.execute_batch(mutation).unwrap();
        tx.commit().unwrap();
        db.close().unwrap();
        let bytes = fs::read(files.db()).unwrap();
        let error = match Client::open(files.db(), scope("alice"), false) {
            Ok(_) => panic!("损坏的下载记录不应被自动修复: {mutation}"),
            Err(error) => error,
        };
        assert_eq!(error.code, "crypto_store_corrupt", "{mutation}");
        assert_eq!(fs::read(files.db()).unwrap(), bytes, "{mutation}");
    }
}

#[test]
fn old_v2_pending_store_is_refused_without_upgrading_or_clearing_reservation() {
    let files = Files::new();
    let mut db = rusqlite::Connection::open(files.db()).unwrap();
    let tx = db.transaction().unwrap();
    let ddl = [
        "CREATE TABLE crypto_meta (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), format TEXT NOT NULL, service TEXT NOT NULL, account TEXT NOT NULL, device TEXT NOT NULL, revision TEXT NOT NULL, identity_json TEXT, conversation TEXT, provider BLOB, provider_hash TEXT NOT NULL, encryptions TEXT NOT NULL, processed_cursor TEXT NOT NULL, decryptions TEXT NOT NULL)",
        "CREATE TABLE crypto_pending (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), request_id TEXT NOT NULL, operation TEXT NOT NULL, input_hash TEXT NOT NULL, base_revision TEXT NOT NULL, base_provider_hash TEXT NOT NULL)",
        "CREATE TABLE crypto_results (request_id TEXT NOT NULL PRIMARY KEY, input_hash TEXT NOT NULL, kind TEXT NOT NULL, outcome_json TEXT NOT NULL)",
        "CREATE TABLE crypto_outbox (attempt_id TEXT NOT NULL PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, request_id TEXT NOT NULL, input_hash TEXT NOT NULL, envelope_json TEXT NOT NULL)",
        "CREATE TABLE crypto_inbox (message_key TEXT NOT NULL PRIMARY KEY, first_sequence TEXT NOT NULL UNIQUE, message_id TEXT NOT NULL, sender_account TEXT NOT NULL, sender_device TEXT NOT NULL, envelope_hash TEXT NOT NULL, ciphertext_hash TEXT NOT NULL, text_hash TEXT NOT NULL, envelope_json TEXT NOT NULL, plaintext_json TEXT NOT NULL)",
        "CREATE TABLE crypto_receipts (sequence TEXT NOT NULL PRIMARY KEY, message_key TEXT NOT NULL, request_id TEXT NOT NULL UNIQUE, input_hash TEXT NOT NULL)",
    ];
    for sql in ddl {
        tx.execute_batch(sql).unwrap();
    }
    tx.execute_batch("INSERT INTO crypto_meta VALUES(1,'Rockets-IM/native-crypto/sqlite/v2','local','alice','alice-device','0',NULL,NULL,NULL,'','0','0','0'); PRAGMA user_version=2").unwrap();
    tx.execute(
        "INSERT INTO crypto_pending VALUES(1,'init','initialize',?1,'0','')",
        ["0".repeat(64)],
    )
    .unwrap();
    tx.commit().unwrap();
    db.close().unwrap();
    let bytes = fs::read(files.db()).unwrap();
    let error = match Client::open(files.db(), scope("alice"), false) {
        Ok(_) => panic!("v2 未决库不应隐式升级"),
        Err(error) => error,
    };
    assert_eq!(error.code, "crypto_store_upgrade_required");
    assert_eq!(fs::read(files.db()).unwrap(), bytes);
}
