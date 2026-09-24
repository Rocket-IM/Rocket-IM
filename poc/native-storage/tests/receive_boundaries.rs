mod receive_support;
use receive_support::*;
use rocket_native_storage_probe::crypto::{contract::Fault, Client};
use std::fs;

#[test]
fn renamed_store_rejects_legacy_project_format_without_modifying_bytes() {
    let files = Files::new();
    let mut client = files.open(true);
    value(client.close());
    drop(client);
    let mut db = rusqlite::Connection::open(files.db()).unwrap();
    let tx = db.transaction().unwrap();
    let current: String = tx
        .query_row(
            "SELECT format FROM crypto_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(current, "Rocket-IM/native-crypto/sqlite/v3");
    // 旧工程名只作为兼容性负例，所有故障注入仍在显式事务中。
    tx.execute(
        "UPDATE crypto_meta SET format=?1 WHERE singleton=1",
        ["Rockets-IM/native-crypto/sqlite/v3"],
    )
    .unwrap();
    tx.commit().unwrap();
    db.close().unwrap();
    let before = fs::read(files.db()).unwrap();
    let error = match Client::open(files.db(), scope("alice"), false) {
        Ok(_) => panic!("旧工程名格式不应被隐式接受"),
        Err(error) => error,
    };
    assert_eq!(error.code, "crypto_scope_mismatch");
    assert!(error.paused);
    assert_eq!(fs::read(files.db()).unwrap(), before);
}

#[test]
fn deleted_receipt_table_and_corrupt_cursor_are_rejected_without_repair() {
    for mutation in [
        "DROP TABLE crypto_receipts",
        "UPDATE crypto_meta SET processed_cursor='2'",
    ] {
        let files = Files::new();
        let mut client = files.open(true);
        let mut peer = group(&mut client);
        let envelope = peer.send("m1", "committed").unwrap();
        value(receive(&mut client, "r1", "1", &envelope, Fault::None));
        value(client.close());
        drop(client);
        // 仅Rust故障夹具在显式事务内破坏实验库，不提供宿主SQL或自动修复入口。
        let mut db = rusqlite::Connection::open(files.db()).unwrap();
        let tx = db.transaction().unwrap();
        tx.execute_batch(mutation).unwrap();
        tx.commit().unwrap();
        db.close().unwrap();
        let bytes = fs::read(files.db()).unwrap();
        assert!(Client::open(files.db(), scope("alice"), false).is_err());
        assert_eq!(fs::read(files.db()).unwrap(), bytes);
    }
}

#[test]
fn receive_capacity_is_rejected_before_reservation_or_crypto() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    for number in 1..=126 {
        let envelope = peer.send(&format!("m{number}"), "synthetic").unwrap();
        value(receive(
            &mut client,
            &format!("r{number}"),
            &number.to_string(),
            &envelope,
            Fault::None,
        ));
    }
    let before = inspect(&mut client);
    assert_eq!(before["processed_cursor"], "126");
    assert_eq!(before["result_count"], 128);
    let envelope = peer.send("overflow", "synthetic").unwrap();
    let refusal = receive(&mut client, "overflow", "127", &envelope, Fault::None);
    no_crypto(&refusal);
    failed(refusal, "crypto_limit");
    assert_eq!(inspect(&mut client), before);
    value(client.close());
}

#[test]
fn old_v1_pending_store_is_refused_without_upgrading_or_changing_identity_state() {
    let files = Files::new();
    let mut db = rusqlite::Connection::open(files.db()).unwrap();
    let tx = db.transaction().unwrap();
    let ddl = [
        "CREATE TABLE crypto_meta (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), format TEXT NOT NULL, service TEXT NOT NULL, account TEXT NOT NULL, device TEXT NOT NULL, revision TEXT NOT NULL, identity_json TEXT, conversation TEXT, provider BLOB, provider_hash TEXT NOT NULL, encryptions TEXT NOT NULL)",
        "CREATE TABLE crypto_pending (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), request_id TEXT NOT NULL, operation TEXT NOT NULL, input_hash TEXT NOT NULL, base_revision TEXT NOT NULL, base_provider_hash TEXT NOT NULL)",
        "CREATE TABLE crypto_results (request_id TEXT NOT NULL PRIMARY KEY, input_hash TEXT NOT NULL, kind TEXT NOT NULL, outcome_json TEXT NOT NULL)",
        "CREATE TABLE crypto_outbox (attempt_id TEXT NOT NULL PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, request_id TEXT NOT NULL, input_hash TEXT NOT NULL, envelope_json TEXT NOT NULL)",
    ];
    for sql in ddl {
        tx.execute_batch(sql).unwrap();
    }
    tx.execute_batch("INSERT INTO crypto_meta VALUES(1,'Rocket-IM/native-crypto/sqlite/v1','local','alice','alice-device','0',NULL,NULL,NULL,'','0'); PRAGMA user_version=1").unwrap();
    tx.execute(
        "INSERT INTO crypto_pending VALUES(1,'init','initialize',?1,'0','')",
        ["0".repeat(64)],
    )
    .unwrap();
    tx.commit().unwrap();
    db.close().unwrap();
    let bytes = fs::read(files.db()).unwrap();
    let error = match Client::open(files.db(), scope("alice"), false) {
        Ok(_) => panic!("旧库不应隐式升级"),
        Err(error) => error,
    };
    assert_eq!(error.code, "crypto_store_upgrade_required");
    assert_eq!(fs::read(files.db()).unwrap(), bytes);
}
