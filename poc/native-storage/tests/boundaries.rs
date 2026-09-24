mod support;
use rocket_native_storage_probe::{
    model::{Fault, OpenOptions, Put},
    Engine,
};
use std::{fs, path::PathBuf};
use support::*;

#[test]
fn input_limits_and_unicode_roundtrip_preserve_valid_state() {
    let files = Files::new();
    let engine = files.open();
    let client = engine.client();
    let value = "中文🙂e\u{301}\0' SELECT";
    assert_eq!(
        snapshot(client.put(put(0, "key", value, Fault::None))).records[0].value,
        value
    );
    for request in [
        put(1, "", "x", Fault::None),
        put(1, "bad\0key", "x", Fault::None),
        put(1, "key", &"x".repeat(4097), Fault::None),
    ] {
        assert!(client.put(request).result.is_err());
    }
    assert_eq!(snapshot(client.snapshot(Fault::None)).revision, "1");
    let mut invalid = put(1, "key", "x", Fault::None);
    invalid.expected_revision = "01".into();
    assert_eq!(
        client.put(invalid).result.unwrap_err().code,
        "invalid_revision"
    );
    for revision in 1..128 {
        snapshot(client.put(put(revision, &format!("k{revision}"), "x", Fault::None)));
    }
    assert_eq!(
        client
            .put(put(128, "too-many", "x", Fault::None))
            .result
            .unwrap_err()
            .code,
        "record_limit"
    );
    assert_eq!(snapshot(client.snapshot(Fault::None)).records.len(), 128);
    engine.close().unwrap();
}

#[test]
fn future_schema_and_corrupt_file_are_not_silently_replaced() {
    let files = Files::new();
    files.open().close().unwrap();
    let mut connection = rusqlite::Connection::open(files.db()).unwrap();
    let transaction = connection.transaction().unwrap();
    transaction
        .execute_batch("PRAGMA user_version = 99")
        .unwrap();
    transaction.commit().unwrap();
    connection.close().unwrap();
    let before = fs::read(files.db()).unwrap();
    assert!(Engine::open(files.db(), scope(), OpenOptions::default()).is_err());
    assert_eq!(fs::read(files.db()).unwrap(), before);
    let corrupt = files.0.join("corrupt.sqlite");
    fs::write(&corrupt, b"ordinary corrupt fixture").unwrap();
    assert!(Engine::open(corrupt.clone(), scope(), OpenOptions::default()).is_err());
    assert_eq!(fs::read(corrupt).unwrap(), b"ordinary corrupt fixture");
}

#[test]
fn revision_above_javascript_safe_integer_remains_exact_and_overflow_rejects() {
    let files = Files::new();
    files.open().close().unwrap();
    let mut connection = rusqlite::Connection::open(files.db()).unwrap();
    let tx = connection.transaction().unwrap();
    tx.execute(
        "UPDATE scope SET revision = ?1 WHERE id=1",
        ["18446744073709551614"],
    )
    .unwrap();
    tx.commit().unwrap();
    connection.close().unwrap();
    let engine = files.open();
    let client = engine.client();
    let result = client.put(Put {
        expected_revision: "18446744073709551614".into(),
        key: "last".into(),
        value: "x".into(),
        fault: Fault::None,
    });
    assert_eq!(snapshot(result).revision, u64::MAX.to_string());
    assert_eq!(
        client
            .put(put(u64::MAX, "overflow", "x", Fault::None))
            .result
            .unwrap_err()
            .code,
        "revision_exhausted"
    );
    engine.close().unwrap();
}

#[test]
fn empty_or_memory_paths_never_silently_replace_persistent_storage() {
    for path in [PathBuf::new(), PathBuf::from(":memory:")] {
        let result = Engine::open(path, scope(), OpenOptions::default());
        assert!(matches!(result, Err(error) if error.code == "invalid_path"));
    }
}
