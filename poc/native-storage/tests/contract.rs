mod support;
use rocket_native_storage_probe::{
    model::{Fault, OpenOptions},
    Engine, Notification,
};
use std::{sync::mpsc::TryRecvError, thread, time::Duration};
use support::*;

fn explicit_sql(trace: &[String]) {
    assert!(!trace.is_empty());
    let mut active = false;
    for token in trace {
        match token.as_str() {
            "BEGIN" => {
                assert!(!active, "nested begin: {trace:?}");
                active = true;
            }
            "COMMIT" => {
                assert!(active, "commit outside tx: {trace:?}");
                active = false;
            }
            "ROLLBACK" | "ROLLBACK_AUTOMATIC" => {
                active = false;
            }
            _ => assert!(active, "SQL outside explicit tx: {trace:?}"),
        }
    }
    assert!(!active, "unclosed transaction: {trace:?}");
}

#[test]
fn sql_trace_covers_initialization_read_and_write_transactions() {
    let files = Files::new();
    let engine = files.open();
    explicit_sql(&engine.startup.trace);
    let client = engine.client();
    assert_ne!(
        engine.startup.worker_thread,
        format!("{:?}", thread::current().id())
    );
    let read = client.snapshot(Fault::None);
    explicit_sql(&read.trace);
    let baseline = snapshot(read);
    assert_eq!(
        (
            baseline.schema_version,
            baseline.journal_mode.as_str(),
            baseline.synchronous
        ),
        (2, "delete", 2)
    );
    let write = client.put(put(0, "key", "value", Fault::None));
    explicit_sql(&write.trace);
    assert_eq!(snapshot(write).revision, "1");
    engine.close().unwrap();
}

#[test]
fn partial_sql_failure_rolls_back_records_and_revision_without_event() {
    let files = Files::new();
    let engine = files.open();
    let client = engine.client();
    let (reply, events) = client.subscribe();
    let baseline = snapshot(reply);
    let failed = client.put(put(0, "bad", "uncommitted", Fault::SqlAfterWrite));
    explicit_sql(&failed.trace);
    assert_eq!(failed.result.unwrap_err().code, "database_error");
    assert_eq!(events.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(snapshot(client.snapshot(Fault::None)), baseline);
    assert_eq!(
        snapshot(client.put(put(0, "good", "saved", Fault::None))).revision,
        "1"
    );
    assert_eq!(
        events
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .revision,
        "1"
    );
    engine.close().unwrap();
}

#[test]
fn failed_read_does_not_expose_partial_snapshot() {
    let files = Files::new();
    let engine = files.open();
    let client = engine.client();
    snapshot(client.put(put(0, "key", "saved", Fault::None)));
    let read = client.snapshot(Fault::ReadAfterSnapshot);
    explicit_sql(&read.trace);
    assert_eq!(read.result.unwrap_err().code, "database_error");
    assert_eq!(snapshot(client.snapshot(Fault::None)).revision, "1");
    engine.close().unwrap();
}

#[test]
fn commit_hook_refusal_pauses_instance_and_preserves_reopen_state() {
    let files = Files::new();
    let engine = files.open();
    let client = engine.client();
    let (reply, events) = client.subscribe();
    let baseline = snapshot(reply);
    let failed = client.put(put(0, "key", "no", Fault::RefuseCommit));
    let error = failed.result.unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.sqlite_code, error.paused),
        ("commit_failed", Some(531), true)
    );
    assert_eq!(events.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(
        client.snapshot(Fault::None).result.unwrap_err().code,
        "paused"
    );
    engine.close().unwrap();
    let reopened = files.open();
    assert_eq!(snapshot(reopened.client().snapshot(Fault::None)), baseline);
    reopened.close().unwrap();
}

#[test]
fn migration_failure_preserves_v1_schema_and_data() {
    let files = Files::new();
    let seed = Engine::open(
        files.db(),
        scope(),
        OpenOptions {
            seed_v1: true,
            fail_migration: false,
        },
    )
    .unwrap();
    let old = snapshot(seed.client().snapshot(Fault::None));
    assert_eq!(old.schema_version, 1);
    seed.close().unwrap();
    let failed = Engine::open(
        files.db(),
        scope(),
        OpenOptions {
            seed_v1: false,
            fail_migration: true,
        },
    );
    assert!(failed.is_err());
    let retained = Engine::open(
        files.db(),
        scope(),
        OpenOptions {
            seed_v1: true,
            fail_migration: false,
        },
    )
    .unwrap();
    assert_eq!(snapshot(retained.client().snapshot(Fault::None)), old);
    retained.close().unwrap();
    let migrated = files.open();
    explicit_sql(&migrated.startup.trace);
    let now = snapshot(migrated.client().snapshot(Fault::None));
    assert_eq!((now.schema_version, now.revision.as_str()), (2, "1"));
    assert_eq!(now.records, old.records);
    migrated.close().unwrap();
}

#[test]
fn failed_request_never_inherits_previous_delivered_notification() {
    let files = Files::new();
    let engine = files.open();
    let client = engine.client();
    let (baseline, receiver) = client.subscribe();
    snapshot(baseline);
    assert_eq!(
        client.put(put(0, "ok", "saved", Fault::None)).notification,
        Notification::Delivered
    );
    receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    let stale = client.put(put(0, "stale", "no", Fault::None));
    assert_eq!(stale.notification, Notification::Idle);
    assert_eq!(stale.result.unwrap_err().code, "revision_conflict");
    let failed = client.put(put(1, "bad", "no", Fault::RefuseCommit));
    assert_eq!(failed.notification, Notification::Idle);
    assert_eq!(failed.result.unwrap_err().code, "commit_failed");
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    engine.close().unwrap();
}
