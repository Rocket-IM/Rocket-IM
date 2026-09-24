mod support;
use rockets_native_storage_probe::{
    model::{Fault, OpenOptions, Scope},
    Engine, Notification,
};
use std::{
    sync::mpsc::{self, TryRecvError},
    thread,
    time::Duration,
};
use support::*;

#[test]
fn callback_can_read_write_unsubscribe_and_close_from_host_thread() {
    let files = Files::new();
    let engine = files.open();
    let client = engine.client();
    let (initial, receiver) = client.subscribe();
    snapshot(initial);
    let callback_client = client.clone();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let callback = thread::spawn(move || {
        let event = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        let read = callback_client.snapshot(Fault::None);
        assert_ne!(read.worker_thread, format!("{:?}", thread::current().id()));
        let visible = snapshot(read);
        assert_eq!(visible.revision, event.revision);
        snapshot(callback_client.put(put(1, "reentrant", "saved", Fault::None)));
        callback_client.unsubscribe().result.unwrap();
        callback_client.close().result.unwrap();
        done_tx.send(()).unwrap();
    });
    snapshot(client.put(put(0, "trigger", "saved", Fault::None)));
    done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    callback.join().unwrap();
    assert_eq!(
        client.snapshot(Fault::None).result.unwrap_err().code,
        "closed"
    );
    engine.close().unwrap();
    let reopened = files.open();
    assert_eq!(
        snapshot(reopened.client().snapshot(Fault::None)).revision,
        "2"
    );
    reopened.close().unwrap();
}

#[test]
fn bounded_event_overflow_is_visible_and_resubscribe_recovers_snapshot() {
    let files = Files::new();
    let engine = files.open();
    let client = engine.client();
    let (reply, receiver) = client.subscribe();
    snapshot(reply);
    for revision in 0..16 {
        assert_eq!(
            client
                .put(put(revision, "key", "saved", Fault::None))
                .notification,
            Notification::Delivered
        );
    }
    let overflow = client.put(put(16, "key", "saved", Fault::None));
    assert_eq!(overflow.notification, Notification::Lagged);
    assert_eq!(snapshot(overflow).revision, "17");
    assert_eq!(receiver.try_iter().count(), 16);
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
    let (reply, fresh) = client.subscribe();
    assert_eq!(snapshot(reply).revision, "17");
    snapshot(client.put(put(17, "key", "again", Fault::None)));
    assert_eq!(
        fresh.recv_timeout(Duration::from_secs(1)).unwrap().revision,
        "18"
    );
    engine.close().unwrap();
}

#[test]
fn stale_concurrent_writes_do_not_overwrite_the_winner() {
    let files = Files::new();
    let engine = files.open();
    let first = engine.client();
    let second = first.clone();
    let a = thread::spawn(move || first.put(put(0, "a", "one", Fault::None)).result);
    let b = thread::spawn(move || second.put(put(0, "b", "two", Fault::None)).result);
    let results = [a.join().unwrap(), b.join().unwrap()];
    assert_eq!(results.iter().filter(|value| value.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .find_map(|value| value.as_ref().err())
            .unwrap()
            .code,
        "revision_conflict"
    );
    let stored = snapshot(engine.client().snapshot(Fault::None));
    assert_eq!((stored.revision.as_str(), stored.records.len()), ("1", 1));
    engine.close().unwrap();
}

#[test]
fn scope_mismatch_rejected_and_other_account_unaffected() {
    let files = Files::new();
    let engine = files.open();
    snapshot(engine.client().put(put(0, "key", "alice", Fault::None)));
    engine.close().unwrap();
    let bob = Scope {
        service: "local-service".into(),
        account: "bob".into(),
    };
    assert!(Engine::open(files.db(), bob.clone(), OpenOptions::default()).is_err());
    let other = Engine::open(files.0.join("bob.sqlite"), bob, OpenOptions::default()).unwrap();
    assert_eq!(snapshot(other.client().snapshot(Fault::None)).revision, "0");
    other.close().unwrap();
    let alice = files.open();
    assert_eq!(
        snapshot(alice.client().snapshot(Fault::None)).records[0].value,
        "alice"
    );
    alice.close().unwrap();
}
