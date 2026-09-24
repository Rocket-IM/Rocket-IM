use rocket_native_storage_probe::crypto::{
    contract::{Action, Fault, Request, Scope},
    model::{Envelope, Identity},
    Client, MemoryPeer, Reply,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "native-crypto-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("crypto.sqlite")
    }
    fn open(&self, create: bool) -> Client {
        Client::open(self.db(), scope("alice", "a"), create).unwrap()
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn scope(account: &str, device: &str) -> Scope {
    Scope {
        service: "local".into(),
        account: account.into(),
        device: device.into(),
    }
}
fn execute(client: &mut Client, id: &str, action: Action, fault: Fault) -> Reply {
    client.execute(Request {
        request_id: id.into(),
        action,
        fault,
    })
}
fn value(reply: Reply) -> Value {
    assert!(reply.ok, "{}", serde_json::to_string(&reply).unwrap());
    reply.result.unwrap()
}
fn inspect(client: &mut Client) -> Value {
    value(client.inspect())
}
fn send(attempt: &str, message: &str, text: &str) -> Action {
    Action::Send {
        attempt_id: attempt.into(),
        message_id: message.into(),
        text: text.into(),
    }
}
fn group(client: &mut Client) -> MemoryPeer {
    let identity: Identity = serde_json::from_value(
        value(execute(client, "init", Action::Initialize {}, Fault::None))["value"].clone(),
    )
    .unwrap();
    let mut peer = MemoryPeer::new(&scope("bob", "b")).unwrap();
    let result = value(execute(
        client,
        "group",
        Action::CreateGroup {
            conversation: "conversation".into(),
            peer: peer.identity(),
        },
        Fault::None,
    ));
    peer.join(
        "conversation",
        &identity,
        result["value"]["welcome"].as_str().unwrap(),
    )
    .unwrap();
    peer
}
fn no_crypto(reply: &Reply) {
    assert_eq!(
        reply.metrics.provider_news
            + reply.metrics.provider_restores
            + reply.metrics.candidate_sends,
        0
    );
}
fn failed(reply: Reply, code: &str) {
    assert!(!reply.ok);
    assert!(reply.result.is_none());
    assert!(reply.events.is_empty());
    assert_eq!(reply.error.unwrap().code, code);
}

#[test]
fn native_ciphertext_retry_and_reopen_never_repeat_encryption() {
    let files = Files::new();
    let mut client = files.open(true);
    let mut peer = group(&mut client);
    let first = execute(
        &mut client,
        "send-1",
        send("a1", "m1", "你好\0🙂"),
        Fault::None,
    );
    assert_eq!(first.metrics.candidate_sends, 1);
    assert_ne!(first.worker_thread, first.crypto_thread);
    assert_eq!(first.events.len(), 1);
    let saved = value(first);
    let state = inspect(&mut client);
    let retry = execute(
        &mut client,
        "send-other-rpc",
        send("a1", "m1", "你好\0🙂"),
        Fault::None,
    );
    no_crypto(&retry);
    assert!(retry.events.is_empty());
    assert_eq!(value(retry)["value"], saved["value"]);
    assert_eq!(inspect(&mut client), state);
    value(client.close());
    drop(client);
    let mut reopened = files.open(false);
    let retry = execute(
        &mut reopened,
        "send-1",
        send("a1", "m1", "你好\0🙂"),
        Fault::None,
    );
    no_crypto(&retry);
    assert_eq!(value(retry)["value"], saved["value"]);
    let envelope: Envelope = serde_json::from_value(saved["value"].clone()).unwrap();
    assert_eq!(peer.receive(&envelope).unwrap().text, "你好\0🙂");
    let next = value(execute(
        &mut reopened,
        "send-2",
        send("a2", "m2", "next"),
        Fault::None,
    ));
    assert_eq!(
        peer.receive(&serde_json::from_value(next["value"].clone()).unwrap())
            .unwrap()
            .text,
        "next"
    );
    assert_eq!(inspect(&mut reopened)["encryptions"], "2");
    value(reopened.close());
}

#[test]
fn candidate_and_commit_failures_leave_persistent_pending_before_cache() {
    for fault in [
        Fault::AfterReserve,
        Fault::AfterCrypto,
        Fault::AfterSql,
        Fault::RefuseCommit,
    ] {
        let files = Files::new();
        let mut client = files.open(true);
        let _peer = group(&mut client);
        // 重试建群使用尚未消费的 KeyPackage，确保验证的是暂停门禁。
        let next_peer = MemoryPeer::new(&scope("bob-next", "b-next"))
            .unwrap()
            .identity();
        value(execute(
            &mut client,
            "old",
            send("a0", "m0", "old"),
            Fault::None,
        ));
        let prior = inspect(&mut client);
        let result = execute(
            &mut client,
            "failed",
            send("a1", "m1", "never-return"),
            fault,
        );
        assert!(!result.ok);
        assert!(result.events.is_empty());
        assert!(result.result.is_none());
        assert_eq!(
            result.metrics.candidate_sends,
            u32::from(fault != Fault::AfterReserve)
        );
        let paused = inspect(&mut client);
        assert!(paused["pending"].is_object());
        for field in [
            "revision",
            "provider_hash",
            "provider_bytes",
            "encryptions",
            "outbox",
            "result_count",
        ] {
            assert_eq!(paused[field], prior[field]);
        }
        value(client.close());
        drop(client);
        let mut reopened = files.open(false);
        assert_eq!(inspect(&mut reopened), paused);
        for (id, action) in [
            ("old", send("a0", "m0", "old")),
            ("failed", send("a1", "m1", "never-return")),
            ("new", send("a2", "m2", "new")),
            ("again-init", Action::Initialize {}),
            (
                "again-group",
                Action::CreateGroup {
                    conversation: "next".into(),
                    peer: next_peer.clone(),
                },
            ),
        ] {
            let response = execute(&mut reopened, id, action, Fault::None);
            no_crypto(&response);
            failed(response, "crypto_pending");
        }
        assert_eq!(inspect(&mut reopened), paused);
        value(reopened.close());
    }
}

#[test]
fn reservation_refusal_never_calls_provider_and_retry_after_reopen_is_safe() {
    let files = Files::new();
    let mut client = files.open(true);
    let before = inspect(&mut client);
    let denied = execute(
        &mut client,
        "init",
        Action::Initialize {},
        Fault::ReserveRefuse,
    );
    no_crypto(&denied);
    assert_eq!(denied.error.as_ref().unwrap().sqlite_code, Some(531));
    failed(denied, "commit_failed");
    assert_eq!(inspect(&mut client), before);
    value(client.close());
    drop(client);
    let mut reopened = files.open(false);
    let initialized = execute(&mut reopened, "init", Action::Initialize {}, Fault::None);
    assert_eq!(initialized.metrics.provider_news, 1);
    value(initialized);
    value(reopened.close());
}

#[test]
fn conflicts_are_prechecked_without_mutating_cryptographic_state() {
    let files = Files::new();
    let mut client = files.open(true);
    let _peer = group(&mut client);
    value(execute(
        &mut client,
        "send",
        send("a1", "m1", "saved"),
        Fault::None,
    ));
    let before = inspect(&mut client);
    for (id, action, code) in [
        (
            "send",
            send("a1", "m1", "changed"),
            "crypto_request_conflict",
        ),
        (
            "other",
            send("a1", "m1", "changed"),
            "crypto_attempt_conflict",
        ),
        (
            "other",
            send("a2", "m1", "saved"),
            "crypto_message_conflict",
        ),
    ] {
        let reply = execute(&mut client, id, action, Fault::None);
        no_crypto(&reply);
        failed(reply, code);
        assert_eq!(inspect(&mut client), before);
    }
    value(client.close());
}

#[test]
fn missing_reservation_table_cannot_be_recreated_to_bypass_pause() {
    let files = Files::new();
    let mut client = files.open(true);
    let _peer = group(&mut client);
    assert!(
        !execute(
            &mut client,
            "failed",
            send("a1", "m1", "x"),
            Fault::AfterCrypto
        )
        .ok
    );
    value(client.close());
    drop(client);
    // 仅故障夹具由 Rust 显式事务破坏测试库；不存在宿主 SQL 或修复入口。
    let mut db = rusqlite::Connection::open(files.db()).unwrap();
    let tx = db.transaction().unwrap();
    tx.execute_batch("DROP TABLE crypto_pending").unwrap();
    tx.commit().unwrap();
    db.close().unwrap();
    let bytes = fs::read(files.db()).unwrap();
    assert!(Client::open(files.db(), scope("alice", "a"), false).is_err());
    assert_eq!(fs::read(files.db()).unwrap(), bytes);
}

#[test]
fn existing_or_mismatched_store_never_silently_starts_new_identity() {
    let files = Files::new();
    assert!(Client::open(files.db(), scope("alice", "a"), false).is_err());
    let mut client = files.open(true);
    value(execute(
        &mut client,
        "init",
        Action::Initialize {},
        Fault::None,
    ));
    let before = inspect(&mut client);
    value(client.close());
    drop(client);
    assert!(Client::open(files.db(), scope("alice", "a"), true).is_err());
    assert!(Client::open(files.db(), scope("alice", "other-device"), false).is_err());
    let mut reopened = files.open(false);
    assert_eq!(inspect(&mut reopened), before);
    value(reopened.close());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(files.db()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn public_inspection_contains_no_private_provider_or_plaintext() {
    let files = Files::new();
    let mut client = files.open(true);
    let _peer = group(&mut client);
    value(execute(
        &mut client,
        "send",
        send("a1", "m1", "plaintext-only-in-input-14857"),
        Fault::None,
    ));
    let snapshot = inspect(&mut client);
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains("plaintext-only-in-input-14857"));
    assert!(snapshot.get("provider").is_none());
    assert!(snapshot.get("signature_id").is_none());
    assert_eq!(snapshot["pending"], json!(null));
    value(client.close());
}
