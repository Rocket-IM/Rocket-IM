use super::*;
use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
pub(super) struct Pair {
    root: PathBuf,
    pub(super) a: PersistentDevice,
    pub(super) b: PersistentDevice,
}
fn scope(account: &str) -> Scope {
    Scope {
        service: "test".into(),
        account: account.into(),
        device: "one".into(),
    }
}
impl Pair {
    pub(super) fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "rocket-persist-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root).unwrap();
        let a = PersistentDevice::open(root.join("a.db"), scope("alice"), true).unwrap();
        let b = PersistentDevice::open(root.join("b.db"), scope("bob"), true).unwrap();
        Self { root, a, b }
    }
    fn init(&mut self) {
        self.a.execute("init".into(), Action::Initialize).unwrap();
        self.b.execute("init".into(), Action::Initialize).unwrap();
    }
    pub(super) fn group(&mut self) {
        self.init();
        let a = self.a.joining_material().unwrap();
        let b = self.b.joining_material().unwrap();
        let result = self
            .a
            .execute(
                "create".into(),
                Action::CreateGroup {
                    conversation: "chat".into(),
                    peer: b.identity,
                    key_package: b.key_package,
                },
            )
            .unwrap();
        let Value::Created { welcome } = result.value else {
            panic!()
        };
        self.b
            .execute(
                "join".into(),
                Action::JoinGroup {
                    conversation: "chat".into(),
                    peer: a.identity,
                    welcome,
                },
            )
            .unwrap();
    }
    pub(super) fn reopen(&mut self) {
        self.a.close().unwrap();
        self.b.close().unwrap();
        self.a = PersistentDevice::open(self.root.join("a.db"), scope("alice"), false).unwrap();
        self.b = PersistentDevice::open(self.root.join("b.db"), scope("bob"), false).unwrap();
    }
}
impl Drop for Pair {
    fn drop(&mut self) {
        let _ = self.a.close();
        let _ = self.b.close();
        let _ = fs::remove_dir_all(&self.root);
    }
}
pub(super) fn send(d: &mut PersistentDevice, id: &str) -> Envelope {
    let r = d
        .execute(
            id.into(),
            Action::Send {
                message_id: id.into(),
                text: format!("测试 {id}"),
            },
        )
        .unwrap();
    let Value::Sent { envelope } = r.value else {
        panic!()
    };
    envelope
}
#[test]
fn dual_persistent_join_restart_messages_and_exact_retry() {
    let mut p = Pair::new();
    p.group();
    let e = send(&mut p.a, "first");
    let r =
        p.b.execute(
            "rx".into(),
            Action::Receive {
                envelope: e.clone(),
            },
        )
        .unwrap();
    assert!(!r.cached);
    let before = p.b.state().unwrap();
    assert!(
        p.b.execute(
            "duplicate".into(),
            Action::Receive {
                envelope: e.clone()
            }
        )
        .unwrap()
        .cached
    );
    assert_eq!(p.b.state().unwrap(), before);
    p.reopen();
    let retry =
        p.a.execute(
            "first".into(),
            Action::Send {
                message_id: "first".into(),
                text: "测试 first".into(),
            },
        )
        .unwrap();
    assert!(retry.cached);
    assert_eq!(retry.value, Value::Sent { envelope: e });
    assert!(p
        .b
        .message("alice".into(), "one".into(), "first".into())
        .unwrap()
        .is_some());
    let back = send(&mut p.b, "reply");
    p.a.execute("back".into(), Action::Receive { envelope: back })
        .unwrap();
    p.reopen();
    let e = send(&mut p.a, "next");
    p.b.execute("next-rx".into(), Action::Receive { envelope: e })
        .unwrap();
    assert_eq!(p.a.state().unwrap().received_count, "1");
    assert_eq!(p.b.state().unwrap().received_count, "2");
}
#[test]
fn wrong_pin_request_conflict_scope_and_fresh_history_are_rejected() {
    let mut p = Pair::new();
    p.init();
    let mut b = p.b.joining_material().unwrap();
    b.identity.identity_key = "00".repeat(32);
    assert_eq!(
        p.a.execute(
            "bad-pin".into(),
            Action::CreateGroup {
                conversation: "chat".into(),
                peer: b.identity,
                key_package: b.key_package
            }
        )
        .unwrap_err()
        .code,
        "identity_mismatch"
    );
    assert_eq!(p.a.state().unwrap().revision, "1");
    assert!(p.a.state().unwrap().pending_request.is_none());
    p.reopen();
    assert_eq!(
        p.a.execute(
            "init".into(),
            Action::Send {
                message_id: "x".into(),
                text: "x".into()
            }
        )
        .unwrap_err()
        .code,
        "request_conflict"
    );
    assert!(PersistentDevice::open(p.root.join("a.db"), scope("mallory"), false).is_err());
    assert!(p
        .b
        .message("alice".into(), "one".into(), "old".into())
        .unwrap()
        .is_none());
}
#[test]
fn input_and_ciphertext_conflicts_do_not_advance_state() {
    let mut p = Pair::new();
    p.group();
    let e = send(&mut p.a, "one");
    p.b.execute(
        "rx".into(),
        Action::Receive {
            envelope: e.clone(),
        },
    )
    .unwrap();
    let before = p.b.state().unwrap();
    let mut changed = e;
    changed.message_id = "spoof".into();
    assert_eq!(
        p.b.execute("conflict".into(), Action::Receive { envelope: changed })
            .unwrap_err()
            .code,
        "message_conflict"
    );
    assert_eq!(p.b.state().unwrap(), before);
    assert_eq!(
        p.a.execute(
            "other".into(),
            Action::Send {
                message_id: "one".into(),
                text: "other".into()
            }
        )
        .unwrap_err()
        .code,
        "message_conflict"
    );
}
#[test]
fn reservation_and_commit_failure_preserve_previous_state() {
    let mut p = Pair::new();
    p.group();
    let input = Action::Send {
        message_id: "pending".into(),
        text: "pending".into(),
    };
    let prepared =
        p.a.database
            .call(move |db| db.update(false, |s| operations::prepare(s, "pending", &input)))
            .unwrap();
    assert!(matches!(prepared, operations::Preparation::Ready(_)));
    p.reopen();
    assert_eq!(p.a.state().unwrap().revision, "2");
    assert_eq!(
        p.a.request("pending".into()).unwrap(),
        RequestState::Pending
    );
    assert_eq!(
        p.a.execute(
            "new".into(),
            Action::Send {
                message_id: "new".into(),
                text: "new".into()
            }
        )
        .unwrap_err()
        .code,
        "operation_pending"
    );
    assert!(p
        .a
        .message("alice".into(), "one".into(), "pending".into())
        .unwrap()
        .is_none());
}
#[test]
fn reopen_refuses_poc_or_corrupt_format_without_reset() {
    let mut p = Pair::new();
    p.init();
    p.a.close().unwrap();
    let path = p.root.join("a.db");
    let bytes = fs::read(&path).unwrap();
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute_batch("PRAGMA application_id=7").unwrap();
    tx.commit().unwrap();
    drop(conn);
    let damaged = fs::read(&path).unwrap();
    assert_ne!(bytes, damaged);
    assert_eq!(
        PersistentDevice::open(path.clone(), scope("alice"), false)
            .err()
            .unwrap()
            .code,
        "store_format_unsupported"
    );
    assert_eq!(fs::read(path).unwrap(), damaged);
}

#[test]
fn maximum_control_character_text_is_not_expanded_before_encryption() {
    let mut p = Pair::new();
    p.group();
    let text = "\0".repeat(32768);
    let r =
        p.a.execute(
            "control".into(),
            Action::Send {
                message_id: "control".into(),
                text: text.clone(),
            },
        )
        .unwrap();
    let Value::Sent { envelope } = r.value else {
        panic!()
    };
    let r =
        p.b.execute("control".into(), Action::Receive { envelope })
            .unwrap();
    let Value::Received { message, .. } = r.value else {
        panic!()
    };
    assert_eq!(message.text, text);
    p.reopen();
    assert_eq!(
        p.b.message("alice".into(), "one".into(), "control".into())
            .unwrap()
            .unwrap()
            .text,
        text
    );
}

#[test]
fn concurrent_handles_share_one_durable_reservation() {
    let mut p = Pair::new();
    p.group();
    let mut other = PersistentDevice::open(p.root.join("a.db"), scope("alice"), false).unwrap();
    let input = Action::Send {
        message_id: "held".into(),
        text: "held".into(),
    };
    p.a.database
        .call(move |db| db.update(false, |s| operations::prepare(s, "held", &input)))
        .unwrap();
    assert_eq!(
        other
            .execute(
                "other".into(),
                Action::Send {
                    message_id: "other".into(),
                    text: "other".into()
                }
            )
            .unwrap_err()
            .code,
        "operation_pending"
    );
    assert_eq!(other.state().unwrap().revision, "2");
    other.close().unwrap();
}
