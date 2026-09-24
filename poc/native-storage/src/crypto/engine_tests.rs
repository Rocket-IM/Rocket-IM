use super::Engine;
use crate::crypto::{contract::Scope, model::PlainMessage};
use crate::model::Error;
use serde_json::Value;

fn scope(account: &str) -> Scope {
    Scope {
        service: "native-test-service".into(),
        account: account.into(),
        device: format!("{account}-device"),
    }
}

fn paired() -> (Engine, Engine) {
    let mut alice = Engine::new(&scope("alice")).expect("创建 Alice");
    let mut bob = Engine::new(&scope("bob")).expect("创建 Bob");
    let alice_identity = alice.identity();
    let welcome = alice
        .create_group("conversation", &bob.identity())
        .expect("创建双成员群");
    bob.join_group("conversation", &alice_identity, &welcome)
        .expect("Bob 加入");
    (alice, bob)
}

fn error_code<T>(result: Result<T, Error>) -> String {
    match result {
        Ok(_) => panic!("应明确拒绝不合法输入"),
        Err(error) => error.code,
    }
}

#[test]
fn real_openmls_initialization_join_and_bidirectional_messages() {
    let (mut alice, mut bob) = paired();
    assert_eq!(alice.conversation().as_deref(), Some("conversation"));
    assert_eq!(bob.conversation().as_deref(), Some("conversation"));
    assert!(alice.identity().key_package.is_empty());
    assert!(bob.identity().key_package.is_empty());

    let sent = alice.send("message-1", "合成实验消息").expect("Alice 发送");
    assert_eq!(
        bob.receive(&sent).expect("Bob 接收"),
        PlainMessage {
            message_id: "message-1".into(),
            sender_account: "alice".into(),
            text: "合成实验消息".into(),
        }
    );
    let reply = bob.send("message-2", "合成回复").expect("Bob 发送");
    assert_eq!(alice.receive(&reply).expect("Alice 接收").text, "合成回复");
}

#[test]
fn provider_restore_preserves_identity_and_next_message_state() {
    let initial = Engine::new(&scope("alice")).expect("创建身份");
    let initial_snapshot = initial.export().expect("导出未入群状态");
    let saved: Value = serde_json::from_slice(&initial_snapshot).expect("解析当前快照");
    assert_eq!(saved["format"], "Rocket-IM/native-crypto/state/v1");
    let restored = Engine::restore(&initial_snapshot, &scope("alice")).expect("恢复身份");
    assert_eq!(initial.identity(), restored.identity());
    assert!(restored.conversation().is_none());

    let (mut alice, mut bob) = paired();
    let first = alice.send("message-before", "保存前").expect("第一条发送");
    assert_eq!(bob.receive(&first).expect("第一条接收").text, "保存前");
    let alice_snapshot = alice.export().expect("导出发送状态");
    let bob_snapshot = bob.export().expect("导出接收状态");
    let mut alice = Engine::restore(&alice_snapshot, &scope("alice")).expect("恢复发送方");
    let mut bob = Engine::restore(&bob_snapshot, &scope("bob")).expect("恢复接收方");
    let second = alice.send("message-after", "恢复后").expect("恢复后发送");
    assert_ne!(first.ciphertext, second.ciphertext);
    assert_eq!(bob.receive(&second).expect("恢复后接收").text, "恢复后");
    let reply = bob.send("reply-after", "恢复后回复").expect("恢复后回复");
    assert_eq!(
        alice.receive(&reply).expect("恢复后接收回复").text,
        "恢复后回复"
    );
}

#[test]
fn restore_rejects_other_service_account_or_device() {
    let engine = Engine::new(&scope("alice")).expect("创建身份");
    let snapshot = engine.export().expect("导出状态");
    for field in ["service", "account", "device"] {
        let mut other = scope("alice");
        match field {
            "service" => other.service = "other-service".into(),
            "account" => other.account = "other-account".into(),
            _ => other.device = "other-device".into(),
        }
        assert_eq!(
            error_code(Engine::restore(&snapshot, &other)),
            "crypto_state_corrupt"
        );
    }
}

#[test]
fn restore_rejects_foreign_or_unknown_snapshot_versions() {
    let engine = Engine::new(&scope("alice")).expect("创建身份");
    let snapshot = engine.export().expect("导出状态");
    for (field, value) in [
        // 旧工程名仅作为拒绝回归输入保留，不能重新接受旧密码状态。
        ("format", "Rockets-IM/native-crypto/state/v1"),
        ("format", "Rocket-IM/browser-crypto/state/v1"),
        ("format", "Rocket-IM/native-crypto/state/v2"),
        ("openmls_version", "0.0.0"),
        ("provider_version", "0.0.0"),
    ] {
        let mut state: Value = serde_json::from_slice(&snapshot).expect("测试快照解析");
        state[field] = value.into();
        let encoded = serde_json::to_vec(&state).expect("测试快照编码");
        assert_eq!(
            error_code(Engine::restore(&encoded, &scope("alice"))),
            "crypto_state_corrupt"
        );
    }
}

#[test]
fn restore_rejects_duplicate_or_unordered_provider_entries() {
    let engine = Engine::new(&scope("alice")).expect("创建身份");
    let snapshot = engine.export().expect("导出状态");
    for duplicate in [false, true] {
        let mut state: Value = serde_json::from_slice(&snapshot).expect("测试快照解析");
        let entries = state["entries"].as_array_mut().expect("provider 条目数组");
        assert!(entries.len() >= 2);
        if duplicate {
            entries[1] = entries[0].clone();
        } else {
            entries.swap(0, 1);
        }
        let encoded = serde_json::to_vec(&state).expect("测试快照编码");
        assert_eq!(
            error_code(Engine::restore(&encoded, &scope("alice"))),
            "crypto_state_corrupt"
        );
    }
}

#[test]
fn changed_authenticated_message_context_discards_candidate() {
    let (mut alice, mut bob) = paired();
    let valid = alice.send("message", "合成消息").expect("发送");
    let mut changed = valid.clone();
    changed.message_id = "different-message".into();
    assert_eq!(
        error_code(bob.receive(&changed)),
        "crypto_identity_mismatch"
    );
    assert_eq!(error_code(bob.receive(&valid)), "crypto_paused");
    assert_eq!(error_code(bob.export()), "crypto_paused");
}

#[test]
fn identity_and_snapshot_bounds_are_checked_before_use() {
    let mut invalid = scope("alice");
    invalid.device.clear();
    assert_eq!(error_code(Engine::new(&invalid)), "invalid_id");
    assert_eq!(
        error_code(Engine::restore(&[], &scope("alice"))),
        "crypto_limit"
    );
    let oversized = vec![0; crate::crypto::model::MAX_STATE_BYTES + 1];
    assert_eq!(
        error_code(Engine::restore(&oversized, &scope("alice"))),
        "crypto_limit"
    );
}
