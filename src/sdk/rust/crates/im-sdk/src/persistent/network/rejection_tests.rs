//! 分类/事务/容量内部夹具；完整256条真实E2EE链另由独立Release消费验收。
use super::{rejection, types::*, NetworkSession};
use crate::persistent::{
    data::{Record, Saved, StoredMessage},
    operations,
    tests::{send, Pair},
    types::*,
    HistoryDirection, HistoryQuery,
};

pub(super) fn attach(p: &mut Pair) {
    let peer = p.a.state().unwrap().identity.unwrap();
    p.b.database
        .call(move |db| {
            db.update(false, |s| {
                s.data.network = Some(NetworkData::new(Binding {
                    url: "wss://127.0.0.1:1/v1/ws".into(),
                    ca_hash: "01".repeat(32),
                    conversation: "chat".into(),
                    peer,
                    creator: false,
                }));
                Ok(())
            })
        })
        .unwrap();
}
pub(super) fn reject(s: &mut Saved, request: &str, envelope: &Envelope) -> Result<()> {
    rejection::commit(
        s,
        request,
        envelope,
        rejection::SendRejection::from_service_send(&Error::new("message_limit")).unwrap(),
    )
}
fn query(cursor: Option<String>) -> HistoryQuery {
    HistoryQuery {
        page_size: 1,
        direction: HistoryDirection::Forward,
        cursor,
    }
}

#[test]
fn only_authenticated_send_message_limit_is_permanent() {
    assert!(rejection::SendRejection::from_service_send(&Error::new("message_limit")).is_some());
    for code in [
        "unauthorized",
        "forbidden",
        "storage_unavailable",
        "network_unavailable",
        "idempotency_conflict",
        "context_not_accepted",
        "successor_required",
        "request_limit",
        "storage_limit",
        "invalid_request",
        "group_not_ready",
        "cancelled",
        "commit_unknown",
    ] {
        assert!(
            rejection::SendRejection::from_service_send(&Error::new(code)).is_none(),
            "{code}"
        );
    }
    assert!(rejection::SendRejection::from_service_send(&Error::paused("message_limit")).is_none());
}

#[test]
fn real_mls_original_retry_history_cursor_and_reopen_preserve_terminal() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let e = send(&mut p.b, "rejected");
    send(&mut p.b, "later");
    let first = p.b.history(query(None)).unwrap();
    let before = p.b.database.call(|db| db.read(Ok)).unwrap();
    let copy = e.clone();
    p.b.database
        .call(move |db| db.update(true, |s| reject(s, "rejected", &copy)))
        .unwrap();
    let after = p.b.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(before.crypto, after.crypto);
    assert_eq!(encode(&before.meta).unwrap(), encode(&after.meta).unwrap());
    assert_eq!(before.data.state, after.data.state);
    assert_eq!(
        encode(&before.data.requests["rejected"].result).unwrap(),
        encode(&after.data.requests["rejected"].result).unwrap()
    );
    assert_eq!(
        before.data.history_messages().unwrap().len(),
        after.data.history_messages().unwrap().len()
    );
    assert!(encode(&after.data).unwrap().len() < encode(&before.data).unwrap().len());
    assert_eq!(
        p.b.history(query(first.next_cursor.clone())).unwrap().items[0]
            .message
            .message_id,
        "later"
    );
    let fingerprint = operations::fingerprint(&after).unwrap();
    let copy = e.clone();
    p.b.database
        .call(move |db| db.update(true, |s| reject(s, "rejected", &copy)))
        .unwrap();
    assert_eq!(
        fingerprint,
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap()
    );
    p.reopen();
    let state = NetworkSession::offline_state(&p.b).unwrap();
    let terminal = state
        .sending
        .iter()
        .find(|s| s.message_id == "rejected")
        .unwrap();
    assert_eq!(terminal.status, "rejected");
    assert!(terminal.acceptance.is_none());
    assert!(p.b.history(query(None)).unwrap().items[0]
        .rejection
        .is_some());
    let original = Action::Send {
        message_id: "rejected".into(),
        text: "测试 rejected".into(),
    };
    assert_eq!(
        p.b.execute("rejected".into(), original.clone())
            .unwrap()
            .value,
        Value::Sent {
            envelope: e.clone()
        }
    );
    assert_eq!(
        p.b.execute("other".into(), original).unwrap_err().code,
        "message_conflict"
    );
    assert_eq!(
        p.b.execute(
            "rejected".into(),
            Action::Send {
                message_id: "rejected".into(),
                text: "changed".into()
            }
        )
        .unwrap_err()
        .code,
        "request_conflict"
    );
    for name in ["incoming1", "incoming2"] {
        let envelope = send(&mut p.a, name);
        p.b.execute(name.into(), Action::Receive { envelope })
            .unwrap();
    }
    // 缺少原始输入、被伪造的接受以及未知终态都不能载入。
    let good = p.b.database.call(|db| db.read(Ok)).unwrap();
    let mut bad = good.data.clone();
    bad.requests.get_mut("rejected").unwrap().input = None;
    assert!(bad.validate(&good.crypto).is_err());
    let mut bad = good.data.clone();
    bad.network.as_mut().unwrap().accepted.insert(
        "rejected".into(),
        Acceptance {
            request_id: "rejected".into(),
            message_id: "rejected".into(),
            sequence: "1".into(),
            envelope_hash: hash(&encode(&e).unwrap()),
        },
    );
    assert!(bad.validate(&good.crypto).is_err());
    let mut raw = serde_json::to_value(&good.data).unwrap();
    raw["requests"]["rejected"]["rejection"]["code"] = "unauthorized".into();
    assert!(serde_json::from_value::<crate::persistent::data::Data>(raw).is_err());
}

fn synthetic_messages(s: &mut Saved, count: usize) {
    // 仅测试计额与关系校验；这些填充信封不是E2EE互通证据。
    for i in s.data.messages.len()..count {
        let message_id = format!("fixture-{i}");
        let action = Action::Send {
            message_id: message_id.clone(),
            text: "capacity fixture".into(),
        };
        let e = Envelope {
            service: s.data.state.scope.service.clone(),
            conversation: "chat".into(),
            sender_account: s.data.state.scope.account.clone(),
            sender_device: s.data.state.scope.device.clone(),
            message_id: message_id.clone(),
            context: s.data.state.context.clone(),
            ciphertext: format!("{i:08x}"),
        };
        let revision = (number(&s.data.state.revision).unwrap() + 1).to_string();
        s.data.requests.insert(
            message_id.clone(),
            Record {
                hash: hash(&encode(&action).unwrap()),
                input: Some(action),
                action: "send".into(),
                result: RequestState::Complete {
                    outcome: Outcome {
                        revision: revision.clone(),
                        cached: false,
                        value: Value::Sent {
                            envelope: e.clone(),
                        },
                    },
                },
                rejection: None,
            },
        );
        s.data.messages.push(StoredMessage {
            message: Message {
                service: e.service.clone(),
                conversation: e.conversation.clone(),
                sender_account: e.sender_account.clone(),
                sender_device: e.sender_device.clone(),
                message_id,
                context: e.context.clone(),
                text: "capacity fixture".into(),
            },
            envelope: e,
            receipt: None,
        });
        s.data.state.revision = revision;
    }
}

#[test]
fn bounded_ledger_reclaims_only_rejected_projections_and_preserves_all_limits() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    p.b.database
        .call(|db| {
            db.update(false, |s| {
                synthetic_messages(s, 256);
                Ok(())
            })
        })
        .unwrap();
    assert_eq!(
        p.b.execute(
            "full".into(),
            Action::Send {
                message_id: "full".into(),
                text: "full".into()
            }
        )
        .unwrap_err()
        .code,
        "message_limit"
    );
    for request in ["fixture-254", "fixture-255"] {
        p.b.database
            .call(move |db| {
                db.update(true, |s| {
                    let e = rejection::original(&s.data.requests[request])?.envelope;
                    reject(s, request, &e)
                })
            })
            .unwrap();
    }
    for name in ["incoming1", "incoming2"] {
        let envelope = send(&mut p.a, name);
        p.b.execute(name.into(), Action::Receive { envelope })
            .unwrap();
    }
    let mut saved = p.b.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(saved.data.messages.len(), 256);
    assert_eq!(saved.data.history_messages().unwrap().len(), 258);
    assert_eq!(
        p.b.execute(
            "full2".into(),
            Action::Send {
                message_id: "full2".into(),
                text: "full".into()
            }
        )
        .unwrap_err()
        .code,
        "message_limit"
    );
    while saved.data.requests.len() < 1024 {
        let id = format!("failed-{}", saved.data.requests.len());
        let action = Action::Send {
            message_id: id.clone(),
            text: "fixture".into(),
        };
        saved.data.requests.insert(
            id,
            Record {
                hash: hash(&encode(&action).unwrap()),
                input: Some(action),
                action: "send".into(),
                result: RequestState::Failed {
                    error: Error::new("fixture"),
                },
                rejection: None,
            },
        );
    }
    saved.data.validate(&saved.crypto).unwrap();
    let r = saved.data.requests["fixture-253"].clone();
    let e = rejection::original(&r).unwrap().envelope;
    reject(&mut saved, "fixture-253", &e).unwrap();
    saved.data.validate(&saved.crypto).unwrap();
    assert_eq!(saved.data.requests.len(), 1024);
    assert_eq!(
        operations::prepare(
            &mut saved,
            "new",
            &Action::Send {
                message_id: "new".into(),
                text: "x".into()
            }
        )
        .err()
        .unwrap()
        .code,
        "request_limit"
    );
    assert_eq!(crate::persistent::data::MAX_DATA, 16 * 1024 * 1024);
    assert_eq!(crate::persistent::store::MAX_META, 32 * 1024 * 1024);
}

#[test]
fn rejection_rollback_unknown_execution_and_format_gate_preserve_previous_state() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let e = send(&mut p.b, "rejected");
    let before = p.b.database.call(|db| db.read(Ok)).unwrap();
    let copy = e.clone();
    let error =
        p.b.database
            .call(move |db| {
                db.update(true, |s| {
                    reject(s, "rejected", &copy)?;
                    Err::<(), _>(Error::new("fixture_abort"))
                })
            })
            .unwrap_err();
    assert_eq!(error.code, "fixture_abort");
    assert_eq!(
        operations::fingerprint(&before).unwrap(),
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap()
    );
    let action = Action::Send {
        message_id: "unknown".into(),
        text: "unknown".into(),
    };
    crate::persistent::recovery_tests::lose_candidate(&mut p.b, "unknown", action.clone());
    let copy = e.clone();
    assert_eq!(
        p.b.database
            .call(move |db| db.update(true, |s| reject(s, "rejected", &copy)))
            .unwrap_err()
            .code,
        "recovery_active"
    );
    assert_eq!(
        p.b.recover_request("unknown".into(), action)
            .unwrap_err()
            .code,
        "successor_required"
    );
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let e = send(&mut p.b, "rejected");
    p.b.database
        .call(move |db| db.update(false, |s| reject(s, "rejected", &e)))
        .unwrap();
    let version =
        p.b.database
            .call(|db| {
                let tx = db.connection.transaction()?;
                let v: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
                tx.commit()?;
                Ok(v)
            })
            .unwrap();
    assert_eq!(version, 5);
    p.reopen();
}
