use super::{
    tests::{send, Pair},
    *,
};
pub(super) fn lose_candidate(device: &mut PersistentDevice, request: &str, action: Action) {
    let rid = request.to_string();
    let input = action.clone();
    let saved = device
        .database
        .call(move |db| {
            db.update(false, |s| {
                operations::prepare(s, &rid, &input)?;
                s.meta.journal = Some(journal::Journal {
                    request: rid,
                    input,
                    phase: journal::Phase::Executing,
                    seed: None,
                    candidate: None,
                });
                Ok(s.clone())
            })
        })
        .unwrap();
    let _lost = candidate::apply(Box::new(saved), request, &action).unwrap();
}
fn packet(result: RecoveryResult) -> String {
    result.packet.unwrap()
}
fn repair(p: &mut Pair, request: &str, action: Action) {
    let peer = p.a.state().unwrap().identity.unwrap();
    let offer = packet(
        p.a.recovery(RecoveryCommand::Begin {
            request_id: request.into(),
            action,
        })
        .unwrap(),
    );
    assert_eq!(
        packet(p.a.recovery(RecoveryCommand::Status).unwrap()),
        offer
    );
    let approval = packet(
        p.b.recovery(RecoveryCommand::Accept {
            offer: offer.clone(),
            peer: peer.clone(),
        })
        .unwrap(),
    );
    assert_eq!(
        packet(
            p.b.recovery(RecoveryCommand::Accept { offer, peer })
                .unwrap()
        ),
        approval
    );
    p.reopen();
    let ready = packet(
        p.a.recovery(RecoveryCommand::Join {
            approval: approval.clone(),
        })
        .unwrap(),
    );
    assert_eq!(
        packet(p.a.recovery(RecoveryCommand::Join { approval }).unwrap()),
        ready
    );
    assert_eq!(
        p.a.recovery(RecoveryCommand::Close { peer_close: None })
            .unwrap_err()
            .code,
        "recovery_close_not_allowed"
    );
    let confirmed =
        p.b.recovery(RecoveryCommand::Confirm {
            ready: ready.clone(),
        })
        .unwrap();
    assert!(confirmed.commit.is_some());
    let receipt = packet(confirmed);
    assert!(p
        .b
        .recovery(RecoveryCommand::Confirm { ready })
        .unwrap()
        .commit
        .is_none());
    p.reopen();
    assert!(p
        .a
        .recovery(RecoveryCommand::Finish {
            receipt: receipt.clone()
        })
        .unwrap()
        .commit
        .is_some());
    assert!(p
        .a
        .recovery(RecoveryCommand::Finish { receipt })
        .unwrap()
        .commit
        .is_none());
}
#[test]
fn uncertain_send_successor_preserves_identity_history_and_original_evidence() {
    let mut p = Pair::new();
    p.group();
    let old = send(&mut p.a, "old");
    p.b.execute(
        "old".into(),
        Action::Receive {
            envelope: old.clone(),
        },
    )
    .unwrap();
    let identities = (p.a.state().unwrap().identity, p.b.state().unwrap().identity);
    for n in 0..2 {
        let rid = format!("lost{n}");
        let action = Action::Send {
            message_id: rid.clone(),
            text: "uncertain".into(),
        };
        lose_candidate(&mut p.a, &rid, action.clone());
        p.reopen();
        assert_eq!(
            p.a.recover_request(rid.clone(), action.clone())
                .unwrap_err()
                .code,
            "successor_required"
        );
        repair(&mut p, &rid, action);
        assert!(matches!(
            p.a.request(rid).unwrap(),
            RequestState::Retired { .. }
        ));
        assert_eq!(
            (p.a.state().unwrap().identity, p.b.state().unwrap().identity),
            identities
        );
        assert!(p
            .a
            .message("alice".into(), "one".into(), "old".into())
            .unwrap()
            .is_some());
        assert_eq!(
            p.b.execute(
                format!("stale{n}"),
                Action::Receive {
                    envelope: old.clone()
                }
            )
            .unwrap_err()
            .code,
            "context_retired"
        );
        let e = send(&mut p.a, &format!("new{n}"));
        p.b.execute(format!("rx{n}"), Action::Receive { envelope: e })
            .unwrap();
        let e = send(&mut p.b, &format!("reply{n}"));
        p.a.execute(format!("back{n}"), Action::Receive { envelope: e })
            .unwrap();
        p.reopen();
    }
    p.a.database
        .call(|db| {
            db.read(|s| {
                assert_eq!(s.meta.archives.len(), 2);
                assert_eq!(
                    s.meta.archives[0].data.requests["lost0"].result,
                    RequestState::Pending
                );
                assert_ne!(s.crypto, s.meta.archives[0].crypto);
                Ok(())
            })
        })
        .unwrap();
}
#[test]
fn reserved_and_complete_candidate_recovery_is_exact_and_single_use() {
    let mut p = Pair::new();
    p.group();
    let action = Action::Send {
        message_id: "held".into(),
        text: "held".into(),
    };
    let input = action.clone();
    p.a.database
        .call(move |db| {
            db.update(false, |s| {
                operations::prepare(s, "held", &input)?;
                s.meta.journal = Some(journal::Journal {
                    request: "held".into(),
                    input,
                    phase: journal::Phase::Reserved,
                    seed: None,
                    candidate: None,
                });
                Ok(())
            })
        })
        .unwrap();
    p.reopen();
    let result = p.a.recover_request("held".into(), action.clone()).unwrap();
    let cached = p.a.recover_request("held".into(), action).unwrap();
    assert!(!result.cached && cached.cached);
    assert_eq!(result.value, cached.value);
    let Value::Sent { envelope } = result.value else {
        panic!()
    };
    p.b.execute("held".into(), Action::Receive { envelope })
        .unwrap();
}
#[test]
fn wrong_peer_material_and_conflicting_request_do_not_replace_offer() {
    let mut p = Pair::new();
    p.group();
    let action = Action::Send {
        message_id: "lost".into(),
        text: "lost".into(),
    };
    lose_candidate(&mut p.a, "lost", action.clone());
    let offer = packet(
        p.a.recovery(RecoveryCommand::Begin {
            request_id: "lost".into(),
            action: action.clone(),
        })
        .unwrap(),
    );
    let mut identity = p.a.state().unwrap().identity.unwrap();
    identity.scope.service = "other".into();
    assert!(p
        .b
        .recovery(RecoveryCommand::Accept {
            offer: offer.clone(),
            peer: identity
        })
        .is_err());
    assert!(p
        .b
        .recovery(RecoveryCommand::Status)
        .unwrap()
        .phase
        .is_none());
    let mut changed = action;
    if let Action::Send { text, .. } = &mut changed {
        *text = "different".into();
    }
    assert_eq!(
        p.a.recovery(RecoveryCommand::Begin {
            request_id: "lost".into(),
            action: changed
        })
        .unwrap_err()
        .code,
        "request_conflict"
    );
    assert_eq!(
        packet(p.a.recovery(RecoveryCommand::Status).unwrap()),
        offer
    );
}

#[test]
fn archived_commit_resolves_lagging_target_before_the_next_successor() {
    let mut p = Pair::new();
    p.group();
    let action = Action::Send {
        message_id: "lost".into(),
        text: "lost".into(),
    };
    lose_candidate(&mut p.a, "lost", action.clone());
    let pin = p.a.state().unwrap().identity.unwrap();
    let offer = packet(
        p.a.recovery(RecoveryCommand::Begin {
            request_id: "lost".into(),
            action,
        })
        .unwrap(),
    );
    let approval = packet(
        p.b.recovery(RecoveryCommand::Accept { offer, peer: pin })
            .unwrap(),
    );
    let ready = p.a.recovery(RecoveryCommand::Join { approval }).unwrap();
    let context = ready.context.unwrap();
    p.b.recovery(RecoveryCommand::Confirm {
        ready: ready.packet.unwrap(),
    })
    .unwrap();
    // 对端已提交，但目标尚未收到 Commit；对端下一发送又发生候选丢失。
    let next = Action::Send {
        message_id: "next-lost".into(),
        text: "next".into(),
    };
    lose_candidate(&mut p.b, "next-lost", next.clone());
    p.b.recovery(RecoveryCommand::Begin {
        request_id: "next-lost".into(),
        action: next,
    })
    .unwrap();
    p.reopen();
    let original = p.b.recovery(RecoveryCommand::Inspect { context }).unwrap();
    assert_eq!(original.phase, Some(RecoveryPhase::Committed));
    p.a.recovery(RecoveryCommand::Finish {
        receipt: original.packet.unwrap(),
    })
    .unwrap();
    let new_offer = packet(p.b.recovery(RecoveryCommand::Status).unwrap());
    let pin = p.b.state().unwrap().identity.unwrap();
    let approval = packet(
        p.a.recovery(RecoveryCommand::Accept {
            offer: new_offer,
            peer: pin,
        })
        .unwrap(),
    );
    let ready = packet(p.b.recovery(RecoveryCommand::Join { approval }).unwrap());
    let receipt = packet(p.a.recovery(RecoveryCommand::Confirm { ready }).unwrap());
    p.b.recovery(RecoveryCommand::Finish { receipt }).unwrap();
    let e = send(&mut p.a, "finished");
    p.b.execute("finished".into(), Action::Receive { envelope: e })
        .unwrap();
    let e = send(&mut p.b, "back");
    p.a.execute("back".into(), Action::Receive { envelope: e })
        .unwrap();
}

#[test]
fn recovery_capacity_rejects_before_creating_an_unfinishable_round() {
    let mut p = Pair::new();
    p.group();
    for n in 0..16 {
        let rid = format!("bounded-{n}");
        let action = Action::Send {
            message_id: rid.clone(),
            text: "bounded".into(),
        };
        lose_candidate(&mut p.a, &rid, action.clone());
        repair(&mut p, &rid, action);
    }
    // 最后一轮确实可以通信；后续超过明示保留上限的恢复必须原地拒绝。
    let e = send(&mut p.a, "last-valid");
    p.b.execute("last-valid".into(), Action::Receive { envelope: e })
        .unwrap();
    let action = Action::Send {
        message_id: "over-limit".into(),
        text: "over-limit".into(),
    };
    lose_candidate(&mut p.a, "over-limit", action.clone());
    let before =
        p.a.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap();
    assert_eq!(
        p.a.recovery(RecoveryCommand::Begin {
            request_id: "over-limit".into(),
            action
        })
        .unwrap_err()
        .code,
        "recovery_limit"
    );
    let after =
        p.a.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap();
    assert_eq!(before, after);
    p.reopen();
    assert_eq!(
        p.a.request("over-limit".into()).unwrap(),
        RequestState::Pending
    );
}
