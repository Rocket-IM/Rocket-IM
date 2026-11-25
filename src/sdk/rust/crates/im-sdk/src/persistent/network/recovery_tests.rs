use super::super::{
    recovery_types::{Body, RecoveryCommand},
    recovery_wire as wire,
    tests::{send, Pair},
    types::*,
    PersistentDevice,
};
use super::{
    recovery_commands::save, recovery_types::*, recovery_validation::validate_round, types::*,
};

fn attach(p: &mut Pair) {
    let a = p.a.state().unwrap().identity.unwrap();
    let b = p.b.state().unwrap().identity.unwrap();
    for (d, peer, creator) in [(&p.a, b, true), (&p.b, a, false)] {
        d.database
            .call(move |db| {
                db.update(false, |s| {
                    s.data.network = Some(NetworkData::new(Binding {
                        url: "wss://127.0.0.1:1/v1/ws".into(),
                        ca_hash: "01".repeat(32),
                        conversation: "chat".into(),
                        peer,
                        creator,
                    }));
                    Ok(())
                })
            })
            .unwrap();
    }
}
fn set_round(d: &PersistentDevice, round: &Round) {
    let round = round.clone();
    d.database
        .call(move |db| {
            db.update(false, |s| {
                let n = s.data.network.as_mut().unwrap();
                let r = n.recovery.get_or_insert_with(RecoveryData::default);
                r.round = Some(round);
                Ok(())
            })
        })
        .unwrap();
}
fn packet(d: &mut PersistentDevice, command: RecoveryCommand) -> String {
    d.recovery_internal(command).unwrap().packet.unwrap()
}
#[test]
fn bilateral_install_gate_signed_binding_and_retained_history() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let old = send(&mut p.a, "old");
    p.b.execute("old".into(), Action::Receive { envelope: old })
        .unwrap();
    let identity = p.a.state().unwrap().identity;
    let action = Action::Send {
        message_id: "lost".into(),
        text: "private".into(),
    };
    super::super::recovery_tests::lose_candidate(&mut p.a, "lost", action.clone());
    p.a.network_recovery(NetworkRecoveryCommand::Begin {
        request_id: "lost".into(),
        action: action.clone(),
    })
    .unwrap();
    let saved = p.a.database.call(|db| db.read(Ok)).unwrap();
    let mut local = saved.data.network.unwrap().recovery.unwrap();
    let q = local.intent.clone().unwrap();
    let mut r = Round {
        reservation: q.clone(),
        context: None,
        status: "reserved".into(),
        materials: Default::default(),
    };
    local.round = Some(r.clone());
    save(&p.a, local).unwrap();
    let offer = packet(
        &mut p.a,
        RecoveryCommand::Begin {
            request_id: "lost".into(),
            action,
        },
    );
    let context =
        p.a.recovery(RecoveryCommand::Status)
            .unwrap()
            .context
            .unwrap();
    r.context = Some(context.clone());
    r.materials.insert("offer".into(), offer.clone());
    r.status = "offered".into();
    set_round(&p.a, &r);
    set_round(&p.b, &r);
    assert_eq!(
        p.a.network_recovery(NetworkRecoveryCommand::Approve {
            round_id: q.id.clone()
        })
        .unwrap_err()
        .code,
        "recovery_role_mismatch"
    );
    assert_eq!(
        p.b.recovery(RecoveryCommand::Accept {
            offer: offer.clone(),
            peer: q.target.clone()
        })
        .unwrap_err()
        .code,
        "network_recovery_managed"
    );
    let before = p.b.state().unwrap();
    for mutate in 0..7 {
        let mut bad = r.clone();
        match mutate {
            0 => bad.reservation.target.scope.service = "other".into(),
            1 => bad.reservation.target.scope.account = "other".into(),
            2 => bad.reservation.peer.scope.device = "other".into(),
            3 => bad.reservation.conversation = "other".into(),
            4 => bad.reservation.old_context = "other".into(),
            5 => bad.reservation.request_hash = "00".repeat(32),
            _ => bad.reservation.deadline = "1".into(),
        }
        let data = p.b.database.call(|db| db.read(|s| Ok(s.data))).unwrap();
        assert!(validate_round(&data, &bad).is_err());
    }
    assert_eq!(p.b.state().unwrap(), before);
    p.b.network_recovery(NetworkRecoveryCommand::Approve {
        round_id: q.id.clone(),
    })
    .unwrap();
    let approval = packet(
        &mut p.b,
        RecoveryCommand::Accept {
            offer,
            peer: q.target.clone(),
        },
    );
    r.materials.insert("approval".into(), approval.clone());
    r.status = "approved".into();
    set_round(&p.a, &r);
    set_round(&p.b, &r);
    p.reopen();
    let ready = packet(&mut p.a, RecoveryCommand::Join { approval });
    r.materials.insert("ready".into(), ready.clone());
    r.status = "ready".into();
    set_round(&p.a, &r);
    set_round(&p.b, &r);
    assert_eq!(
        p.a.network_recovery(NetworkRecoveryCommand::Seal {
            round_id: q.id.clone()
        })
        .unwrap_err()
        .code,
        "recovery_close_not_allowed"
    );
    let receipt = packet(&mut p.b, RecoveryCommand::Confirm { ready });
    r.materials.insert("commit".into(), receipt.clone());
    r.status = "committed".into();
    set_round(&p.a, &r);
    set_round(&p.b, &r);
    assert_eq!(
        p.b.execute(
            "early".into(),
            Action::Send {
                message_id: "early".into(),
                text: "wait".into()
            }
        )
        .unwrap_err()
        .code,
        "recovery_active"
    );
    p.a.recovery_internal(RecoveryCommand::Finish {
        receipt: receipt.clone(),
    })
    .unwrap();
    for (d, key) in [(&p.a, "installed_target"), (&p.b, "installed_peer")] {
        let s = d.database.call(|db| db.read(Ok)).unwrap();
        r.materials.insert(
            key.into(),
            wire::sign(
                &s,
                Body::Installed {
                    context: context.clone(),
                    receipt_hash: hash(receipt.as_bytes()),
                },
            )
            .unwrap(),
        );
    }
    r.status = "complete".into();
    set_round(&p.a, &r);
    set_round(&p.b, &r);
    p.reopen();
    assert_eq!(p.a.state().unwrap().identity, identity);
    assert!(matches!(
        p.a.request("lost".into()).unwrap(),
        RequestState::Retired { .. }
    ));
    let e = send(&mut p.a, "new");
    p.b.execute("new".into(), Action::Receive { envelope: e })
        .unwrap();
    assert!(p
        .b
        .message("alice".into(), "one".into(), "old".into())
        .unwrap()
        .is_some());
}

#[test]
fn full_candidate_cannot_be_replaced_by_network_recovery() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    p.a.database
        .call(|db| {
            db.update(false, |s| {
                super::super::operations::prepare(
                    s,
                    "reserved",
                    &Action::Send {
                        message_id: "reserved".into(),
                        text: "kept".into(),
                    },
                )?;
                s.meta.journal = Some(super::super::journal::Journal {
                    request: "reserved".into(),
                    input: Action::Send {
                        message_id: "reserved".into(),
                        text: "kept".into(),
                    },
                    phase: super::super::journal::Phase::Reserved,
                    seed: None,
                    candidate: None,
                });
                Ok(())
            })
        })
        .unwrap();
    let action = Action::Send {
        message_id: "reserved".into(),
        text: "kept".into(),
    };
    assert_eq!(
        p.a.network_recovery(NetworkRecoveryCommand::Begin {
            request_id: "reserved".into(),
            action: action.clone()
        })
        .unwrap_err()
        .code,
        "request_recoverable"
    );
    p.a.recover_request("reserved".into(), action).unwrap();
    assert!(p
        .a
        .network_recovery(NetworkRecoveryCommand::Status)
        .unwrap()
        .is_none());
}
