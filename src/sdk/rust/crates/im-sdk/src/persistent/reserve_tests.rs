//! 真实MLS候选与生产写事务；字节填充明确为非E2EE容量夹具。
use super::{tests::Pair, *};

#[test]
fn reserve_candidate_is_exact_persistent_and_idempotent() {
    let mut p = Pair::new();
    p.group();
    let action = Action::Send {
        message_id: "reserved-candidate".into(),
        text: "真实候选".into(),
    };
    let input = action.clone();
    p.a.database
        .call(move |db| {
            db.update(false, |s| {
                operations::prepare(s, "reserved-candidate", &input)?;
                s.meta.journal = Some(journal::Journal {
                    request: "reserved-candidate".into(),
                    input: input.clone(),
                    phase: journal::Phase::Executing,
                    seed: None,
                    candidate: None,
                });
                let (c, _) = candidate::apply(Box::new(s.clone()), "reserved-candidate", &input)?;
                s.meta.journal.as_mut().unwrap().candidate = Some(journal::Candidate {
                    data: c.data,
                    crypto: c.crypto,
                });
                budget_tests::pad_meta(s, store::MAX_META - 256);
                Ok(())
            })
        })
        .unwrap();
    let expected =
        p.a.database
            .call(|db| db.read(|s| journal::installed(&s)))
            .unwrap();
    let capacity = p.a.reserve_capacity().unwrap();
    assert_eq!(capacity.reserve.state, "bounded_ready");
    assert_eq!(capacity.reserve.work[0].count, "1");
    assert_eq!(
        capacity
            .operations
            .iter()
            .find(|o| o.operation == "install_candidate")
            .unwrap()
            .state,
        CapacityOperationState::BoundedReady
    );
    let fingerprint =
        p.a.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap();
    assert_eq!(p.a.reserve_capacity().unwrap().reserve, capacity.reserve);
    assert_eq!(
        p.a.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap(),
        fingerprint
    );
    p.reopen();
    let result =
        p.a.recover_request("reserved-candidate".into(), action.clone())
            .unwrap();
    let actual = p.a.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(actual.crypto, expected.crypto);
    assert_eq!(
        encode(&actual.data).unwrap(),
        encode(&expected.data).unwrap()
    );
    assert!(
        p.a.recover_request("reserved-candidate".into(), action)
            .unwrap()
            .cached
    );
    assert_eq!(result.revision, actual.data.state.revision);
    assert_eq!(
        p.a.recover_request(
            "reserved-candidate".into(),
            Action::Send {
                message_id: "reserved-candidate".into(),
                text: "changed".into()
            }
        )
        .unwrap_err()
        .code,
        "request_conflict"
    );
}
#[test]
fn reserve_marker_guard_overhead_and_transaction_failure_do_not_consume() {
    let p = Pair::new();
    let before = p.a.database.call(|db| db.read(Ok)).unwrap();
    let mut proposed = before.clone();
    proposed.meta.reserve_version = Some(reserve::VERSION.into());
    let overhead = encode(&proposed.meta).unwrap().len() - encode(&before.meta).unwrap().len();
    assert!(overhead > 0);
    let proof = reserve::prove(&proposed).unwrap();
    assert_eq!(proof.peak[5] - proof.used[5], 82);
    let error =
        p.a.database
            .call(|db| {
                db.update(false, |s| {
                    s.meta.reserve_version = Some(reserve::VERSION.into());
                    Err::<(), _>(Error::new("cancelled"))
                })
            })
            .unwrap_err();
    assert_eq!(error.code, "cancelled");
    assert_eq!(
        operations::fingerprint(&before).unwrap(),
        p.a.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap()
    );
    p.a.database
        .call(|db| {
            db.update(false, |s| {
                budget_tests::pad_meta(s, store::MAX_META - 32);
                Ok(())
            })
        })
        .unwrap();
    let original =
        p.a.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap();
    assert_eq!(
        p.a.reserve_capacity().unwrap_err().code,
        "capacity_reserved"
    );
    assert_eq!(
        original,
        p.a.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap()
    );
}
#[test]
fn reserve_unknown_never_becomes_recoverable_and_format_cannot_downgrade() {
    let mut p = Pair::new();
    p.group();
    let action = Action::Send {
        message_id: "unknown".into(),
        text: "unknown".into(),
    };
    recovery_tests::lose_candidate(&mut p.a, "unknown", action.clone());
    let out = p.a.reserve_capacity().unwrap();
    assert_eq!(out.reserve.work[0].count, "0");
    assert!(out
        .operations
        .iter()
        .find(|o| o.operation == "recover_pending")
        .unwrap()
        .blockers
        .contains(&"successor_required".into()));
    p.reopen();
    assert_eq!(
        p.a.recover_request("unknown".into(), action)
            .unwrap_err()
            .code,
        "successor_required"
    );
    assert_eq!(
        p.a.database
            .call(|db| db.update(false, |s| {
                s.meta.reserve_version = None;
                Ok(())
            }))
            .unwrap_err()
            .code,
        "reserve_changed"
    );
    let version: i64 =
        p.a.database
            .call(|db| {
                let tx = db.connection.transaction()?;
                let version = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
                tx.commit()?;
                Ok(version)
            })
            .unwrap();
    assert_eq!(version, 6);
}
