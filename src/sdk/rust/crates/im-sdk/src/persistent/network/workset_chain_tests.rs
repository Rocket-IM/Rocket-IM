//! 真实MLS发送原件配合内部控制夹具；实际网络/Release证明由联合验收提供。
use super::{types::*, workset_chain, workset_tests::*, *};
use crate::persistent::{
    budget_tests,
    data::MAX_DATA,
    operations, reserve,
    tests::{send, Pair},
    types::*,
};

fn next(p: &Pair, previous: &str) -> Result<CapacityWorksetState> {
    let previous = previous.to_owned();
    p.b.database
        .call(move |db| db.update(false, |s| workset_chain::prepare_next(s, &previous)))
}

fn complete(p: &mut Pair) {
    phase(p, WorksetPhase::Confirmed).unwrap();
    phase(p, WorksetPhase::Active).unwrap();
    let saved = p.b.database.call(|db| db.read(Ok)).unwrap();
    let n = saved.data.network.as_ref().unwrap();
    let last = n.workset.as_ref().unwrap().workset.last.clone();
    super::queue::process_event(
        &mut p.b,
        &saved,
        n.events[number(&last).unwrap() as usize - 1].clone(),
    )
    .unwrap();
    p.b.database
        .call(move |db| {
            db.update(false, |s| {
                s.data.network.as_mut().unwrap().reported = last;
                Ok(())
            })
        })
        .unwrap();
    phase(p, WorksetPhase::Settled).unwrap();
}

fn control(p: &mut Pair, number: u64) {
    let request = format!("workset-original-{number}");
    let envelope = send(&mut p.b, &request);
    p.b.database
        .call(move |db| {
            db.update(false, |s| {
                s.data.network.as_mut().unwrap().events.push(Event {
                    sequence: number.to_string(),
                    kind: "delivered".into(),
                    envelope: None,
                    acceptance: Acceptance {
                        request_id: request.clone(),
                        message_id: request,
                        sequence: number.to_string(),
                        envelope_hash: hash(&encode(&envelope)?),
                    },
                });
                Ok(())
            })
        })
        .unwrap();
}

#[test]
fn repeated_worksets_preserve_three_rounds_and_idempotent_predecessors() {
    let mut p = source();
    let first = prepare(&p);
    assert_eq!(
        next(&p, &first.workset.id).unwrap_err().code,
        "workset_not_settled"
    );
    complete(&mut p);
    assert_eq!(
        next(&p, &first.workset.id).unwrap_err().code,
        "workset_empty"
    );
    control(&mut p, 2);
    let before = p.b.database.call(|db| db.read(Ok)).unwrap();
    let second = next(&p, &first.workset.id).unwrap();
    assert_eq!(
        (second.workset.first.as_str(), second.workset.last.as_str()),
        ("2", "2")
    );
    assert_ne!(first.workset.originals_hash, second.workset.originals_hash);
    assert_eq!(
        second.workset.previous.as_deref(),
        Some(first.workset.id.as_str())
    );
    assert_eq!(next(&p, &first.workset.id).unwrap(), second);
    assert_eq!(
        next(&p, &second.workset.id).unwrap_err().code,
        "workset_not_settled"
    );
    assert_eq!(
        next(&p, &"ff".repeat(32)).unwrap_err().code,
        "workset_conflict"
    );
    let after = p.b.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(before.crypto, after.crypto);
    assert_eq!(
        encode(&before.data.requests).unwrap(),
        encode(&after.data.requests).unwrap()
    );
    assert_eq!(
        encode(&before.data.messages).unwrap(),
        encode(&after.data.messages).unwrap()
    );
    assert_eq!(before.data.state, after.data.state);
    p.reopen();
    assert_eq!(p.b.capacity_workset().unwrap(), Some(second.clone()));
    complete(&mut p);
    let second_terminal = p.b.capacity_workset().unwrap().unwrap();
    control(&mut p, 3);
    let third = next(&p, &second.workset.id).unwrap();
    assert_eq!(third.workset.first, "3");
    let before =
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap();
    assert_eq!(next(&p, &first.workset.id).unwrap(), second_terminal);
    assert_eq!(
        before,
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap()
    );
    for mutation in 0..5 {
        assert!(p
            .b
            .database
            .call(move |db| db.update(false, |s| {
                let n = s.data.network.as_mut().unwrap();
                match mutation {
                    0 => n.workset_history.clear(),
                    1 => n.workset_history.reverse(),
                    2 => n.workset_history[0].phase = WorksetPhase::Prepared,
                    3 => n.workset = Some(n.workset_history[0].clone()),
                    _ => n.workset_history[0].workset.sdk_instance = "dd".repeat(32),
                }
                Ok(())
            }))
            .is_err());
        assert_eq!(
            before,
            p.b.database
                .call(|db| db.read(|s| operations::fingerprint(&s)))
                .unwrap()
        );
    }
    p.reopen();
    complete(&mut p);
    assert_eq!(
        p.b.database
            .call(|db| db.read(|s| Ok(s.data.network.unwrap().workset_history.len())))
            .unwrap(),
        2
    );
}

#[test]
fn repeated_workset_metadata_rejection_preserves_history_and_known_controls() {
    let mut p = source();
    let first = prepare(&p);
    complete(&mut p);
    control(&mut p, 2);
    p.b.database
        .call(|db| {
            db.update(false, |s| {
                let proof = reserve::prove(s)?;
                budget_tests::pad_data(&mut s.data, MAX_DATA - (proof.peak[3] - proof.used[3]));
                Ok(())
            })
        })
        .unwrap();
    let before =
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap();
    assert_eq!(
        next(&p, &first.workset.id).unwrap_err().code,
        "capacity_reserved"
    );
    assert_eq!(
        before,
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap()
    );
    let saved = p.b.database.call(|db| db.read(Ok)).unwrap();
    super::queue::process_event(
        &mut p.b,
        &saved,
        saved.data.network.as_ref().unwrap().events[1].clone(),
    )
    .unwrap();
    p.b.database
        .call(|db| {
            db.update(false, |s| {
                s.data.network.as_mut().unwrap().reported = "2".into();
                Ok(())
            })
        })
        .unwrap();
    assert_eq!(
        p.b.capacity_workset().unwrap().unwrap().workset,
        first.workset
    );
}

#[test]
fn repeated_workset_budget_reserves_current_growth_and_immutable_history() {
    let mut p = source();
    let first = prepare(&p);
    complete(&mut p);
    control(&mut p, 2);
    let second = next(&p, &first.workset.id).unwrap();
    budget_competition(p, second);
}
