//! 内部真实MLS原发送+合成控制事件，非Release联合E2EE验收。
use super::{rejection_tests::attach, types::*, workset, *};
use crate::persistent::{
    budget_tests,
    data::MAX_DATA,
    operations, reserve,
    tests::{send, Pair},
    types::*,
    PersistentDevice,
};

#[test]
fn workset_canonical_digest_matches_service_vector() {
    let mut w = CapacityWorkset {
        version: "control-workset-v1".into(),
        id: String::new(),
        owner: Identity {
            scope: Scope {
                service: "test".into(),
                account: "alice".into(),
                device: "a1".into(),
            },
            identity_key: "01".repeat(32),
        },
        sdk_instance: "aa".repeat(32),
        conversation: "chat".into(),
        context: "initial".into(),
        first: "1".into(),
        last: "2".into(),
        originals_hash: "bb".repeat(32),
        previous: None,
    };
    w.id = w.digest().unwrap();
    w.validate().unwrap();
    assert_eq!(
        w.id,
        "81368f51e502e0cfde7e723c56923389136e5afba2fd06c6830acf6d1e843e49"
    );
    w.previous = Some(w.id.clone());
    w.version = "control-workset-v2".into();
    w.first = "3".into();
    w.last = "4".into();
    w.id = w.digest().unwrap();
    w.validate().unwrap();
    assert_eq!(
        w.id,
        "04ad78a7e2dc01d74ac20ecde9b482df4654f0ff63d09dba61f3910a8ed61482"
    );
    let mut raw: serde_json::Value = serde_json::from_slice(&encode(&w).unwrap()).unwrap();
    raw["previous"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<CapacityWorkset>(raw).is_err());
}

pub(super) fn source() -> Pair {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let envelope = send(&mut p.b, "workset-original");
    p.b.reserve_capacity().unwrap();
    p.b.database
        .call(move |db| {
            db.update(false, |s| {
                s.data.network.as_mut().unwrap().events.push(Event {
                    sequence: "1".into(),
                    kind: "delivered".into(),
                    envelope: None,
                    acceptance: Acceptance {
                        request_id: "workset-original".into(),
                        message_id: "workset-original".into(),
                        sequence: "1".into(),
                        envelope_hash: hash(&encode(&envelope)?),
                    },
                });
                Ok(())
            })
        })
        .unwrap();
    p
}
pub(super) fn prepare(p: &Pair) -> CapacityWorksetState {
    p.b.database
        .call(|db| {
            db.update(false, |s| {
                let w = workset::select(s, &"aa".repeat(32))?;
                s.data.network.as_mut().unwrap().workset = Some(w.clone());
                Ok(w)
            })
        })
        .unwrap()
}
pub(super) fn phase(p: &Pair, phase: WorksetPhase) -> Result<()> {
    p.b.database.call(move |db| {
        db.update(false, |s| {
            s.data
                .network
                .as_mut()
                .unwrap()
                .workset
                .as_mut()
                .unwrap()
                .phase = phase;
            Ok(())
        })
    })
}

#[test]
fn workset_fixed_originals_phases_restart_and_settlement() {
    let mut p = source();
    let before = p.b.database.call(|db| db.read(Ok)).unwrap();
    let w = prepare(&p);
    assert_eq!(w.phase, WorksetPhase::Prepared);
    assert_eq!(
        (w.workset.first.as_str(), w.workset.last.as_str()),
        ("1", "1")
    );
    let proof =
        p.b.database
            .call(|db| db.read(|s| reserve::prove(&s)))
            .unwrap();
    assert!(proof.peak[3] > proof.used[3]);
    assert_eq!(
        phase(&p, WorksetPhase::Active).unwrap_err().code,
        "workset_conflict"
    );
    p.reopen();
    assert_eq!(p.b.capacity_workset().unwrap(), Some(w.clone()));
    phase(&p, WorksetPhase::Confirmed).unwrap();
    phase(&p, WorksetPhase::Active).unwrap();
    assert!(phase(&p, WorksetPhase::Settled).is_err());
    let saved = p.b.database.call(|db| db.read(Ok)).unwrap();
    super::queue::process_event(
        &mut p.b,
        &saved,
        saved.data.network.as_ref().unwrap().events[0].clone(),
    )
    .unwrap();
    p.b.database
        .call(|db| {
            db.update(false, |s| {
                s.data.network.as_mut().unwrap().reported = "1".into();
                Ok(())
            })
        })
        .unwrap();
    phase(&p, WorksetPhase::Settled).unwrap();
    assert_eq!(
        phase(&p, WorksetPhase::Prepared).unwrap_err().code,
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
    assert_eq!(
        encode(&before.data.network.as_ref().unwrap().events).unwrap(),
        encode(&after.data.network.as_ref().unwrap().events).unwrap()
    );
    let final_w = p.b.capacity_workset().unwrap().unwrap();
    assert_eq!(final_w.workset, w.workset);
    assert_eq!(prepare(&p), final_w);
    p.reopen();
    assert_eq!(p.b.capacity_workset().unwrap().unwrap(), final_w);
}

#[test]
fn workset_record_and_original_mutations_roll_back() {
    let p = source();
    prepare(&p);
    let fingerprint =
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap();
    for change in 0..5 {
        assert!(p
            .b
            .database
            .call(move |db| db.update(false, |s| {
                let n = s.data.network.as_mut().unwrap();
                match change {
                    0 => n.workset = None,
                    1 => n.workset.as_mut().unwrap().workset.sdk_instance = "bb".repeat(32),
                    2 => n.workset.as_mut().unwrap().workset.context = "bb".repeat(32),
                    3 => n.events[0].kind = "unavailable".into(),
                    _ => n.workset.as_mut().unwrap().workset.owner.scope.account = "foreign".into(),
                }
                Ok(())
            }))
            .is_err());
        assert_eq!(
            fingerprint,
            p.b.database
                .call(|db| db.read(|s| operations::fingerprint(&s)))
                .unwrap()
        );
    }
}

#[test]
fn workset_metadata_competes_in_original_budget_and_reserved_growth_settles() {
    let p = source();
    let w = prepare(&p);
    budget_competition(p, w);
}

pub(super) fn budget_competition(mut p: Pair, w: CapacityWorksetState) {
    p.b.database
        .call(|db| {
            db.update(false, |s| {
                let proof = reserve::prove(s)?;
                let growth = proof.peak[3] - proof.used[3];
                budget_tests::pad_data(&mut s.data, MAX_DATA - growth - 1);
                Ok(())
            })
        })
        .unwrap();
    let path =
        p.b.database
            .call(|db| Ok(std::path::PathBuf::from(db.connection.path().unwrap())))
            .unwrap();
    let mut other = PersistentDevice::open(path, p.b.state().unwrap().scope, false).unwrap();
    for device in [&p.b, &other] {
        // 仅测试延长锁等待，让两个独立Store真正竞争最后字节；生产100ms不变。
        device
            .database
            .call(|db| {
                db.connection
                    .busy_timeout(std::time::Duration::from_secs(30))?;
                Ok(())
            })
            .unwrap();
    }
    fn grow(s: &mut crate::persistent::data::Saved) -> Result<()> {
        let r = s
            .data
            .requests
            .iter_mut()
            .find(|(id, _)| id.starts_with("budget-padding-"))
            .unwrap()
            .1;
        if let Some(Action::Send { text, .. }) = &mut r.input {
            text.push('x');
        }
        r.hash = hash(&encode(r.input.as_ref().unwrap())?);
        Ok(())
    }
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            p.b.database.call(|db| db.update(false, grow))
        });
        let b = scope.spawn(|| {
            barrier.wait();
            other.database.call(|db| db.update(false, grow))
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(
        usize::from(results.0.is_ok()) + usize::from(results.1.is_ok()),
        1
    );
    assert_eq!(
        results.0.err().or(results.1.err()).unwrap().code,
        "capacity_reserved"
    );
    assert_eq!(p.b.capacity_workset().unwrap().unwrap(), w);
    assert_eq!(
        p.b.database
            .call(|db| db.read(|s| reserve::prove(&s)))
            .unwrap()
            .peak[3],
        MAX_DATA
    );
    other.close().unwrap();
    phase(&p, WorksetPhase::Confirmed).unwrap();
    phase(&p, WorksetPhase::Active).unwrap();
    let saved = p.b.database.call(|db| db.read(Ok)).unwrap();
    super::queue::process_event(
        &mut p.b,
        &saved,
        saved.data.network.as_ref().unwrap().events[number(&w.workset.last).unwrap() as usize - 1]
            .clone(),
    )
    .unwrap();
    let last = w.workset.last.clone();
    p.b.database
        .call(move |db| {
            db.update(false, |s| {
                s.data.network.as_mut().unwrap().reported = last;
                Ok(())
            })
        })
        .unwrap();
    phase(&p, WorksetPhase::Settled).unwrap();
    assert_eq!(p.b.capacity_workset().unwrap().unwrap().workset, w.workset);
    let proof =
        p.b.database
            .call(|db| db.read(|s| reserve::prove(&s)))
            .unwrap();
    assert_eq!(proof.peak[3], proof.used[3]);
}

#[test]
fn workset_new_record_requires_room_and_empty_prefix_is_not_guaranteed() {
    let p = source();
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
    let e =
        p.b.database
            .call(|db| {
                db.update(false, |s| {
                    let w = workset::select(s, &"aa".repeat(32))?;
                    s.data.network.as_mut().unwrap().workset = Some(w);
                    Ok(())
                })
            })
            .unwrap_err();
    assert_eq!(e.code, "capacity_reserved");
    assert_eq!(
        before,
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap()
    );
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    p.b.reserve_capacity().unwrap();
    assert_eq!(
        p.b.database
            .call(|db| db.read(|s| workset::select(&s, &"aa".repeat(32))))
            .unwrap_err()
            .code,
        "workset_empty"
    );
}
