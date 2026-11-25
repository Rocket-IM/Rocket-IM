//! 原发送与最后字节竞争；填充为非E2EE夹具，发送和候选使用真实MLS。
use super::{rejection_tests::attach, types::*, *};
use crate::persistent::{
    budget_tests,
    data::MAX_DATA,
    metering, operations, reserve,
    tests::{send, Pair},
    types::*,
    PersistentDevice,
};

fn grow(s: &mut crate::persistent::data::Saved) -> Result<()> {
    let record = s.data.requests.get_mut("budget-padding-3").unwrap();
    if let Some(Action::Send { text, .. }) = &mut record.input {
        text.push('x');
    }
    record.hash = hash(&encode(record.input.as_ref().unwrap())?);
    Ok(())
}
#[test]
fn reserve_ack_last_byte_concurrent_writes_do_not_oversell() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let envelope = send(&mut p.b, "known");
    p.b.reserve_capacity().unwrap();
    p.b.database
        .call(|db| {
            db.update(false, |s| {
                let proof = reserve::prove(s)?;
                let growth = proof.peak[3] - proof.used[3];
                assert!(growth > 0);
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
    // 真正等待前一写事务结束再竞争额度，避免100ms默认busy门提前截断容量路径。
    p.b.database
        .call(|db| {
            db.connection
                .busy_timeout(std::time::Duration::from_secs(30))?;
            Ok(())
        })
        .unwrap();
    other
        .database
        .call(|db| {
            db.connection
                .busy_timeout(std::time::Duration::from_secs(30))?;
            Ok(())
        })
        .unwrap();
    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
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
        usize::from(outcomes.0.is_ok()) + usize::from(outcomes.1.is_ok()),
        1
    );
    let err = outcomes.0.err().or(outcomes.1.err()).unwrap();
    assert_eq!(err.code, "capacity_reserved");
    let proof =
        p.b.database
            .call(|db| db.read(|s| reserve::prove(&s)))
            .unwrap();
    assert_eq!(proof.peak[3], MAX_DATA);
    let ack = Acceptance {
        request_id: "known".into(),
        message_id: "known".into(),
        sequence: "256".into(),
        envelope_hash: hash(&encode(&envelope).unwrap()),
    };
    p.b.database
        .call(move |db| {
            db.update(false, |s| {
                ledger::validate_ack(&s.data, &ack)?;
                s.data
                    .network
                    .as_mut()
                    .unwrap()
                    .accepted
                    .insert(ack.message_id.clone(), ack);
                Ok(())
            })
        })
        .unwrap();
    assert_eq!(
        p.b.capacity().unwrap().reserve.resources[3].protected_remaining,
        "0"
    );
    assert_eq!(
        p.b.capacity().unwrap().budgets[3].used,
        MAX_DATA.to_string()
    );
    other.close().unwrap();
    p.reopen();
    assert_eq!(
        p.b.capacity().unwrap().reserve.resources[3].protected_remaining,
        "0"
    );
}
#[test]
fn reserve_controls_and_reports_use_known_prefix_and_keep_originals() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let envelope = send(&mut p.b, "known");
    p.b.reserve_capacity().unwrap();
    let ack = Acceptance {
        request_id: "known".into(),
        message_id: "known".into(),
        sequence: "1".into(),
        envelope_hash: hash(&encode(&envelope).unwrap()),
    };
    let event = Event {
        sequence: "1".into(),
        kind: "delivered".into(),
        acceptance: ack.clone(),
        envelope: None,
    };
    p.b.database
        .call(move |db| {
            db.update(false, |s| {
                s.data.network.as_mut().unwrap().events.push(event);
                Ok(())
            })
        })
        .unwrap();
    let before = p.b.database.call(|db| db.read(Ok)).unwrap();
    let proof = reserve::prove(&before).unwrap();
    assert_eq!((proof.controls, proof.reports), (1, 1));
    let event = before.data.network.as_ref().unwrap().events[0].clone();
    queue::process_event(&mut p.b, &before, event).unwrap();
    p.b.database
        .call(|db| {
            db.update(false, |s| {
                s.data.network.as_mut().unwrap().reported = "1".into();
                Ok(())
            })
        })
        .unwrap();
    let after = p.b.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(before.crypto, after.crypto);
    assert_eq!(
        encode(&before.data.requests).unwrap(),
        encode(&after.data.requests).unwrap()
    );
    assert_eq!(
        encode(&before.data.network.unwrap().events).unwrap(),
        encode(&after.data.network.as_ref().unwrap().events).unwrap()
    );
    assert!(metering::usage(&after)
        .unwrap()
        .iter()
        .zip(proof.peak)
        .all(|(u, p)| *u <= p));
    assert_eq!(reserve::prove(&after).unwrap().reports, 0);
}
#[test]
fn reserve_rejection_settles_only_original_and_exact_retry_is_free() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let envelope = send(&mut p.b, "reject");
    p.b.reserve_capacity().unwrap();
    let before = p.b.database.call(|db| db.read(Ok)).unwrap();
    let copy = envelope.clone();
    p.b.database
        .call(move |db| db.update(true, |s| rejection_tests::reject(s, "reject", &copy)))
        .unwrap();
    let after = p.b.database.call(|db| db.read(Ok)).unwrap();
    assert!(metering::usage(&after)
        .unwrap()
        .iter()
        .zip(reserve::prove(&before).unwrap().peak)
        .all(|(u, p)| *u <= p));
    assert_eq!(reserve::prove(&after).unwrap().sends, 0);
    let fingerprint = operations::fingerprint(&after).unwrap();
    p.b.database
        .call(move |db| db.update(true, |s| rejection_tests::reject(s, "reject", &envelope)))
        .unwrap();
    assert_eq!(
        fingerprint,
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap()
    );
}
