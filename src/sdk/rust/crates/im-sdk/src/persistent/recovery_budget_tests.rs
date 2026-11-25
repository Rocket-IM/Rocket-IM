//! 实测一轮真实MLS后继的各持久阶段；内部丢候选入口不冒充进程故障验收。
use super::{
    recovery_tests::lose_candidate,
    tests::{send, Pair},
    *,
};

fn measure(device: &PersistentDevice, role: &str, stage: &str) {
    super::capacity_tests::measured(device);
    let (data, meta, crypto, fresh, candidate, archives) = device
        .database
        .call(|db| {
            db.read(|s| {
                let (fresh, candidate) = s.meta.session.as_ref().map_or((0, 0), |session| {
                    (
                        encode(&session.fresh).unwrap().len(),
                        session
                            .candidate
                            .as_ref()
                            .map_or(0, |c| encode(c).unwrap().len()),
                    )
                });
                Ok((
                    encode(&s.data)?.len(),
                    encode(&s.meta)?.len(),
                    s.crypto.len(),
                    fresh,
                    candidate,
                    encode(&s.meta.archives)?.len(),
                ))
            })
        })
        .unwrap();
    // 仅记录单位为字节的计数，不导出密码快照、正文或签名材料。
    println!("BUDGET recovery role={role} stage={stage} data={data} meta={meta} crypto_raw={crypto} fresh_json={fresh} candidate_json={candidate} archives_json={archives}");
}

#[test]
fn successor_keeps_fresh_candidate_and_old_archive_cost_after_install() {
    let mut pair = Pair::new();
    pair.group();
    let e = send(&mut pair.a, "history");
    pair.b
        .execute("history".into(), Action::Receive { envelope: e })
        .unwrap();
    let action = Action::Send {
        message_id: "unknown".into(),
        text: "bounded".into(),
    };
    lose_candidate(&mut pair.a, "unknown", action.clone());
    measure(&pair.a, "target", "executing_unknown");
    let pin = pair.a.state().unwrap().identity.unwrap();
    let offer = pair
        .a
        .recovery(RecoveryCommand::Begin {
            request_id: "unknown".into(),
            action,
        })
        .unwrap()
        .packet
        .unwrap();
    measure(&pair.a, "target", "offered");
    let approval = pair
        .b
        .recovery(RecoveryCommand::Accept { offer, peer: pin })
        .unwrap()
        .packet
        .unwrap();
    measure(&pair.b, "peer", "prepared");
    let ready = pair
        .a
        .recovery(RecoveryCommand::Join { approval })
        .unwrap()
        .packet
        .unwrap();
    measure(&pair.a, "target", "ready");
    let before = pair.a.database.call(|db| db.read(Ok)).unwrap();
    let receipt = pair
        .b
        .recovery(RecoveryCommand::Confirm { ready })
        .unwrap()
        .packet
        .unwrap();
    measure(&pair.b, "peer", "committed");
    pair.a
        .recovery(RecoveryCommand::Finish { receipt })
        .unwrap();
    measure(&pair.a, "target", "finished");
    pair.reopen();
    let after = pair.a.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(after.meta.archives.len(), 1);
    assert_eq!(
        encode(&after.meta.archives[0].data).unwrap(),
        encode(&before.data).unwrap()
    );
    assert_eq!(after.meta.archives[0].crypto, before.crypto);
    let session = after.meta.session.as_ref().unwrap();
    assert!(!session.fresh.is_empty());
    assert_eq!(session.candidate.as_ref(), Some(&after.crypto));
    assert!(encode(&after.meta).unwrap().len() > encode(&before.meta).unwrap().len());
    assert!(matches!(
        after.data.requests["unknown"].result,
        RequestState::Retired { .. }
    ));
    let e = send(&mut pair.a, "after-recovery");
    pair.b
        .execute("after-recovery".into(), Action::Receive { envelope: e })
        .unwrap();
}
