use super::*;

#[test]
fn legacy_pending_cannot_gain_receipt_pin_and_still_applies_exact_saved_candidate() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    super::super::bootstrap(&f, &cp);
    let proof = prepare(&f, "A", "legacy");
    let locked = LockedDevice::open(&f.root.join("A")).unwrap();
    let mut a = locked
        .load(&Context {
            service: "S1".into(),
            account: "A".into(),
            device: "A".into(),
        })
        .unwrap()
        .unwrap();
    let mut raw = serde_json::to_value(&a.permissions).unwrap();
    raw.as_object_mut().unwrap().remove("recovery");
    a.permissions = serde_json::from_value(raw).unwrap();
    locked
        .save(&mut a, super::super::super::CrashPoint::None)
        .unwrap();
    drop(locked);
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_bootstrap","checkpoint":cp,"relay_receipt_key":codec::encode(SigningKey::from_bytes(&[19;32]).verifying_key().as_bytes())}),
        "permission_pending",
    );
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_close_request"}),
        "receipt_pin_required",
    );
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_recover","record":closed(&SigningKey::from_bytes(&[19;32]),&proof)}),
        "receipt_pin_required",
    );
    f.call("A", json!({"operation":"permission_apply","change":proof}));
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_bootstrap","checkpoint":cp}),
        "permission_conflict",
    );
}

#[test]
fn exhausted_epoch_budget_preserves_intent_and_allows_only_exact_pending_retry() {
    let (f, key) = setup();
    let locked = LockedDevice::open(&f.root.join("A")).unwrap();
    let mut a = locked
        .load(&Context {
            service: "S1".into(),
            account: "A".into(),
            device: "A".into(),
        })
        .unwrap()
        .unwrap();
    a.permissions.recovery.prepare_count = 63;
    locked
        .save(&mut a, super::super::super::CrashPoint::None)
        .unwrap();
    drop(locked);
    let proof = prepare(&f, "A", "last");
    assert_eq!(proof, prepare(&f, "A", "last"));
    assert_eq!(
        f.call("A", json!({"operation":"permission_inspect"}))["epoch_prepare_count"],
        64
    );
    recover(&f, "A", &closed(&key, &proof));
    fail_atomic(
        &f,
        "A",
        json!({"operation":"permission_prepare","change_id":"over","action":{"kind":"remove_member","account_id":"C"}}),
        "permission_epoch_budget",
    );
    blocked(&f, "A");
}

#[test]
fn sixty_fourth_real_handshake_crosses_unseen_closed_candidates_and_next_epoch_resets_budget() {
    let (f, key) = setup_devices(&["A", "B", "C", "D"]);
    let locked = LockedDevice::open(&f.root.join("A")).unwrap();
    let mut a = locked
        .load(&Context {
            service: "S1".into(),
            account: "A".into(),
            device: "A".into(),
        })
        .unwrap()
        .unwrap();
    // 对端B始终不接触前63个已封口Commit；不导出或改写任何密码ratchet。
    let mut last = None;
    for n in 1..=64 {
        let result = super::super::super::permissions::prepare(
            &mut a,
            format!("try{n}"),
            permission::Action::RemoveMember {
                account_id: "C".into(),
            },
            None,
        )
        .unwrap();
        let proof: Proof = serde_json::from_value(result["change"].clone()).unwrap();
        if n < 64 {
            super::super::super::permission_recovery::recover(&mut a, closed(&key, &proof))
                .unwrap();
        } else {
            last = Some(proof);
        }
    }
    locked
        .save(&mut a, super::super::super::CrashPoint::None)
        .unwrap();
    drop(locked);
    let proof = last.unwrap();
    let record = accepted(&key, &proof);
    recover(&f, "A", &record);
    recover(&f, "B", &record);
    assert_eq!(
        f.call("A", json!({"operation":"permission_inspect"}))["epoch_prepare_count"],
        0
    );
    f.call("A",json!({"operation":"permission_prepare","change_id":"next","action":{"kind":"remove_member","account_id":"D"}}));
    assert_eq!(
        f.call("A", json!({"operation":"permission_inspect"}))["epoch_prepare_count"],
        1
    );
}
