use super::super::super::super::{wire_history, CrashPoint};
use super::*;
use openmls::prelude::PastEpochDeletionPolicy;

fn with_device(
    f: &Fixture,
    device: &str,
    change: impl FnOnce(&mut super::super::super::super::state::DeviceState),
) {
    let locked = LockedDevice::open(&f.root.join(device)).unwrap();
    let mut state = locked
        .load(&Context {
            service: "S1".into(),
            account: device.into(),
            device: device.into(),
        })
        .unwrap()
        .unwrap();
    change(&mut state);
    locked.save(&mut state, CrashPoint::None).unwrap();
}

#[test]
fn two_past_epochs_are_retained_and_third_transition_expires_unseen_message() {
    let (f, key) = setup_devices(&["A", "B", "C", "D", "E"]);
    let kept = f.send("A", "kept")["envelope"].clone();
    let expired = f.send("A", "expired")["envelope"].clone();
    let kept_receipt = acceptance(&key, &kept, "K1");
    remove(&f, &key, "removeC", "C");
    remove(&f, &key, "removeD", "D");
    assert_eq!(
        f.call("B", receive(&kept, "K1", &kept_receipt))["historical"],
        true
    );
    let before = f.call("B", json!({"operation":"wire_inspect"}));
    assert_eq!(
        before["history"]["past_epochs"].as_array().unwrap().len(),
        2
    );
    remove(&f, &key, "removeE", "E");
    let state = f.call("B", json!({"operation":"wire_inspect"}));
    assert_eq!(state["history"]["past_epochs"].as_array().unwrap().len(), 2);
    assert!(state["history"]["past_epochs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|epoch| epoch["epoch"] != "1"));
    fail_atomic(
        &f,
        "B",
        receive(&expired, "K2", &acceptance(&key, &expired, "K2")),
        "history_unavailable",
    );
    assert_eq!(
        f.call("B", receive(&kept, "K1", &kept_receipt))["duplicate"],
        true
    );
    let current = f.send("A", "current");
    f.receive("B", &current["envelope"]);
}

#[test]
fn old_pending_candidate_does_not_gain_deleted_past_keys_after_policy_upgrade() {
    let (f, key) = setup_devices(&["A", "B", "C", "D"]);
    let unavailable = f.send("B", "before_upgrade")["envelope"].clone();
    let proof = prepare(&f, "A", "old_candidate");
    with_device(&f, "A", |state| {
        let provider = permission_state::provider_from(
            &state
                .permissions
                .pending
                .as_ref()
                .unwrap()
                .candidate_entries,
        )
        .unwrap();
        let mut candidate = permission_state::group_from(state, &provider).unwrap();
        candidate
            .set_past_epoch_deletion_policy(&provider, PastEpochDeletionPolicy::MaxEpochs(0))
            .unwrap();
        state
            .permissions
            .pending
            .as_mut()
            .unwrap()
            .candidate_entries = permission_state::entries(&provider).unwrap();
        state
            .group()
            .unwrap()
            .set_past_epoch_deletion_policy(&state.provider, PastEpochDeletionPolicy::MaxEpochs(0))
            .unwrap();
        let mut encoded = serde_json::to_value(&state.permissions).unwrap();
        encoded.as_object_mut().unwrap().remove("history");
        state.permissions = serde_json::from_value(encoded).unwrap();
    });
    let record = accepted(&key, &proof);
    recover(&f, "A", &record);
    recover(&f, "B", &record);
    assert_eq!(
        f.call("A", json!({"operation":"wire_inspect"}))["history"]["past_epochs"],
        json!([])
    );
    fail_atomic(
        &f,
        "A",
        receive(&unavailable, "K1", &acceptance(&key, &unavailable, "K1")),
        "history_unavailable",
    );
    with_device(&f, "A", |state| {
        assert_eq!(
            state.group().unwrap().past_epoch_deletion_policy(),
            &PastEpochDeletionPolicy::MaxEpochs(wire_history::PAST_EPOCHS)
        )
    });
    let future_old = f.send("B", "after_upgrade")["envelope"].clone();
    remove(&f, &key, "removeD", "D");
    assert_eq!(
        f.call(
            "A",
            receive(&future_old, "K2", &acceptance(&key, &future_old, "K2"))
        )["historical"],
        true
    );
}

#[test]
fn no_pin_groups_keep_original_zero_history_policy() {
    let f = Fixture::new();
    let cp = checkpoint(&f);
    super::super::super::bootstrap(&f, &cp);
    for device in ["A", "B", "C"] {
        with_device(&f, device, |state| {
            assert_eq!(
                state.group().unwrap().past_epoch_deletion_policy(),
                &PastEpochDeletionPolicy::MaxEpochs(0)
            )
        });
    }
    let proof = prepare(&f, "A", "legacy");
    f.call("A", json!({"operation":"permission_apply","change":proof}));
    with_device(&f, "A", |state| {
        assert_eq!(
            state.group().unwrap().past_epoch_deletion_policy(),
            &PastEpochDeletionPolicy::MaxEpochs(0)
        )
    });
}
