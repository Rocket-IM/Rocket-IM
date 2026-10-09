//! 合成占额只验证既定硬界与原子候选；不声称真实用户完成了128次核验。
use super::*;

fn state() -> DeviceState {
    DeviceState::new(Context {
        service: "S1".into(),
        account: "A".into(),
        device: "A".into(),
    })
    .unwrap()
}
fn identity(index: u16) -> crate::identity_trust::DeviceIdentity {
    let mut seed = [0; 32];
    seed[..2].copy_from_slice(&index.to_be_bytes());
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    identity_state::object(
        "S1",
        &format!("B{index}"),
        &format!("D{index}"),
        &codec::encode(key.verifying_key().as_bytes()),
    )
}

#[test]
fn record_and_runtime_display_capacity_preserve_existing_facts() {
    let mut state = state();
    for n in 1..=128 {
        identity_records::observe(&mut state, identity(n)).unwrap();
    }
    identity_state::validate(&state).unwrap();
    let before = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        identity_records::observe(&mut state, identity(129))
            .unwrap_err()
            .code,
        "identity_budget"
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    assert_eq!(
        identity_records::observe(&mut state, identity(1)).unwrap()["duplicate"],
        true
    );
    let mut session = Session::new().unwrap();
    for n in 1..=128 {
        identity_records::prepare(
            &state,
            &mut session,
            identity_state::target(&identity(n)),
            crate::identity_trust::Purpose::Verify,
        )
        .unwrap();
    }
    assert_eq!(
        identity_records::prepare(
            &state,
            &mut session,
            identity_state::target(&identity(1)),
            crate::identity_trust::Purpose::Verify
        )
        .unwrap_err()
        .code,
        "identity_budget"
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}

#[test]
fn ledger_and_full_snapshot_bytes_refuse_before_installing_candidate() {
    let mut state = state();
    // 原控制结果中的合成字符串只占整快照预算，不调小生产16MiB。
    state.control_outbox.insert(
        "filler".into(),
        state::ControlRecord {
            request_digest: [0; 32],
            result: json!("x".repeat(crate::snapshot::MAX_PLAINTEXT_BYTES)),
        },
    );
    let before = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        identity_records::observe(&mut state, identity(1))
            .unwrap_err()
            .code,
        "identity_budget"
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    let mut ledger = identity_state::State {
        version: 1,
        records: Default::default(),
    };
    let mut valid = self::state();
    identity_records::observe(&mut valid, identity(1)).unwrap();
    let mut record = valid
        .identity_trust
        .take()
        .unwrap()
        .records
        .into_values()
        .next()
        .unwrap();
    // 字节函数的独立边界：故意长字段不是可加载合法设备记录。
    record.revision = "1".repeat(identity_state::BYTE_LIMIT);
    ledger
        .records
        .insert("synthetic-byte-boundary".into(), record);
    assert_eq!(
        identity_state::budget(&ledger).unwrap_err().code,
        "identity_budget"
    );
}

#[test]
fn legacy_none_and_invalid_stored_records_never_gain_verification() {
    let mut state = state();
    state.identity_trust = None;
    identity_state::validate(&state).unwrap();
    assert_eq!(
        identity_gate::require(&state, &identity(1))
            .unwrap_err()
            .code,
        "identity_unverified"
    );
    identity_records::observe(&mut state, identity(1)).unwrap();
    let original = serde_json::to_value(&state).unwrap();
    let key = identity_state::key(&identity_state::target(&identity(1))).unwrap();
    let mutations = [
        ("status", json!("verified")),
        ("revision", json!("0")),
        ("history", json!("reset")),
        ("last_reset", json!("a".repeat(64))),
        ("candidate", serde_json::to_value(identity(2)).unwrap()),
    ];
    for (field, value) in mutations {
        let mut encoded = original.clone();
        encoded["identity_trust"]["records"][&key][field] = value;
        let corrupt: DeviceState = serde_json::from_value(encoded).unwrap();
        assert!(identity_state::validate(&corrupt).is_err(), "{field}");
    }
    let mut unknown = original;
    unknown["identity_trust"]["records"][&key]["trusted_by_service"] = json!(true);
    assert!(serde_json::from_value::<DeviceState>(unknown).is_err());
}

#[test]
fn retired_binding_limit_keeps_all_1024_terminal_records_on_reset_failure() {
    let mut state = state();
    let original = identity(0);
    identity_records::observe(&mut state, original.clone()).unwrap();
    let key = identity_state::key(&identity_state::target(&original)).unwrap();
    let record = state
        .identity_trust
        .as_mut()
        .unwrap()
        .records
        .get_mut(&key)
        .unwrap();
    let same_target = |n| {
        let mut next = identity(n);
        next.account_id = original.account_id.clone();
        next.device_id = original.device_id.clone();
        next
    };
    record.retired = (1..=1024)
        .map(|n| identity_state::Retired {
            identity: same_target(n),
            verification: None,
        })
        .collect();
    record.last_reset = Some("a".repeat(64));
    record.history = identity_state::History::Gap;
    record.status = identity_state::Status::Changed;
    record.revision = "1026".into();
    record.candidate = Some(same_target(1025));
    identity_state::validate(&state).unwrap();
    let before = serde_json::to_vec(&state).unwrap();
    let mut session = Session::new().unwrap();
    let display = serde_json::from_value(
        identity_records::prepare(
            &state,
            &mut session,
            identity_state::target(&original),
            crate::identity_trust::Purpose::Reset,
        )
        .unwrap()["display"]
            .clone(),
    )
    .unwrap();
    assert_eq!(
        identity_records::confirm(
            &mut state,
            &session,
            display,
            same_target(1025),
            crate::consistency_exchange::Verification::SyntheticLocal,
            crate::identity_trust::Purpose::Reset
        )
        .unwrap_err()
        .code,
        "identity_budget"
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}
