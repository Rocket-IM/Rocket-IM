//! 与真实准备共用的纯元数据门禁；provider 保持空白，不能用它实现预约前检查。
use super::{bootstrap, checkpoint, prepare, Context, Fixture, LockedDevice};
use crate::lab::{permission_prepare, state::DeviceState, MAX_RECORDS};
use crate::permission::{Action, Proof};

#[test]
fn admission_metadata_rejects_full_materials_but_keeps_original_id_available() {
    use crate::lab::permission_admission::{intent, JoinMode};
    use crate::permission::admission::JoinMaterial;
    let f = Fixture::new();
    bootstrap(&f, &checkpoint(&f));
    let mut state = metadata(&f);
    state.permissions.recovery.relay_receipt_key =
        Some(crate::lab::codec::encode(&state.own_signature_key));
    state.permissions.admission.materials = (0..MAX_RECORDS)
        .map(|n| {
            (
                n.to_string(),
                JoinMaterial {
                    key_package: "AQ==".into(),
                    welcome: String::new(),
                    allocation: None,
                },
            )
        })
        .collect();
    let member = state.permissions.checkpoint.as_ref().unwrap().members[1].clone();
    assert_eq!(
        intent(
            &state,
            "fresh",
            member.clone(),
            "AQ==",
            "from_join".into(),
            JoinMode::Member
        )
        .unwrap_err()
        .code,
        "resource_exhausted"
    );
    assert!(intent(
        &state,
        "0",
        member,
        "AQ==",
        "from_join".into(),
        JoinMode::Member
    )
    .is_ok());
}

fn metadata(f: &Fixture) -> DeviceState {
    let locked = LockedDevice::open(&f.root.join("A")).unwrap();
    let state = locked
        .load(&Context {
            service: "S1".into(),
            account: "A".into(),
            device: "A".into(),
        })
        .unwrap()
        .unwrap();
    // provider 是 serde(skip) 字段，模拟锚路径的 metadata_committed。
    serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap()
}

fn rejected(state: &DeviceState, id: &str, action: &Action, validity: Option<u16>, code: &str) {
    let before = serde_json::to_vec(state).unwrap();
    assert_eq!(
        permission_prepare::check(state, id, action, validity)
            .unwrap_err()
            .code,
        code
    );
    assert_eq!(serde_json::to_vec(state).unwrap(), before);
}

#[test]
fn metadata_prepare_checks_limits_roles_and_versions_without_provider() {
    let f = Fixture::new();
    bootstrap(&f, &checkpoint(&f));
    let action = Action::RemoveMember {
        account_id: "C".into(),
    };
    let mut state = metadata(&f);
    assert!(state.group().is_err());
    assert!(permission_prepare::check(&state, "fresh", &action, None)
        .unwrap()
        .is_none());
    rejected(&state, "fresh", &action, Some(0), "invalid_permission");
    state.permissions.recovery.prepare_count = 64;
    rejected(&state, "fresh", &action, None, "permission_epoch_budget");
    state.permissions.recovery.prepare_count = 0;
    state
        .permissions
        .checkpoint
        .as_mut()
        .unwrap()
        .authorization_version = u64::MAX.to_string();
    rejected(&state, "fresh", &action, None, "permission_version");
    state
        .permissions
        .checkpoint
        .as_mut()
        .unwrap()
        .authorization_version = "1".into();
    state.context.account = "B".into();
    state.context.device = "B".into();
    rejected(&state, "fresh", &action, None, "permission_denied");
    state.permissions.applied = (0..MAX_RECORDS)
        .map(|n| {
            (
                n.to_string(),
                Proof {
                    statement_bytes: String::new(),
                    signature_bytes: String::new(),
                    commit_bytes: String::new(),
                },
            )
        })
        .collect();
    rejected(&state, "fresh", &action, None, "resource_exhausted");
}

#[test]
fn metadata_prepare_preserves_pending_and_applied_retry_semantics() {
    let f = Fixture::new();
    bootstrap(&f, &checkpoint(&f));
    let proof = prepare(&f, "A", "original");
    let action = Action::RemoveMember {
        account_id: "C".into(),
    };
    let mut state = metadata(&f);
    assert!(state.group().is_err());
    state.permissions.recovery.prepare_count = 64;
    assert_eq!(
        permission_prepare::check(&state, "original", &action, None).unwrap(),
        Some(&proof)
    );
    rejected(&state, "other", &action, None, "pending_conflict");
    rejected(&state, "original", &action, Some(1), "pending_conflict");
    state.permissions.pending = None;
    state
        .permissions
        .applied
        .insert("original".into(), proof.clone());
    assert_eq!(
        permission_prepare::check(&state, "original", &action, None).unwrap(),
        Some(&proof)
    );
    rejected(
        &state,
        "original",
        &Action::RemoveMember {
            account_id: "B".into(),
        },
        None,
        "permission_conflict",
    );
}
