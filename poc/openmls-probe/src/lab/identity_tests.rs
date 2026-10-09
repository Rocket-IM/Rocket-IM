use super::*;
use serde_json::json;

#[path = "identity_budget_tests.rs"]
mod budget;
#[path = "identity_guard_tests.rs"]
mod guards;
#[path = "identity_lifecycle_tests.rs"]
mod lifecycle;

#[test]
fn identity_public_object_binds_all_scope_fields() {
    let a = DeviceState::new(Context {
        service: "S1".into(),
        account: "A".into(),
        device: "A1".into(),
    })
    .unwrap();
    let identity = identity_state::own(&a);
    let mut other = identity.clone();
    other.account_id = "B".into();
    assert_ne!(
        identity.fingerprint().unwrap(),
        other.fingerprint().unwrap()
    );
    assert!(identity_gate::require(&a, &other).is_err());
}

#[test]
fn identity_observe_never_inherits_pin_and_reset_keeps_history() {
    let mut a = DeviceState::new(Context {
        service: "S1".into(),
        account: "A".into(),
        device: "A1".into(),
    })
    .unwrap();
    let b = DeviceState::new(Context {
        service: "S1".into(),
        account: "B".into(),
        device: "B1".into(),
    })
    .unwrap();
    let mut b2 = identity_state::own(&DeviceState::new(b.context.clone()).unwrap());
    b2.device_id = "B1".into();
    let identity = identity_state::own(&b);
    a.peer_pins.push(Pin {
        account: "B".into(),
        device: "B1".into(),
        signature_key: identity.signature_key.clone(),
    });
    let observed = identity_records::observe(&mut a, identity.clone()).unwrap();
    assert_eq!(observed["record"]["status"], "unverified");
    let mut session = Session::new().unwrap();
    let display: crate::identity_trust::Display = serde_json::from_value(
        identity_records::prepare(
            &a,
            &mut session,
            identity_state::target(&identity),
            crate::identity_trust::Purpose::Verify,
        )
        .unwrap()["display"]
            .clone(),
    )
    .unwrap();
    identity_records::confirm(
        &mut a,
        &session,
        display.clone(),
        identity.clone(),
        crate::consistency_exchange::Verification::SyntheticLocal,
        crate::identity_trust::Purpose::Verify,
    )
    .unwrap();
    assert!(identity_gate::require(&a, &identity).is_ok());
    assert_eq!(
        identity_records::confirm(
            &mut a,
            &session,
            display,
            identity.clone(),
            crate::consistency_exchange::Verification::SyntheticLocal,
            crate::identity_trust::Purpose::Verify
        )
        .unwrap()["duplicate"],
        true
    );
    assert_eq!(
        identity_records::observe(&mut a, b2.clone()).unwrap()["record"]["history"],
        "gap"
    );
    assert!(identity_gate::require(&a, &identity).is_err());
    let display = serde_json::from_value(
        identity_records::prepare(
            &a,
            &mut session,
            identity_state::target(&b2),
            crate::identity_trust::Purpose::Reset,
        )
        .unwrap()["display"]
            .clone(),
    )
    .unwrap();
    let reset = identity_records::confirm(
        &mut a,
        &session,
        display,
        b2,
        crate::consistency_exchange::Verification::SyntheticLocal,
        crate::identity_trust::Purpose::Reset,
    )
    .unwrap();
    assert_eq!(reset["record"]["status"], "unverified");
    assert_eq!(reset["record"]["history"], "reset");
    assert_eq!(reset["record"]["retired"].as_array().unwrap().len(), 1);
    assert_eq!(a.peer_pins[0].signature_key, identity.signature_key);
    identity_state::validate(&a).unwrap();
    assert_eq!(
        identity_records::observe(&mut a, identity.clone()).unwrap()["record"]["status"],
        "changed"
    );
    assert_eq!(
        identity_state::binding_available(&a, &identity)
            .unwrap_err()
            .code,
        "identity_changed"
    );
    assert_eq!(json!(a.permissions.pending.is_some()), false);
}

#[test]
fn revoked_roster_key_remains_reserved_to_its_original_device() {
    let mut observer = DeviceState::new(Context {
        service: "S1".into(),
        account: "A".into(),
        device: "A".into(),
    })
    .unwrap();
    let old = DeviceState::new(Context {
        service: "S1".into(),
        account: "A".into(),
        device: "old".into(),
    })
    .unwrap();
    observer.roster = crate::authorization::TrustedRoster::new(
        "S1".into(),
        "A".into(),
        "old".into(),
        old.own_signature_key,
    )
    .unwrap();
    assert!(observer
        .roster
        .key_bound_to_other_device("new", &old.own_signature_key));
    assert!(!observer
        .roster
        .key_bound_to_other_device("old", &old.own_signature_key));
    observer.roster.revoke("old", 0).unwrap();
    assert!(observer.roster.trusted_signature_key("old").is_none());
    assert!(observer
        .roster
        .key_bound_to_other_device("new", &old.own_signature_key));
    let identity = identity_state::object("S1", "A", "new", &codec::encode(&old.own_signature_key));
    let before = serde_json::to_vec(&observer).unwrap();
    assert_eq!(
        identity_records::observe(&mut observer, identity)
            .unwrap_err()
            .code,
        "identity_changed"
    );
    assert!(serde_json::to_vec(&observer).unwrap() == before);
}

#[test]
fn refreshed_keypackage_preserves_same_device_verification() {
    use openmls::prelude::{tls_codec::Serialize, KeyPackage};
    let mut observer = DeviceState::new(Context {
        service: "S1".into(),
        account: "A".into(),
        device: "A".into(),
    })
    .unwrap();
    let mut peer = DeviceState::new(Context {
        service: "S1".into(),
        account: "B".into(),
        device: "B".into(),
    })
    .unwrap();
    let identity = identity_state::own(&peer);
    identity_records::observe(&mut observer, identity.clone()).unwrap();
    let mut session = Session::new().unwrap();
    let display = serde_json::from_value(
        identity_records::prepare(
            &observer,
            &mut session,
            identity_state::target(&identity),
            crate::identity_trust::Purpose::Verify,
        )
        .unwrap()["display"]
            .clone(),
    )
    .unwrap();
    identity_records::confirm(
        &mut observer,
        &session,
        display,
        identity.clone(),
        crate::consistency_exchange::Verification::SyntheticLocal,
        crate::identity_trust::Purpose::Verify,
    )
    .unwrap();
    let old = peer.key_package.clone();
    let fresh = KeyPackage::builder()
        .build(
            codec::CIPHERSUITE,
            &peer.provider,
            &peer.signer().unwrap(),
            peer.own_credential().unwrap(),
        )
        .unwrap();
    peer.key_package = fresh.key_package().tls_serialize_detached().unwrap();
    assert_ne!(old, peer.key_package);
    assert_eq!(identity, identity_state::own(&peer));
    assert_eq!(
        identity_records::observe(&mut observer, identity_state::own(&peer)).unwrap()["duplicate"],
        true
    );
    identity_gate::require(&observer, &identity).unwrap();
}
