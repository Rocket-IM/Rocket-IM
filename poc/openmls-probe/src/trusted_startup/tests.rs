use super::*;
#[test]
fn fixed_wire_vector_and_mutations() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../api/realtime/trusted-startup-vectors.json"
    ))
    .unwrap();
    let proof: SignedRecord = serde_json::from_value(v["proof"].clone()).unwrap();
    let key = v["approval_key"].as_str().unwrap();
    let parsed: Approval = verify(&proof, APPROVAL_DOMAIN, key).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), v["approval"]);
    assert!(verify::<Approval>(&proof, RESPONSE_DOMAIN, key).is_err());
    assert!(
        verify::<Approval>(&proof, APPROVAL_DOMAIN, &public(&"99".repeat(32)).unwrap()).is_err()
    );
    for field in ["slot", "previous_generation"] {
        let mut changed = v["approval"].clone();
        changed[field] = serde_json::json!("wrong");
        let bad = SignedRecord {
            statement_bytes: STANDARD.encode(serde_json::to_vec(&changed).unwrap()),
            signature_bytes: proof.signature_bytes.clone(),
        };
        assert!(verify::<Approval>(&bad, APPROVAL_DOMAIN, key).is_err());
    }
    let mut changed = v["approval"].clone();
    changed["unknown"] = serde_json::json!(true);
    let bad = sign(&changed, APPROVAL_DOMAIN, &"33".repeat(32)).unwrap();
    assert!(verify::<Approval>(&bad, APPROVAL_DOMAIN, key).is_err());
}
fn manifest(generation: &str, key: u8) -> Manifest {
    Manifest {
        protocol_version: "rim-startup-manifest-1".into(),
        slot: "installation".into(),
        generation: generation.into(),
        roots: Roots {
            service_id: "service".into(),
            issuer: "issuer".into(),
            audience: "audience".into(),
            business_key: public(&"11".repeat(32)).unwrap(),
            receipt_key: public(&"22".repeat(32)).unwrap(),
        },
        scope: Scope {
            service: "service".into(),
            account: "alice".into(),
            device: format!("device-{key}"),
            identity_key: format!("{key:02x}").repeat(32),
            store_id: format!("{key:02x}").repeat(32),
        },
        anchor_public_key: crate::rollback_anchor::public_key(&[key; 32]),
        anchor_config_sha256: "ab".repeat(32),
    }
}
fn state() -> authority::State {
    authority::State {
        protocol_version: "rim-startup-authority-1".into(),
        slot: "installation".into(),
        approval_key: public(&"33".repeat(32)).unwrap(),
        response_seed: "44".repeat(32),
        generation: 0,
        current: None,
        disabled: false,
        retired: vec![],
        last: None,
    }
}
fn approval(s: &authority::State, action: &str, m: Option<Manifest>) -> SignedRecord {
    sign(
        &Approval {
            protocol_version: "rim-startup-approval-1".into(),
            slot: s.slot.clone(),
            previous_generation: s.generation.to_string(),
            previous_sha256: s
                .current
                .as_ref()
                .map(Manifest::hash)
                .transpose()
                .unwrap()
                .unwrap_or_else(|| "absent".into()),
            action: action.into(),
            manifest: m,
        },
        APPROVAL_DOMAIN,
        &"33".repeat(32),
    )
    .unwrap()
}
#[test]
fn lifecycle_cas_retirement_disable() {
    let mut s = state();
    let first = approval(&s, "install", Some(manifest("1", 5)));
    s.apply(first.clone()).unwrap();
    s.apply(first.clone()).unwrap();
    assert_eq!(s.generation, 1);
    let second = approval(&s, "rotate", Some(manifest("2", 6)));
    s.apply(second).unwrap();
    assert!(s.apply(first).is_err());
    let old = approval(&s, "rotate", Some(manifest("3", 5)));
    assert_eq!(s.apply(old).unwrap_err().code, "startup_retired");
    let disabled = approval(&s, "disable", None);
    s.apply(disabled.clone()).unwrap();
    s.apply(disabled).unwrap();
    let revive = approval(&s, "rotate", Some(manifest("4", 7)));
    assert_eq!(s.apply(revive).unwrap_err().code, "startup_disabled");
}
#[test]
fn signature_domain_and_wrong_key_rejected() {
    let s = state();
    let a = approval(&s, "install", Some(manifest("1", 5)));
    assert!(verify::<Approval>(&a, RESPONSE_DOMAIN, &s.approval_key).is_err());
    assert!(verify::<Approval>(&a, APPROVAL_DOMAIN, &public(&"55".repeat(32)).unwrap()).is_err());
}
#[test]
fn capacity_keeps_tombstones_and_allows_disable() {
    let mut s = state();
    s.apply(approval(&s, "install", Some(manifest("1", 5))))
        .unwrap();
    for n in 0..64 {
        let m = manifest(&(n + 2).to_string(), (n + 100) as u8);
        s.apply(approval(&s, "rotate", Some(m))).unwrap();
    }
    let before = serde_json::to_vec(&s).unwrap();
    let over = approval(&s, "rotate", Some(manifest("66", 90)));
    assert_eq!(s.apply(over).unwrap_err().code, "startup_capacity");
    assert_eq!(before, serde_json::to_vec(&s).unwrap());
    s.apply(approval(&s, "disable", None)).unwrap();
    assert!(s.disabled);
    assert_eq!(s.retired.len(), 64);
}
#[test]
fn rotation_requires_new_identity_store_and_anchor() {
    let mut s = state();
    s.apply(approval(&s, "install", Some(manifest("1", 5))))
        .unwrap();
    let mut next = manifest("2", 6);
    next.scope.store_id = s.current.as_ref().unwrap().scope.store_id.clone();
    assert_eq!(
        s.apply(approval(&s, "rotate", Some(next)))
            .unwrap_err()
            .code,
        "startup_successor_required"
    );
}
