//! 旧绑定入口与核验账本组合后，任何拒绝均保留可加载的设备状态。
use super::*;

fn pin(account: &str, key: &Value) -> Value {
    json!({"operation":"permission_pin_member","member":{"account_id":account,"device_id":account,"signature_key":key}})
}

#[test]
fn verified_key_cannot_be_pinned_to_another_device_and_normal_verification_continues() {
    let mut f = Fixture::new();
    let display = f.prepare();
    f.call("A", f.confirm(display)).unwrap();
    let before = f.bytes();
    assert_eq!(
        f.call("A", pin("C", &f.public[1]["signature_key"]))
            .unwrap_err()
            .code,
        "identity_changed"
    );
    assert_eq!(f.bytes(), before);
    let own_key = f.public[0]["signature_key"].clone();
    assert_eq!(
        f.call("A", pin("C", &own_key)).unwrap_err().code,
        "identity_changed"
    );
    assert_eq!(f.bytes(), before);
    f.session = Session::new().unwrap();
    f.call("A", json!({"operation":"inspect"})).unwrap();
    f.call("A", pin("C", &f.public[2]["signature_key"]))
        .unwrap();
    f.call(
        "A",
        json!({"operation":"identity_trust_observe","identity":f.identity(2)}),
    )
    .unwrap();
    let display = f.call("A", json!({"operation":"identity_trust_prepare","target":{"account_id":"C","device_id":"C"},"purpose":"verify"})).unwrap()["display"].clone();
    f.call("A", json!({"operation":"identity_trust_confirm","display":display,"independent_identity":f.identity(2),"verification":"synthetic_local"})).unwrap();
    let records = f
        .call("A", json!({"operation":"identity_trust_inspect"}))
        .unwrap();
    assert_eq!(records["records"].as_array().unwrap().len(), 2);
    assert!(records["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["status"] == "verified"));
}

#[test]
fn preexisting_conflicting_legacy_pin_cannot_poison_a_saved_identity_ledger() {
    let mut f = Fixture::new();
    let display = f.prepare();
    f.call("A", f.confirm(display)).unwrap();
    // 模拟旧版本已允许的 pin；账本本身仍有效。拒绝发生在新候选保存前。
    {
        let locked = store::LockedDevice::open(&f.root.join("A")).unwrap();
        let context = Context {
            service: "S1".into(),
            account: "A".into(),
            device: "A".into(),
        };
        let mut state = locked.load(&context).unwrap().unwrap();
        state.peer_pins.push(Pin {
            account: "C".into(),
            device: "C".into(),
            signature_key: f.public[1]["signature_key"].as_str().unwrap().into(),
        });
        locked.save(&mut state, CrashPoint::None).unwrap();
    }
    let before = f.bytes();
    assert_eq!(
        f.call(
            "A",
            json!({"operation":"identity_trust_observe","identity":f.identity(2)})
        )
        .unwrap_err()
        .code,
        "identity_invalid"
    );
    assert_eq!(f.bytes(), before);
    f.session = Session::new().unwrap();
    f.call("A", json!({"operation":"inspect"})).unwrap();
    assert_eq!(
        f.call("A", json!({"operation":"identity_trust_inspect"}))
            .unwrap()["records"][0]["status"],
        "verified"
    );
    let mut replacement = f.identity(1);
    replacement["signature_key"] = f.public[2]["signature_key"].clone();
    f.call(
        "A",
        json!({"operation":"identity_trust_observe","identity":replacement}),
    )
    .unwrap();
    let display = f.call("A", json!({"operation":"identity_trust_prepare","target":{"account_id":"B","device_id":"B"},"purpose":"reset"})).unwrap()["display"].clone();
    f.call("A", json!({"operation":"identity_trust_reset","display":display,"independent_identity":replacement,"verification":"synthetic_local"})).unwrap();
    f.call("A", json!({"operation":"inspect"})).unwrap();
}

#[test]
fn retired_key_cannot_gain_a_new_pin_but_exact_original_pin_remains_readable() {
    let mut f = Fixture::new();
    let old_key = f.public[1]["signature_key"].clone();
    f.call("A", pin("B", &old_key)).unwrap();
    let display = f.prepare();
    f.call("A", f.confirm(display)).unwrap();
    let mut replacement = f.identity(1);
    replacement["signature_key"] = f.public[2]["signature_key"].clone();
    f.call(
        "A",
        json!({"operation":"identity_trust_observe","identity":replacement}),
    )
    .unwrap();
    let display = f.call("A", json!({"operation":"identity_trust_prepare","target":{"account_id":"B","device_id":"B"},"purpose":"reset"})).unwrap()["display"].clone();
    f.call("A", json!({"operation":"identity_trust_reset","display":display,"independent_identity":replacement,"verification":"synthetic_local"})).unwrap();
    let before = f.bytes();
    assert_eq!(
        f.call("A", pin("C", &old_key)).unwrap_err().code,
        "identity_changed"
    );
    assert_eq!(f.bytes(), before);
    assert_eq!(f.call("A", pin("B", &old_key)).unwrap()["reused"], true);
    assert_eq!(
        f.call("A", json!({"operation":"identity_trust_inspect"}))
            .unwrap()["records"][0]["status"],
        "unverified"
    );
}

#[test]
fn legacy_roster_admission_checks_other_accounts_identity_bindings() {
    let mut f = Fixture::new();
    let request = json!({"directory":f.root.join("A2"),"service":"S1","account":"A","device":"A2","operation":"init"});
    let public = f.session.execute(&request.to_string()).unwrap()["result"].clone();
    let mut claimed = f.identity(2);
    claimed["signature_key"] = public["signature_key"].clone();
    f.call(
        "A",
        json!({"operation":"identity_trust_observe","identity":claimed}),
    )
    .unwrap();
    let raw = codec::decode(public["key_package"].as_str().unwrap()).unwrap();
    let key = codec::decode(public["signature_key"].as_str().unwrap()).unwrap();
    let authorization = crate::authorization::AuthorizationRequest {
        service: "S1".into(),
        account: "A".into(),
        signer_device: "A".into(),
        new_device: "A2".into(),
        new_signature_key: key.try_into().unwrap(),
        key_package_sha256: crate::authorization::key_package_sha256(&raw),
        expected_roster_version: 0,
        nonce: [17; 32],
        issued_at_unix_secs: 1,
        expires_at_unix_secs: 100,
    };
    let signed = f
        .call(
            "A",
            json!({"operation":"sign_authorization","request":authorization}),
        )
        .unwrap();
    let before = f.bytes();
    assert_eq!(f.call("A", json!({"operation":"authorize","authorization":signed["authorization"],"key_package":public["key_package"],"now_unix_secs":2})).unwrap_err().code, "identity_changed");
    assert_eq!(f.bytes(), before);
    assert_eq!(
        f.call("A", json!({"operation":"inspect"})).unwrap()["roster_version"],
        0
    );
}
