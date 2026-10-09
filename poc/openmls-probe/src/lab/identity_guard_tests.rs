//! 实际原消息/权限入口的回归，查询不会授予外发或清除独立门禁。
use super::*;
use std::fs;

fn replacement() -> crate::identity_trust::DeviceIdentity {
    identity_state::own(
        &DeviceState::new(Context {
            service: "S1".into(),
            account: "B".into(),
            device: "B".into(),
        })
        .unwrap(),
    )
}

fn verify_replacement(f: &wire_tests::Fixture, identity: &crate::identity_trust::DeviceIdentity) {
    let mut session = Session::new().unwrap();
    let mut call =
        |operation: Value| session.execute(&f.request("A", operation)).unwrap()["result"].clone();
    let display = call(json!({"operation":"identity_trust_prepare","target":{"account_id":"B","device_id":"B"},"purpose":"reset"}))["display"].clone();
    call(
        json!({"operation":"identity_trust_reset","display":display,"independent_identity":identity,"verification":"synthetic_local"}),
    );
    let display = call(json!({"operation":"identity_trust_prepare","target":{"account_id":"B","device_id":"B"},"purpose":"verify"}))["display"].clone();
    call(
        json!({"operation":"identity_trust_confirm","display":display,"independent_identity":identity,"verification":"synthetic_local"}),
    );
}

#[test]
fn original_wire_and_legacy_ciphertext_cannot_follow_reset_identity() {
    let f = wire_tests::Fixture::new();
    let sent = f.send("A", "original");
    let old_request = json!({"operation":"send","id":"old","payload":"synthetic legacy"});
    let old = f.call("A", old_request.clone());
    assert_eq!(f.send("A", "original")["envelope"], sent["envelope"]);
    assert_eq!(
        f.call("A", old_request.clone())["ciphertext"],
        old["ciphertext"]
    );
    let identity = replacement();
    f.call(
        "A",
        json!({"operation":"identity_trust_observe","identity":identity}),
    );
    let original = fs::read(f.root.join("A/state.enc")).unwrap();
    f.fails("A", old_request.clone(), "identity_changed");
    f.fails("A", json!({"operation":"wire_send","logical_message_id":"original","attempt_id":"P1","payload":"synthetic test content"}), "identity_changed");
    assert_eq!(fs::read(f.root.join("A/state.enc")).unwrap(), original);
    verify_replacement(&f, &identity);
    let reset = fs::read(f.root.join("A/state.enc")).unwrap();
    f.fails("A", old_request, "identity_changed");
    f.fails("A", json!({"operation":"wire_send","logical_message_id":"original","attempt_id":"P1","payload":"synthetic test content"}), "identity_changed");
    assert_eq!(fs::read(f.root.join("A/state.enc")).unwrap(), reset);
}

#[test]
fn public_permission_query_keeps_pending_and_q02_guards() {
    let f = wire_tests::Fixture::new();
    let members: Vec<_> = f.identities.iter().map(|p| json!({"account_id":p["account"],"device_id":p["device"],"signature_key":p["signature_key"]})).collect();
    let cp = json!({"service_id":"S1","conversation_id":"G1","authorization_version":"1","crypto_state_ref":f.call("A",json!({"operation":"wire_inspect"}))["crypto_state_ref"],"owner_account_id":"A","members":members});
    let signer = ed25519_dalek::SigningKey::from_bytes(&[45; 32]);
    f.call("A",json!({"operation":"permission_bootstrap","checkpoint":cp,"relay_receipt_key":codec::encode(signer.verifying_key().as_bytes())}));
    let proof = f.call("A",json!({"operation":"permission_prepare","change_id":"pending","action":{"kind":"remove_member","account_id":"C"}}));
    let identity = replacement();
    f.call(
        "A",
        json!({"operation":"identity_trust_observe","identity":identity}),
    );
    let before = fs::read(f.root.join("A/state.enc")).unwrap();
    let queried = f.call("A", json!({"operation":"permission_inspect"}));
    assert_eq!(queried["pending_change"], proof["change"]);
    assert!(queried.get("welcome").is_none());
    f.fails("A",json!({"operation":"permission_prepare","change_id":"pending","action":{"kind":"remove_member","account_id":"C"}}),"identity_changed");
    assert_eq!(fs::read(f.root.join("A/state.enc")).unwrap(), before);
    verify_replacement(&f, &identity);
    f.fails("A",json!({"operation":"wire_send","logical_message_id":"blocked","attempt_id":"P1","payload":"synthetic"}),"permission_pending");
    f.call("A", json!({"operation":"consistency_challenge"}));
    let paused = fs::read(f.root.join("A/state.enc")).unwrap();
    f.call("A", json!({"operation":"permission_inspect"}));
    f.call("A", json!({"operation":"identity_trust_inspect"}));
    f.fails(
        "A",
        json!({"operation":"identity_trust_observe","identity":identity}),
        "consistency_paused",
    );
    assert_eq!(fs::read(f.root.join("A/state.enc")).unwrap(), paused);
    assert_eq!(
        f.call("A", json!({"operation":"consistency_inspect"}))["paused"],
        true
    );
}

#[test]
fn colliding_directory_replacement_persists_pause_and_cannot_reset_into_binding() {
    for source in [0, 2] {
        let f = wire_tests::Fixture::new();
        f.send("A", "beforeCollision");
        let original = identity_state::object(
            "S1",
            "B",
            "B",
            f.identities[1]["signature_key"].as_str().unwrap(),
        );
        let collision = identity_state::object(
            "S1",
            "B",
            "B",
            f.identities[source]["signature_key"].as_str().unwrap(),
        );
        let observed = f.call(
            "A",
            json!({"operation":"identity_trust_observe","identity":collision}),
        );
        assert_eq!(
            observed["record"]["identity"],
            serde_json::to_value(&original).unwrap()
        );
        assert_eq!(
            observed["record"]["candidate"],
            serde_json::to_value(&collision).unwrap()
        );
        assert_eq!(observed["record"]["status"], "changed");
        // 每次公开调用重新加载加密快照；拒绝前后保留原绑定和候选。
        let before = fs::read(f.root.join("A/state.enc")).unwrap();
        assert_eq!(f.call("A",json!({"operation":"identity_trust_inspect","target":{"account_id":"B","device_id":"B"}}))["records"][0]["status"],"changed");
        f.fails("A",json!({"operation":"wire_send","logical_message_id":"beforeCollision","attempt_id":"P1","payload":"synthetic test content"}),"identity_changed");
        f.fails("A",json!({"operation":"wire_send","logical_message_id":"afterCollision","attempt_id":"P1","payload":"synthetic test content"}),"identity_changed");
        let mut session = Session::new().unwrap();
        let prepared = session.execute(&f.request("A",json!({"operation":"identity_trust_prepare","target":{"account_id":"B","device_id":"B"},"purpose":"reset"}))).unwrap();
        let reset = json!({"operation":"identity_trust_reset","display":prepared["result"]["display"],"independent_identity":collision,"verification":"synthetic_local"});
        assert_eq!(
            session.execute(&f.request("A", reset)).unwrap_err().code,
            "identity_changed"
        );
        assert!(fs::read(f.root.join("A/state.enc")).unwrap() == before);
        // 返回旧目录对象不会静默清除异常；本轮没有“忽略冲突”操作。
        assert_eq!(
            f.call(
                "A",
                json!({"operation":"identity_trust_observe","identity":original})
            )["record"]["status"],
            "changed"
        );
        assert!(fs::read(f.root.join("A/state.enc")).unwrap() == before);
        let fresh = replacement();
        f.call(
            "A",
            json!({"operation":"identity_trust_observe","identity":fresh}),
        );
        verify_replacement(&f, &fresh);
        assert_eq!(f.call("A",json!({"operation":"identity_trust_inspect","target":{"account_id":"B","device_id":"B"}}))["records"][0]["status"],"verified");
        // 显式新身份核验仍不能授权旧消息向另一个身份重发。
        f.fails("A",json!({"operation":"wire_send","logical_message_id":"beforeCollision","attempt_id":"P1","payload":"synthetic test content"}),"identity_changed");
    }
}
