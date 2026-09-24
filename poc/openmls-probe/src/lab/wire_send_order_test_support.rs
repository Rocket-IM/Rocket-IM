//! 单未决发送门测试装置；合成 Service 私钥只在测试内签原字节，不写入日志。

use crate::lab::{
    codec, state::DeviceState, store::LockedDevice, wire_tests::Fixture, Context, CrashPoint,
};
use crate::{message_acceptance, permission::receipts::SignedRecord};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::fs;

pub(super) fn pin(f: &Fixture, key: &SigningKey) {
    let members: Vec<_> = f.identities.iter().map(|identity| json!({
        "account_id":identity["account"],"device_id":identity["device"],"signature_key":identity["signature_key"]
    })).collect();
    let checkpoint = json!({"service_id":"S1","conversation_id":"G1","authorization_version":"1",
        "crypto_state_ref":f.call("A",json!({"operation":"wire_inspect"}))["crypto_state_ref"],
        "owner_account_id":"A","members":members});
    for device in ["A", "B", "C"] {
        f.call(
            device,
            json!({"operation":"permission_bootstrap","checkpoint":checkpoint,
            "relay_receipt_key":codec::encode(key.verifying_key().as_bytes())}),
        );
    }
}

pub(super) fn setup() -> (Fixture, SigningKey) {
    let f = Fixture::new();
    let key = SigningKey::from_bytes(&[74; 32]);
    pin(&f, &key);
    (f, key)
}

pub(super) fn enable(f: &Fixture, device: &str) -> Value {
    f.call(device, json!({"operation":"wire_send_order_enable"}))
}

pub(super) fn inspect(f: &Fixture, device: &str) -> Value {
    f.call(device, json!({"operation":"wire_inspect"}))
}

pub(super) fn accept(sent: &Value, key: &SigningKey, id: &str) -> Value {
    let header = codec::decode(sent["envelope"]["header_bytes"].as_str().unwrap()).unwrap();
    let payload = codec::decode(sent["envelope"]["payload_bytes"].as_str().unwrap()).unwrap();
    let fields: Value = serde_json::from_slice(&header).unwrap();
    let body = json!({"protocol_version":"rim-message-acceptance-1","service_id":fields["service_id"],
        "conversation_id":fields["conversation_id"],"acceptance_id":id,
        "envelope_sha256":message_acceptance::envelope_digest(&header,&payload),
        "authorization_version":fields["authorization_version"],"crypto_state_ref":fields["crypto_state_ref"]});
    let raw = serde_json::to_vec(&body).unwrap();
    let mut message = message_acceptance::SIGNING_DOMAIN.to_vec();
    message.extend(&raw);
    let receipt = SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(&key.sign(&message).to_bytes()),
    };
    json!({"operation":"wire_accept","logical_message_id":sent["logical_message_id"],
        "attempt_id":sent["attempt_id"],"acceptance_receipt":receipt})
}

pub(super) fn reject(f: &Fixture, device: &str, operation: Value, code: &str) {
    let snapshot = fs::read(f.root.join(device).join("state.enc")).unwrap();
    let key = fs::read(f.root.join(device).join("device.key")).unwrap();
    f.fails(device, operation, code);
    assert!(snapshot == fs::read(f.root.join(device).join("state.enc")).unwrap());
    assert!(key == fs::read(f.root.join(device).join("device.key")).unwrap());
}

fn context(device: &str) -> Context {
    Context {
        service: "S1".into(),
        account: device.into(),
        device: device.into(),
    }
}

pub(super) fn load(f: &Fixture, device: &str) -> DeviceState {
    LockedDevice::open(&f.root.join(device))
        .unwrap()
        .load(&context(device))
        .unwrap()
        .unwrap()
}

/// 仅构造损坏快照负例；不能作为正常业务写入或跳过真实接受的成功证据。
pub(super) fn alter_invalid(f: &Fixture, device: &str, alter: impl FnOnce(&mut DeviceState)) {
    let locked = LockedDevice::open(&f.root.join(device)).unwrap();
    let mut state = locked.load(&context(device)).unwrap().unwrap();
    alter(&mut state);
    locked.save(&mut state, CrashPoint::None).unwrap();
}
