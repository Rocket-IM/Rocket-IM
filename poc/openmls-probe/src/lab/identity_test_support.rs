//! 测试控制器明确交换公开对象，走真实观察/展示/确认入口，不直接写核验账本。
use super::Session;
use serde_json::{json, Value};
use std::path::Path;

pub(super) fn verify(directory: &Path, service: &str, account: &str, device: &str, public: &Value) {
    let identity = json!({"protocol_version":"rim-device-identity-1","service_id":public["service"],
        "account_id":public["account"],"device_id":public["device"],"signature_key":public["signature_key"]});
    let mut session = Session::new().unwrap();
    let mut call = |mut operation: Value| {
        let map = operation.as_object_mut().unwrap();
        map.insert("directory".into(), json!(directory));
        map.insert("service".into(), json!(service));
        map.insert("account".into(), json!(account));
        map.insert("device".into(), json!(device));
        session.execute(&operation.to_string()).unwrap()["result"].clone()
    };
    call(json!({"operation":"identity_trust_observe","identity":identity}));
    let display = call(json!({"operation":"identity_trust_prepare","target":{"account_id":public["account"],"device_id":public["device"]},"purpose":"verify"}))["display"].clone();
    call(
        json!({"operation":"identity_trust_confirm","display":display,"independent_identity":identity,"verification":"synthetic_local"}),
    );
}
