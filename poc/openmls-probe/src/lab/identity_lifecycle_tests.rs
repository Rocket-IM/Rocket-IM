//! 经实际请求、快照与Rust会话验证核验，不把字段构造当作核验成功。
use super::*;
use std::{fs, path::PathBuf};

struct Fixture {
    root: PathBuf,
    public: Vec<Value>,
    session: Session,
}
impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rim-identity-{}",
                identity_session::random().unwrap()
            ));
        fs::create_dir(&root).unwrap();
        let mut f = Self {
            root,
            public: Vec::new(),
            session: Session::new().unwrap(),
        };
        for device in ["A", "B", "C"] {
            let public = f.call(device, json!({"operation":"init"})).unwrap();
            f.public.push(public);
        }
        f
    }
    fn request(&self, device: &str, mut operation: Value) -> String {
        let map = operation.as_object_mut().unwrap();
        map.insert("directory".into(), json!(self.root.join(device)));
        map.insert("service".into(), json!("S1"));
        map.insert("account".into(), json!(device));
        map.insert("device".into(), json!(device));
        operation.to_string()
    }
    fn call(&mut self, device: &str, operation: Value) -> Result<Value, LabError> {
        let request = self.request(device, operation);
        Ok(self.session.execute(&request)?["result"].clone())
    }
    fn identity(&self, index: usize) -> Value {
        let p = &self.public[index];
        json!({"protocol_version":"rim-device-identity-1","service_id":p["service"],"account_id":p["account"],"device_id":p["device"],"signature_key":p["signature_key"]})
    }
    fn prepare(&mut self) -> Value {
        self.call(
            "A",
            json!({"operation":"identity_trust_observe","identity":self.identity(1)}),
        )
        .unwrap();
        self.call("A", json!({"operation":"identity_trust_prepare","target":{"account_id":"B","device_id":"B"},"purpose":"verify"})).unwrap()["display"].clone()
    }
    fn confirm(&self, display: Value) -> Value {
        json!({"operation":"identity_trust_confirm","display":display,"independent_identity":self.identity(1),"verification":"synthetic_local"})
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.root.join("A/state.enc")).unwrap()
    }
    fn create(&self) -> Value {
        let b = &self.public[1];
        json!({"operation":"create","peers":[{"account":"B","device":"B","signature_key":b["signature_key"],"key_package":b["key_package"]}]})
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn strict_default_and_cached_welcome_require_exact_verified_target() {
    let mut f = Fixture::new();
    let old = f.bytes();
    assert_eq!(
        f.call("A", f.create()).unwrap_err().code,
        "identity_unverified"
    );
    assert_eq!(f.bytes(), old);
    let display = f.prepare();
    assert_eq!(
        f.call("A", f.create()).unwrap_err().code,
        "identity_unverified"
    );
    let before = f.bytes();
    let mut wrong = f.confirm(display.clone());
    wrong["independent_identity"]["account_id"] = json!("C");
    assert_eq!(f.call("A", wrong).unwrap_err().code, "identity_context");
    assert_eq!(f.bytes(), before);
    let confirmation = f.confirm(display);
    let confirmed = f.call("A", confirmation.clone()).unwrap();
    assert_eq!(confirmed["record"]["status"], "verified");
    let saved = f.bytes();
    assert_eq!(f.call("A", confirmation).unwrap()["duplicate"], true);
    assert_eq!(f.bytes(), saved);
    let first = f.call("A", f.create()).unwrap();
    assert_eq!(f.call("A", f.create()).unwrap(), first);
    let mut replacement = f.identity(1);
    replacement["signature_key"] = f.identity(2)["signature_key"].clone();
    assert_eq!(
        f.call(
            "A",
            json!({"operation":"identity_trust_observe","identity":replacement})
        )
        .unwrap()["record"]["status"],
        "changed"
    );
    let blocked = f.bytes();
    assert_eq!(
        f.call("A", f.create()).unwrap_err().code,
        "identity_changed"
    );
    assert_eq!(f.bytes(), blocked);
}

#[test]
fn confirmation_cannot_cross_scope_restart_or_candidate_revision() {
    let mut f = Fixture::new();
    let display = f.prepare();
    f.call("B", json!({"operation":"inspect"})).unwrap();
    let before = f.bytes();
    assert_eq!(
        f.call("A", f.confirm(display)).unwrap_err().code,
        "identity_confirmation_stale"
    );
    assert_eq!(f.bytes(), before);
    let display = f.prepare();
    f.session = Session::new().unwrap();
    assert_eq!(
        f.call("A", f.confirm(display)).unwrap_err().code,
        "identity_confirmation_stale"
    );
    let display = f.prepare();
    let mut replacement = f.identity(1);
    replacement["signature_key"] = f.identity(2)["signature_key"].clone();
    f.call(
        "A",
        json!({"operation":"identity_trust_observe","identity":replacement}),
    )
    .unwrap();
    assert_eq!(
        f.call("A", f.confirm(display)).unwrap_err().code,
        "identity_confirmation_stale"
    );
}

#[test]
fn committed_confirmation_survives_restart_but_old_display_does_not() {
    let mut f = Fixture::new();
    let display = f.prepare();
    let confirmation = f.confirm(display);
    f.call("A", confirmation.clone()).unwrap();
    let before = f.bytes();
    f.session = Session::new().unwrap();
    let inspected = f
        .call("A", json!({"operation":"identity_trust_inspect"}))
        .unwrap();
    assert_eq!(inspected["records"][0]["status"], "verified");
    assert_eq!(
        f.call("A", confirmation).unwrap_err().code,
        "identity_confirmation_stale"
    );
    assert_eq!(f.bytes(), before);
}

#[test]
fn registration_proof_binds_local_identity_without_saving_or_trusting_peers() {
    let mut f = Fixture::new();
    assert_eq!(f.public[0]["identity_trust_version"], "1");
    assert_eq!(f.public[0]["identity_trust_strict"], true);
    let challenge = json!({"protocol_version":"rim-device-registration-1","service_id":"S1","account_id":"A","device_id":"A","registration_id":"R1","signature_key":f.public[0]["signature_key"],"purpose":"register_device","challenge_nonce":codec::encode(&[7;32]),"issued_at_ms":"1","expires_at_ms":"2"});
    let before = f.bytes();
    let encoded = codec::encode(&serde_json::to_vec(&challenge).unwrap());
    let request = json!({"operation":"device_registration_prove","challenge_bytes":encoded});
    let proof = f.call("A", request.clone()).unwrap();
    assert_eq!(f.call("A", request).unwrap(), proof);
    let proof: crate::permission::receipts::SignedRecord =
        serde_json::from_value(proof["proof"].clone()).unwrap();
    assert_eq!(
        crate::device_registration::verify_proof(&proof)
            .unwrap()
            .account_id,
        "A"
    );
    assert_eq!(f.bytes(), before);
    assert!(f
        .call("A", json!({"operation":"identity_trust_inspect"}))
        .unwrap()["records"]
        .as_array()
        .unwrap()
        .is_empty());
    for field in ["service_id", "account_id", "device_id", "signature_key"] {
        let mut wrong = challenge.clone();
        wrong[field] = if field == "signature_key" {
            f.public[1]["signature_key"].clone()
        } else {
            json!("other")
        };
        assert_eq!(f.call("A",json!({"operation":"device_registration_prove","challenge_bytes":codec::encode(&serde_json::to_vec(&wrong).unwrap())})).unwrap_err().code,"registration_context");
    }
    assert_eq!(f.bytes(), before);
}

#[test]
fn entire_display_is_exact_and_nullable_previous_must_be_present() {
    let mut f = Fixture::new();
    let display = f.prepare();
    let before = f.bytes();
    for field in [
        "protocol_version",
        "record_revision",
        "session_nonce",
        "display_nonce",
    ] {
        let mut changed = display.clone();
        changed[field] = json!("altered");
        assert_eq!(
            f.call("A", f.confirm(changed)).unwrap_err().code,
            "identity_confirmation_stale"
        );
    }
    let mut missing = display.clone();
    missing.as_object_mut().unwrap().remove("previous");
    assert_eq!(
        f.call("A", f.confirm(missing)).unwrap_err().code,
        "invalid_request"
    );
    let mut unknown = display;
    unknown["trusted_by_service"] = json!(true);
    assert_eq!(
        f.call("A", f.confirm(unknown)).unwrap_err().code,
        "invalid_request"
    );
    assert_eq!(f.bytes(), before);
}
