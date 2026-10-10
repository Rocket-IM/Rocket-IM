//! 新初始化共用公开身份标识规则；合成旧快照只验证旧范围的读取兼容性。
use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rim-identity-init-{}",
                identity_session::random().unwrap()
            ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn request(&self, directory: &str, context: &Context, mut operation: Value) -> String {
        let fields = operation.as_object_mut().unwrap();
        fields.insert("directory".into(), json!(self.0.join(directory)));
        fields.insert("service".into(), json!(context.service));
        fields.insert("account".into(), json!(context.account));
        fields.insert("device".into(), json!(context.device));
        operation.to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context() -> Context {
    Context {
        service: "S1".into(),
        account: "A".into(),
        device: "A1".into(),
    }
}

fn replace(context: &mut Context, index: usize, value: &str) {
    match index {
        0 => context.service = value.into(),
        1 => context.account = value.into(),
        _ => context.device = value.into(),
    }
}

#[test]
fn new_identity_rejects_incompatible_ids_before_creating_device_files() {
    let f = Fixture::new();
    for field in 0..3 {
        for value in [
            "设备".into(),
            "has space".into(),
            "has.dot".into(),
            "a".repeat(65),
            "a".repeat(128),
            "".into(),
            "a\nb".into(),
        ] {
            let mut context = context();
            replace(&mut context, field, &value);
            let error =
                execute(&f.request("new", &context, json!({"operation":"init"}))).unwrap_err();
            assert_eq!(error.code, "invalid_id");
            assert!(
                !f.0.join("new").exists(),
                "invalid init created device files"
            );
        }
    }
    let existing = f.0.join("empty");
    fs::create_dir(&existing).unwrap();
    fs::set_permissions(&existing, fs::Permissions::from_mode(0o700)).unwrap();
    let mut context = context();
    context.account = "a".repeat(65);
    assert_eq!(
        execute(&f.request("empty", &context, json!({"operation":"init"})))
            .unwrap_err()
            .code,
        "invalid_id"
    );
    assert_eq!(fs::read_dir(existing).unwrap().count(), 0);
}

#[test]
fn maximum_ascii_ids_support_registration_and_first_verification() {
    let f = Fixture::new();
    let context = Context {
        service: "S_0-".repeat(16),
        account: "A_0-".repeat(16),
        device: "D_0-".repeat(16),
    };
    let public = execute(&f.request("new", &context, json!({"operation":"init"}))).unwrap();
    let identity = identity_state::object(
        &context.service,
        &context.account,
        &context.device,
        public["result"]["signature_key"].as_str().unwrap(),
    );
    identity.validate().unwrap();
    let challenge = crate::device_registration::Challenge {
        protocol_version: "rim-device-registration-1".into(),
        service_id: context.service.clone(),
        account_id: context.account.clone(),
        device_id: context.device.clone(),
        registration_id: "registration".into(),
        signature_key: identity.signature_key.clone(),
        purpose: "register_device".into(),
        challenge_nonce: codec::encode(&[7; 32]),
        issued_at_ms: "1".into(),
        expires_at_ms: "300001".into(),
    };
    let proof = execute(&f.request(
        "new",
        &context,
        json!({"operation":"device_registration_prove",
        "challenge_bytes":codec::encode(&serde_json::to_vec(&challenge).unwrap())}),
    ))
    .unwrap();
    let proof = serde_json::from_value(proof["result"]["proof"].clone()).unwrap();
    assert_eq!(
        crate::device_registration::verify_proof(&proof).unwrap(),
        challenge
    );

    let other = DeviceState::new(Context {
        service: context.service.clone(),
        account: "B".into(),
        device: "B1".into(),
    })
    .unwrap();
    let target = identity_state::own(&other);
    let mut session = Session::new().unwrap();
    session
        .execute(&f.request(
            "new",
            &context,
            json!({"operation":"identity_trust_observe","identity":target}),
        ))
        .unwrap();
    let prepared = session.execute(&f.request("new", &context,
        json!({"operation":"identity_trust_prepare","target":{"account_id":"B","device_id":"B1"},"purpose":"verify"}))).unwrap();
    let display = &prepared["result"]["display"];
    assert_eq!(display["observer"], serde_json::to_value(identity).unwrap());
    let confirmed = session
        .execute(&f.request(
            "new",
            &context,
            json!({"operation":"identity_trust_confirm","display":display,
            "independent_identity":target,"verification":"synthetic_local"}),
        ))
        .unwrap();
    assert_eq!(confirmed["result"]["record"]["status"], "verified");
}

#[test]
fn legacy_wide_ids_remain_readable_but_identity_workflows_fail_without_writes() {
    let f = Fixture::new();
    let target = identity_state::own(&DeviceState::new(context()).unwrap());
    let display = json!({"protocol_version":"rim-identity-verification-1",
        "observer":target,"identity":target,"previous":null,"record_revision":"1",
        "session_nonce":"unused","display_nonce":"unused","purpose":"verify"});
    let operations = [
        json!({"operation":"identity_trust_observe","identity":target}),
        json!({"operation":"identity_trust_prepare","target":{"account_id":"A","device_id":"A1"},"purpose":"verify"}),
        json!({"operation":"identity_trust_confirm","display":display,
            "independent_identity":target,"verification":"synthetic_local"}),
        json!({"operation":"identity_trust_reset","display":display,
            "independent_identity":target,"verification":"synthetic_local"}),
        json!({"operation":"device_registration_prove","challenge_bytes":"AA=="}),
    ];
    for field in 0..3 {
        for (offset, wide) in ["旧设备".into(), "a".repeat(65)].iter().enumerate() {
            let name = format!("legacy-{field}-{offset}");
            let mut context = context();
            replace(&mut context, field, wide);
            // 只为本单元测试构造旧格式，真实历史二进制兼容证据由联合验证单独记录。
            let mut state = DeviceState::new(context.clone()).unwrap();
            state.identity_trust = None;
            let directory = f.0.join(&name);
            let locked = LockedDevice::open(&directory).unwrap();
            locked.save(&mut state, CrashPoint::None).unwrap();
            drop(locked);
            let before = fs::read(directory.join("state.enc")).unwrap();
            execute(&f.request(&name, &context, json!({"operation":"inspect"}))).unwrap();
            let inspected = execute(&f.request(
                &name,
                &context,
                json!({"operation":"identity_trust_inspect"}),
            ))
            .unwrap();
            assert_eq!(inspected["result"]["records"], json!([]));
            for operation in &operations {
                let error = execute(&f.request(&name, &context, operation.clone())).unwrap_err();
                assert_eq!(error.code, "identity_invalid");
                assert!(error.message.contains("1—64"));
                assert_eq!(fs::read(directory.join("state.enc")).unwrap(), before);
            }
        }
    }
}
