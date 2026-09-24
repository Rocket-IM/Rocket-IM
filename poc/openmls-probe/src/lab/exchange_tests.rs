use super::{
    accepted, checkpoint, closed, fail_atomic, prepare, recover, setup, Context, Fixture,
    LockedDevice,
};
use crate::{
    consistency_exchange as public,
    lab::{codec, exchange_state, state::DeviceState, CrashPoint},
    permission::receipts::SignedRecord,
};
use serde_json::{json, Value};

#[path = "exchange_boundary_tests.rs"]
mod boundaries;

fn edit(f: &Fixture, device: &str, body: impl FnOnce(&mut DeviceState)) {
    let locked = LockedDevice::open(&f.root.join(device)).unwrap();
    let mut state = locked
        .load(&Context {
            service: "S1".into(),
            account: device.into(),
            device: device.into(),
        })
        .unwrap()
        .unwrap();
    body(&mut state);
    locked.save(&mut state, CrashPoint::None).unwrap();
}

fn begin(f: &Fixture, source: &str, target: &str) -> SignedRecord {
    let key = f
        .identities
        .iter()
        .find(|id| id["device"] == source)
        .unwrap()["signature_key"]
        .as_str()
        .unwrap();
    serde_json::from_value(f.call(target,json!({"operation":"consistency_exchange_begin","source":{"account_id":source,"device_id":source},"verified_fingerprint":public::fingerprint(key).unwrap(),"verification":"synthetic_local"}))["request"].clone()).unwrap()
}

fn export(f: &Fixture, source: &str, request: &SignedRecord, id: &str) -> SignedRecord {
    serde_json::from_value(
        f.call(
            source,
            json!({"operation":"consistency_exchange_export","request":request,"change_id":id}),
        )["package"]
            .clone(),
    )
    .unwrap()
}

fn import(f: &Fixture, target: &str, package: &SignedRecord) -> Value {
    f.call(
        target,
        json!({"operation":"consistency_exchange_import","package":package}),
    )
}

fn inspect(f: &Fixture, target: &str) -> Value {
    f.call(target, json!({"operation":"consistency_exchange_inspect"}))
}

fn sign(f: &Fixture, device: &str, domain: &[u8], value: &Value) -> SignedRecord {
    let mut signed = None;
    edit(f, device, |state| {
        signed = Some(exchange_state::sign(state, domain, value).unwrap())
    });
    signed.unwrap()
}

#[test]
fn exchange_actual_holders_match_and_duplicate_preserves_later_gate() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "change");
    for device in ["A", "B"] {
        recover(&f, device, &accepted(&key, &proof));
    }
    let request = begin(&f, "A", "B");
    assert_eq!(begin(&f, "A", "B"), request);
    let package = export(&f, "A", &request, "change");
    assert_eq!(export(&f, "A", &request, "change"), package);
    let before = f.call("B", json!({"operation":"permission_inspect"}));
    let result = import(&f, "B", &package);
    assert_eq!(result["outcome"], "matched");
    assert_eq!(result["consistency"]["paused"], false);
    assert_eq!(result["consistency"]["freshness"], "unknown");
    assert_eq!(
        f.call("B", json!({"operation":"permission_inspect"})),
        before
    );
    let later = f.call("B", json!({"operation":"consistency_challenge"}));
    assert_eq!(import(&f, "B", &package)["duplicate"], true);
    assert_eq!(
        inspect(&f, "B")["consistency"]["challenge"],
        later["challenge"]
    );
    assert_eq!(
        inspect(&f, "B")["imports"][0]["verification"],
        "synthetic_local"
    );
    fail_atomic(
        &f,
        "A",
        json!({"operation":"consistency_exchange_export","request":request,"change_id":"other"}),
        "exchange_conflict",
    );
}

#[test]
fn exchange_actual_fork_is_saved_and_survives_revocation_and_cancel() {
    let (f, key) = setup();
    let left = prepare(&f, "A", "left");
    recover(&f, "B", &accepted(&key, &left));
    recover(&f, "A", &closed(&key, &left));
    let right = prepare(&f, "A", "right");
    recover(&f, "A", &accepted(&key, &right));
    let request = begin(&f, "A", "B");
    let package = export(&f, "A", &request, "right");
    let result = import(&f, "B", &package);
    assert_eq!(result["outcome"], "fork_detected");
    assert_eq!(result["consistency"]["status"], "fork_detected");
    assert_eq!(inspect(&f, "B")["consistency"]["fork_evidence_count"], 1);
    f.fails("B",json!({"operation":"wire_send","logical_message_id":"blocked","attempt_id":"P","payload":"test"}),"consistency_paused");
    // 合成状态只用于验证重试当前钥门禁；真实分叉与两端应用已由前面的操作取得。
    edit(&f, "B", |state| {
        state.permissions.recovery.access_removed = true
    });
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_exchange_import","package":package}),
        "access_removed",
    );
    assert_eq!(inspect(&f, "B")["consistency"]["status"], "fork_detected");
    f.call("B", json!({"operation":"consistency_exchange_cancel"}));
    assert_eq!(inspect(&f, "B")["consistency"]["status"], "fork_detected");
}

#[test]
fn exchange_insufficient_or_cancel_never_clear_checking() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "change");
    recover(&f, "A", &accepted(&key, &proof));
    let request = begin(&f, "A", "B");
    let package = export(&f, "A", &request, "change");
    assert_eq!(
        import(&f, "B", &package)["outcome"],
        "insufficient_comparison"
    );
    assert_eq!(inspect(&f, "B")["consistency"]["checking"], true);
    f.call("B", json!({"operation":"consistency_exchange_cancel"}));
    assert_eq!(inspect(&f, "B")["consistency"]["checking"], true);
    let key = f.identities[0]["signature_key"].as_str().unwrap();
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_exchange_begin","source":{"account_id":"A","device_id":"A"},"verified_fingerprint":public::fingerprint(key).unwrap(),"verification":"synthetic_local"}),
        "exchange_challenge_required",
    );
    // 已记录的包可重试，但从未导入的迟到包在取消后不得建立新交换。
    let (f, key) = setup();
    let proof = prepare(&f, "A", "change");
    recover(&f, "A", &accepted(&key, &proof));
    let request = begin(&f, "A", "B");
    let package = export(&f, "A", &request, "change");
    f.call("B", json!({"operation":"consistency_exchange_cancel"}));
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_exchange_import","package":package}),
        "exchange_unavailable",
    );
}

#[test]
fn exchange_request_strict_fields_signature_and_stale_fingerprints() {
    let (f, _) = setup();
    let request = begin(&f, "A", "B");
    let raw = codec::decode(&request.statement_bytes).unwrap();
    let original: Value = serde_json::from_slice(&raw).unwrap();
    for field in ["source_fingerprint", "target_fingerprint"] {
        let mut stale = original.clone();
        stale[field] = json!("f".repeat(64));
        let request = sign(&f, "B", public::REQUEST_DOMAIN, &stale);
        fail_atomic(
            &f,
            "A",
            json!({"operation":"consistency_exchange_export","request":request,"change_id":"missing"}),
            "exchange_key_changed",
        );
    }
    let wrong = sign(&f, "B", public::PACKAGE_DOMAIN, &original);
    fail_atomic(
        &f,
        "A",
        json!({"operation":"consistency_exchange_export","request":wrong,"change_id":"missing"}),
        "exchange_signature",
    );
    let mut extra = original.clone();
    extra["trusted"] = json!(true);
    let extra = sign(&f, "B", public::REQUEST_DOMAIN, &extra);
    assert_eq!(
        public::parse_request(&extra).unwrap_err().code,
        "exchange_invalid"
    );
    let duplicate = String::from_utf8(raw.clone()).unwrap().replacen(
        "{",
        "{\"challenge\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
        1,
    );
    let mut malformed = request.clone();
    malformed.statement_bytes = codec::encode(duplicate.as_bytes());
    assert_eq!(
        public::parse_request(&malformed).unwrap_err().code,
        "exchange_invalid"
    );
    let mut padded = raw;
    padded.resize(public::REQUEST_LIMIT, b' ');
    malformed.statement_bytes = codec::encode(&padded);
    public::parse_request(&malformed).unwrap();
    padded.push(b' ');
    malformed.statement_bytes = codec::encode(&padded);
    assert_eq!(
        public::parse_request(&malformed).unwrap_err().code,
        "exchange_invalid"
    );
}

#[test]
fn exchange_capacity_is_atomic_and_old_snapshot_defaults_do_not_create_trust() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "change");
    for device in ["A", "B"] {
        recover(&f, device, &accepted(&key, &proof));
    }
    let request = begin(&f, "A", "B");
    let package = export(&f, "A", &request, "change");
    import(&f, "B", &package);
    // 仅复制已公开的测试记录来触及容量，不声称执行过128次独立交换。
    edit(&f, "A", |state| {
        let export = state
            .permissions
            .exchange
            .exports
            .values()
            .next()
            .unwrap()
            .clone();
        state.permissions.exchange.exports = (0..exchange_state::LIMIT)
            .map(|i| (format!("fixture_{i}"), export.clone()))
            .collect();
    });
    fail_atomic(
        &f,
        "A",
        json!({"operation":"consistency_exchange_export","request":request,"change_id":"change"}),
        "resource_exhausted",
    );
    let request = begin(&f, "A", "B");
    edit(&f, "B", |state| {
        let import = state
            .permissions
            .exchange
            .imports
            .values()
            .next()
            .unwrap()
            .clone();
        state.permissions.exchange.imports = (0..exchange_state::LIMIT)
            .map(|i| (format!("fixture_{i}"), import.clone()))
            .collect();
    });
    // 重新生成只绑定新请求的公开包，沿真实本机持有路径取得。
    edit(&f, "A", |state| state.permissions.exchange.exports.clear());
    let package = export(&f, "A", &request, "change");
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_exchange_import","package":package}),
        "resource_exhausted",
    );
    assert_eq!(inspect(&f, "B")["consistency"]["checking"], true);
    edit(&f, "B", |state| {
        let provider = std::mem::take(&mut state.provider);
        let mut value = serde_json::to_value(&*state).unwrap();
        value["permissions"]
            .as_object_mut()
            .unwrap()
            .remove("exchange");
        *state = serde_json::from_value(value).unwrap();
        state.provider = provider;
    });
    assert_eq!(inspect(&f, "B")["import_count"], 0);
    assert_eq!(inspect(&f, "B")["consistency"]["checking"], true);
    assert_eq!(checkpoint(&f).authorization_version, "1");
}
