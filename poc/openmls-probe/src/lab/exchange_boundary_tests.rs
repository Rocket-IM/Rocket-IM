use super::{
    accepted, begin, edit, export, fail_atomic, import, inspect, prepare, public, recover, setup,
    sign,
};
use crate::{
    lab::{codec, consistency_state::Status},
    permission::receipts::SignedRecord,
};
use serde_json::{json, Value};

#[test]
fn exchange_fixed_digest_vector_uses_typed_field_order() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../../api/realtime/vectors.json")).unwrap();
    let v = &vectors["consistency_exchange_request_digest_vector"];
    let request: SignedRecord = serde_json::from_value(v["request"].clone()).unwrap();
    assert_eq!(
        serde_json::to_string(&request).unwrap(),
        v["serialized_utf8"]
    );
    assert_eq!(
        public::request_digest(&request).unwrap(),
        "4113e76b25668ef1ab68d4dfb8fdf018ef90b0c950c14271ec73d2c1d4dd362e"
    );
    assert_eq!(
        public::request_digest(&request).unwrap(),
        v["request_sha256"]
    );
    public::parse_request(&request).unwrap();
}

#[test]
fn exchange_signed_package_binds_every_scope_field_before_any_state_change() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "change");
    for device in ["A", "B"] {
        recover(&f, device, &accepted(&key, &proof));
    }
    let request = begin(&f, "A", "B");
    let package = export(&f, "A", &request, "change");
    let body: Value =
        serde_json::from_slice(&codec::decode(&package.statement_bytes).unwrap()).unwrap();
    for field in [
        "service_id",
        "conversation_id",
        "source",
        "target",
        "challenge",
        "request_sha256",
    ] {
        let mut bad = body.clone();
        bad[field] = match field {
            "source" | "target" => json!({"account_id":"C","device_id":"C"}),
            "challenge" | "request_sha256" => json!("f".repeat(64)),
            _ => json!("other"),
        };
        let package = sign(&f, "A", public::PACKAGE_DOMAIN, &bad);
        fail_atomic(
            &f,
            "B",
            json!({"operation":"consistency_exchange_import","package":package}),
            "exchange_context",
        );
    }
    let mut proof_tamper = body.clone();
    proof_tamper["record"]["change"]["commit_bytes"] = json!(codec::encode(&[1, 2, 3]));
    let bad = sign(&f, "A", public::PACKAGE_DOMAIN, &proof_tamper);
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_exchange_import","package":bad}),
        "permission_context",
    );
    let bad = sign(&f, "C", public::PACKAGE_DOMAIN, &body);
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_exchange_import","package":bad}),
        "exchange_signature",
    );
    let bad = sign(&f, "A", public::REQUEST_DOMAIN, &body);
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_exchange_import","package":bad}),
        "exchange_signature",
    );
    assert_eq!(inspect(&f, "B")["import_count"], 0);
    assert_eq!(inspect(&f, "B")["consistency"]["checking"], true);
}

#[test]
fn exchange_package_boundaries_and_missing_predecessor_do_not_create_coverage() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "change");
    for device in ["A", "B"] {
        recover(&f, device, &accepted(&key, &proof));
    }
    let request = begin(&f, "A", "B");
    let package = export(&f, "A", &request, "change");
    let raw = codec::decode(&package.statement_bytes).unwrap();
    let mut padded = raw.clone();
    padded.resize(public::PACKAGE_LIMIT, b' ');
    let mut candidate = package.clone();
    candidate.statement_bytes = codec::encode(&padded);
    public::parse_package(&candidate).unwrap();
    padded.push(b' ');
    candidate.statement_bytes = codec::encode(&padded);
    assert_eq!(
        public::parse_package(&candidate).unwrap_err().code,
        "exchange_invalid"
    );
    let mut extra: Value = serde_json::from_slice(&raw).unwrap();
    extra["trust"] = json!(true);
    let candidate = sign(&f, "A", public::PACKAGE_DOMAIN, &extra);
    assert_eq!(
        public::parse_package(&candidate).unwrap_err().code,
        "exchange_invalid"
    );
    let mut candidate = package.clone();
    candidate.statement_bytes.push(' ');
    assert_eq!(
        public::parse_package(&candidate).unwrap_err().code,
        "exchange_invalid"
    );
    edit(&f, "B", |state| {
        state.permissions.consistency.checkpoints.remove(&1);
    });
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_exchange_import","package":package}),
        "consistency_coverage",
    );
    assert_eq!(
        inspect(&f, "B")["consistency"]["verified_checkpoint_count"],
        1
    );
}

#[test]
fn exchange_insufficient_retries_after_actual_recovery_and_preserves_prior_pause() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "change");
    recover(&f, "A", &accepted(&key, &proof));
    let request = begin(&f, "A", "B");
    let package = export(&f, "A", &request, "change");
    assert_eq!(
        import(&f, "B", &package)["outcome"],
        "insufficient_comparison"
    );
    recover(&f, "B", &accepted(&key, &proof));
    // 此处只注入既有暂停以检查责任边界；不是回滚事件触发证明。
    edit(&f, "B", |state| {
        state
            .permissions
            .consistency
            .pause(Status::RollbackDetected, "fixture_existing_pause")
    });
    let result = import(&f, "B", &package);
    assert_eq!(result["outcome"], "matched");
    assert_eq!(result["duplicate"], false);
    assert_eq!(result["consistency"]["checking"], false);
    assert_eq!(result["consistency"]["status"], "rollback_detected");
    assert_eq!(inspect(&f, "B")["import_count"], 1);
}

#[test]
fn exchange_cached_paths_recheck_current_pending_and_fingerprint_binding() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "change");
    for device in ["A", "B"] {
        recover(&f, device, &accepted(&key, &proof));
    }
    let request = begin(&f, "A", "B");
    let package = export(&f, "A", &request, "change");
    import(&f, "B", &package);
    f.call("A", json!({"operation":"consistency_challenge"}));
    assert_eq!(export(&f, "A", &request, "change"), package);
    // 正常接口没有改钥入口；合成替换已保存请求中的旧指纹，验证缓存不能跳过核验。
    let mut old: Value =
        serde_json::from_slice(&codec::decode(&request.statement_bytes).unwrap()).unwrap();
    old["source_fingerprint"] = json!("0".repeat(64));
    let stale = sign(&f, "B", public::REQUEST_DOMAIN, &old);
    edit(&f, "B", |state| {
        state
            .permissions
            .exchange
            .imports
            .values_mut()
            .next()
            .unwrap()
            .request = stale
    });
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_exchange_import","package":package}),
        "exchange_key_changed",
    );
    edit(&f, "A", |state| {
        state.permissions.recovery.intent = Some(crate::lab::recovery_state::Intent {
            origin_change_id: "fixture".into(),
            action: crate::permission::Action::RemoveMember {
                account_id: "C".into(),
            },
            minimum_version: "2".into(),
            minimum_state_ref: "f".repeat(64),
            satisfied: false,
        })
    });
    fail_atomic(
        &f,
        "A",
        json!({"operation":"consistency_exchange_export","request":request,"change_id":"change"}),
        "permission_pending",
    );
}
