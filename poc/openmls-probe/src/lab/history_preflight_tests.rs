//! 预检只用真实快照的元数据；空 provider 保证不会预约前加载 MLS。
use super::*;
use crate::lab::{state::DeviceState, wire_receive, Operation};

fn metadata(f: &Fixture) -> DeviceState {
    let state = crate::lab::wire_send_order_test_support::load(f, "B");
    serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap()
}

fn preflight(state: &DeviceState, request: Value) -> Result<(), crate::lab::LabError> {
    use openmls_traits::OpenMlsProvider;
    let operation: Operation = serde_json::from_value(request).unwrap();
    let before = serde_json::to_vec(state).unwrap();
    assert!(state.provider.storage().values.read().unwrap().is_empty());
    let result = wire_receive::preflight(state, &operation);
    assert_eq!(serde_json::to_vec(state).unwrap(), before);
    assert!(state.provider.storage().values.read().unwrap().is_empty());
    result
}

#[test]
fn metadata_history_rejection_preserves_retained_messages_and_expired_exact_duplicates() {
    let (f, key) = setup_devices(&["A", "B", "C", "D", "E"]);
    let sent = f.send("A", "kept");
    let kept = sent["envelope"].clone();
    let kept_request = receive(&kept, "K1", &acceptance(&key, &kept, "K1"));
    f.call(
        "A",
        crate::lab::wire_send_order_test_support::accept(&sent, &key, "K1"),
    );
    let unseen = f.send("A", "unseen")["envelope"].clone();
    let unseen_request = receive(&unseen, "K2", &acceptance(&key, &unseen, "K2"));
    remove(&f, &key, "removeC", "C");
    preflight(&metadata(&f), kept_request.clone()).unwrap();
    assert_eq!(f.call("B", kept_request.clone())["historical"], true);
    remove(&f, &key, "removeD", "D");
    remove(&f, &key, "removeE", "E");
    let metadata = metadata(&f);
    for _ in 0..2 {
        assert_eq!(
            preflight(&metadata, unseen_request.clone())
                .unwrap_err()
                .code,
            "history_unavailable"
        );
        preflight(&metadata, kept_request.clone()).unwrap();
    }
    // 已有成功记录仍须验证收到的接受证据，不允许去重绕过验签或改绑 ID。
    let forged = acceptance(&SigningKey::from_bytes(&[21; 32]), &kept, "K1");
    assert_eq!(
        preflight(&metadata, receive(&kept, "K1", &forged))
            .unwrap_err()
            .code,
        "acceptance_signature"
    );
    assert_eq!(
        preflight(
            &metadata,
            receive(&kept, "K3", &acceptance(&key, &kept, "K3"))
        )
        .unwrap_err()
        .code,
        "acceptance_conflict"
    );
    assert_eq!(f.call("B", kept_request)["duplicate"], true);
}

#[test]
fn future_epoch_remains_waiting_until_actual_permission_dependency_is_installed() {
    let (f, key) = setup();
    let proof = prepare(&f, "A", "future");
    let record = accepted(&key, &proof);
    recover(&f, "A", &record);
    let future = f.send("A", "future_message")["envelope"].clone();
    let receipt = acceptance(&key, &future, "K1");
    preflight(&metadata(&f), receive(&future, "K1", &receipt)).unwrap();
    let page = crate::lab::stream_source_test_support::page(
        vec![event(&future, "K1", Some(&receipt))],
        1,
        1,
    );
    f.call(
        "B",
        crate::lab::stream_source_test_support::signed(&key, &page, 0, 100),
    );
    let waiting = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(
        waiting["results"][0]["result"],
        json!({"status":"waiting_dependency","code":"missing_crypto_state"})
    );
    assert_eq!(waiting["sync"]["processed_cursor"], "0");
    assert_eq!(waiting["deliveries"], json!([]));
    recover(&f, "B", &record);
    let processed = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(processed["results"][0]["result"]["status"], "valid");
    assert_eq!(processed["sync"]["processed_cursor"], "1");
    assert_eq!(processed["deliveries"].as_array().unwrap().len(), 1);
}

#[test]
fn metadata_preflight_does_not_replace_private_ciphertext_authentication() {
    let (f, key) = setup();
    let old = f.send("A", "past")["envelope"].clone();
    remove(&f, &key, "removeC", "C");
    let mut bad = old.clone();
    let mut raw = codec::decode(old["payload_bytes"].as_str().unwrap()).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    bad["payload_bytes"] = json!(codec::encode(&raw));
    let request = receive(&bad, "K1", &acceptance(&key, &bad, "K1"));
    preflight(&metadata(&f), request.clone()).unwrap();
    fail_atomic(&f, "B", request, "decryption_failed");
    assert_eq!(
        f.call("B", receive(&old, "K1", &acceptance(&key, &old, "K1")))["historical"],
        true
    );
}
