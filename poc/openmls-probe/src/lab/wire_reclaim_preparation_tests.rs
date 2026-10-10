//! 持久准备使用真实MLS、签页和加密快照；固定测试钥签许可，不代表Relay确认。
#[path = "wire_reclaim_preparation_boundary_tests.rs"]
mod boundaries;
#[path = "wire_reclaim_preparation_quota_tests.rs"]
mod quotas;
#[path = "wire_reclaim_refresh_tests.rs"]
mod refresh;
#[path = "wire_terminal_reference_tests.rs"]
mod terminal_reference;

use super::*;
use crate::lab::{self, wire_send_order_test_support::alter_invalid};

fn prepare(f: &Fixture, device: &str, plan: &str, ids: &[&str]) -> Value {
    f.call(
        device,
        json!({"operation":"wire_reclaim_request","plan_id":plan,"acceptance_ids":ids}),
    )
}

fn recover(f: &Fixture, device: &str, plan: &str) -> Value {
    f.call(
        device,
        json!({"operation":"wire_reclaim_recover","plan_id":plan}),
    )
}

fn list(f: &Fixture, device: &str, after: Option<&str>, limit: &str) -> Value {
    let mut operation = json!({"operation":"wire_reclaim_list","limit":limit});
    if let Some(after) = after {
        operation["after_plan_id"] = json!(after);
    }
    f.call(device, operation)
}

fn bytes(f: &Fixture, device: &str) -> Vec<u8> {
    fs::read(f.root.join(device).join("state.enc")).unwrap()
}

#[test]
fn prepared_only_reopens_with_original_request_bytes_and_processed_prefix() {
    let (f, key, sent, payload) = fixture(false, "deleted");
    let receipt = permit(&f, &key, "B", &sent, "R1", "deleted");
    let original = prepare(&f, "B", "R1", &["K1"]);
    let expected = r#"{"acceptance_ids":["K1"],"conversation_id":"G1","plan_id":"R1","processed_seq":"3","service_id":"S1","stream_id":"B_stream"}"#;
    assert_eq!(original["status"], "prepared");
    assert_eq!(original["duplicate"], false);
    assert_eq!(original["request_json"], expected);
    assert_eq!(
        serde_json::from_str::<Value>(expected).unwrap(),
        original["request"]
    );
    let state = load(&f, "B");
    let ledger = state.wire_reclamation.as_ref().unwrap();
    assert_eq!(ledger.version, 2);
    assert_eq!(ledger.prepared.len(), 1);
    assert!(ledger.messages.is_empty() && ledger.slots.is_empty() && ledger.plans.is_empty());
    assert_eq!(ledger.prepared["R1"].request_json, expected);
    assert!(state
        .wire
        .inbox
        .values()
        .any(|message| message.payload.as_deref() == Some(payload.as_str())));
    let saved = bytes(&f, "B");
    let recovery = recover(&f, "B", "R1");
    assert_eq!(recovery["request_json"], expected);
    assert!(recovery.get("duplicate").is_none());
    assert_eq!(bytes(&f, "B"), saved);

    // 无关消息的真签页推进P不能证明原confirm无效，也不把恢复当重新准备。
    download(
        &f,
        &key,
        "B",
        vec![event(
            "B",
            4,
            json!({"type":"delivery","acceptance_id":"unrelated",
        "attempt_id":"P1","device":{"account_id":"B","device_id":"B"}}),
        )],
        3,
        4,
    );
    assert_eq!(load(&f, "B").wire_sync.processed_cursor, 4);
    let saved = bytes(&f, "B");
    let duplicate = prepare(&f, "B", "R1", &["K1"]);
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(duplicate["request_json"], expected);
    assert_eq!(recover(&f, "B", "R1")["request_json"], expected);
    assert_eq!(bytes(&f, "B"), saved);

    let applied = f.call("B", json!({"operation":"wire_reclaim","receipt":receipt}));
    let ledger = load(&f, "B").wire_reclamation.unwrap();
    assert!(ledger.prepared.is_empty());
    assert_eq!(ledger.plans["R1"].request_json.as_deref(), Some(expected));
    let recovery = recover(&f, "B", "R1");
    assert_eq!(recovery["status"], "applied");
    assert_eq!(recovery["finish_request"], applied["finish_request"]);
    assert_eq!(recovery["result"], applied);
    let saved = bytes(&f, "B");
    assert_eq!(prepare(&f, "B", "R1", &["K1"])["request_json"], expected);
    assert_eq!(
        f.call("B", json!({"operation":"wire_reclaim","receipt":receipt}))["duplicate"],
        true
    );
    assert_eq!(bytes(&f, "B"), saved);
}

#[test]
fn list_pages_mix_real_prepared_and_applied_plans_without_modifying_snapshot() {
    let (f, key, sent, _) = fixture(false, "deleted");
    assert_eq!(
        list(&f, "A", None, "100"),
        json!({"plans":[],"has_more":false,"next_after_plan_id":null})
    );
    prepare(&f, "A", "R10", &["K1"]);
    f.call(
        "A",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"A",&sent,"R10","deleted")}),
    );
    for (message, acceptance, plan) in [("M2", "K2", "R20"), ("M3", "K3", "R03")] {
        let sent = f.send("A", message);
        f.call("A", accept(&sent, &key, acceptance));
        prepare(&f, "A", plan, &[acceptance]);
    }
    let saved = bytes(&f, "A");
    assert_eq!(
        list(&f, "A", None, "1"),
        json!({"plans":[{"plan_id":"R03","status":"prepared"}],"has_more":true,"next_after_plan_id":"R03"})
    );
    assert_eq!(
        list(&f, "A", Some("R03"), "1"),
        json!({"plans":[{"plan_id":"R10","status":"applied"}],"has_more":true,"next_after_plan_id":"R10"})
    );
    assert_eq!(
        list(&f, "A", Some("R10"), "1"),
        json!({"plans":[{"plan_id":"R20","status":"prepared"}],"has_more":false,"next_after_plan_id":null})
    );
    assert_eq!(
        list(&f, "A", Some("R04"), "100")["plans"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(list(&f, "A", Some("Z"), "100")["plans"], json!([]));
    reject(
        &f,
        "A",
        json!({"operation":"wire_reclaim_recover","plan_id":"missing"}),
        "reclaim_not_found",
    );
    assert_eq!(bytes(&f, "A"), saved);
}

#[test]
fn saved_preparation_rejects_changed_selection_overlapping_plan_and_changed_permit_prefix() {
    let (f, key, sent, _) = fixture(false, "deleted");
    let original = permit(&f, &key, "B", &sent, "R1", "deleted");
    prepare(&f, "B", "R1", &["K1"]);
    for operation in [
        json!({"operation":"wire_reclaim_request","plan_id":"R1","acceptance_ids":["K2"]}),
        json!({"operation":"wire_reclaim_request","plan_id":"R2","acceptance_ids":["K1"]}),
        json!({"operation":"wire_reclaim","receipt":re_sign(&key,&original,|s|s["plan_id"]=json!("R2"))}),
        json!({"operation":"wire_reclaim","receipt":re_sign(&key,&original,|s|s["processed_seq"]=json!("2"))}),
    ] {
        reject(&f, "B", operation, "reclaim_conflict");
    }
    assert_eq!(load(&f, "B").wire.inbox.len(), 1);
    f.call("B", json!({"operation":"wire_reclaim","receipt":original}));
}

#[test]
fn legacy_trusted_permit_and_exact_v1_encoding_survive_readonly_recovery_then_upgrade_once() {
    let (f, key, sent, _) = fixture(false, "deleted");
    // 没有prepare的旧可信许可仍沿真实执行入口应用。
    let applied = f.call(
        "A",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"A",&sent,"OLD","deleted")}),
    );
    let state = load(&f, "A");
    let ledger = state.wire_reclamation.as_ref().unwrap();
    assert_eq!(ledger.version, 1);
    assert!(ledger.plans["OLD"].request_json.is_none());
    let encoded = serde_json::to_vec(ledger).unwrap();
    // 独立固定旧State四字段、旧Plan两字段的原序，不能由新State编码器生成期望。
    let expected = format!(
        "{{\"version\":1,\"messages\":{},\"slots\":{},\"plans\":{{\"OLD\":{{\"receipt\":{},\"result\":{}}}}}}}",
        serde_json::to_string(&ledger.messages).unwrap(),
        serde_json::to_string(&ledger.slots).unwrap(),
        serde_json::to_string(&ledger.plans["OLD"].receipt).unwrap(),
        serde_json::to_string(&ledger.plans["OLD"].result).unwrap(),
    );
    assert_eq!(encoded, expected.as_bytes());
    let legacy_shape = json!({"version":1,"messages":ledger.messages,"slots":ledger.slots,"plans":{
        "OLD":{"receipt":ledger.plans["OLD"].receipt,"result":ledger.plans["OLD"].result}}});
    let decoded: lab::wire_reclaim_types::State = serde_json::from_value(legacy_shape).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
    let saved = bytes(&f, "A");
    assert_eq!(recover(&f, "A", "OLD")["result"], applied);
    assert_eq!(
        list(&f, "A", None, "100")["plans"],
        json!([{"plan_id":"OLD","status":"applied"}])
    );
    let retry = prepare(&f, "A", "OLD", &["K1"]);
    assert_eq!(retry["status"], "applied");
    assert!(retry.get("request_json").is_none());
    assert_eq!(retry["request"]["processed_seq"], "0");
    assert_eq!(bytes(&f, "A"), saved);
    assert_eq!(
        serde_json::to_vec(load(&f, "A").wire_reclamation.as_ref().unwrap()).unwrap(),
        encoded
    );

    let next = f.send("A", "M2");
    f.call("A", accept(&next, &key, "K2"));
    prepare(&f, "A", "NEW", &["K2"]);
    let upgraded = load(&f, "A").wire_reclamation.unwrap();
    assert_eq!(upgraded.version, 2);
    assert_eq!(upgraded.plans["OLD"].result, applied);
    assert!(upgraded.plans["OLD"].request_json.is_none());
    assert_eq!(
        recover(&f, "A", "OLD")["finish_request"],
        applied["finish_request"]
    );
}
