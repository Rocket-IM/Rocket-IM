//! 合成近满元数据只用于触达原硬界；候选、许可、保存与重载走原实现，不宣称自然累计容量。
use super::*;
use lab::wire_reclaim_types::{Plan, Prepared, State, BYTE_LIMIT, PLAN_LIMIT};

#[test]
fn exactly_1024_combined_plans_convert_prepared_to_applied_without_double_counting() {
    let (f, key, sent, _) = fixture(false, "deleted");
    let receipt = permit(&f, &key, "A", &sent, "R1", "deleted");
    let original = prepare(&f, "A", "R1", &["K1"]);
    // 原始候选R1真实；其余1023条仅注入合法、互不相交的固定准备元数据占额。
    // loader不重新要求这些合成选择有可回收原件；这不代表1023次自然prepare成功。
    alter_invalid(&f, "A", |state| {
        let ledger = state.wire_reclamation.as_mut().unwrap();
        for index in 0..PLAN_LIMIT - 1 {
            let id = format!("F{index:04}");
            let mut request = original["request"].clone();
            request["plan_id"] = json!(id);
            request["acceptance_ids"] = json!([format!("S{index:04}")]);
            ledger.prepared.insert(
                id,
                Prepared {
                    request_json: serde_json::to_string(&request).unwrap(),
                },
            );
        }
    });
    let ledger = load(&f, "A").wire_reclamation.unwrap();
    assert_eq!(ledger.prepared.len(), PLAN_LIMIT);
    assert!(ledger.plans.is_empty());
    assert!(ledger.budget().unwrap() < BYTE_LIMIT);
    let next = f.send("A", "M2");
    f.call("A", accept(&next, &key, "K2"));
    let overflow =
        json!({"operation":"wire_reclaim_request","plan_id":"R2","acceptance_ids":["K2"]});
    reject(&f, "A", overflow.clone(), "resource_exhausted");
    let applied = f.call("A", json!({"operation":"wire_reclaim","receipt":receipt}));
    let ledger = load(&f, "A").wire_reclamation.unwrap();
    assert_eq!(ledger.prepared.len(), PLAN_LIMIT - 1);
    assert_eq!(ledger.plans.len(), 1);
    assert_eq!(ledger.summary().unwrap()["plan_count"], PLAN_LIMIT);
    assert_eq!(
        ledger.plans["R1"].request_json.as_deref(),
        original["request_json"].as_str()
    );
    reject(&f, "A", overflow, "resource_exhausted");
    let saved = bytes(&f, "A");
    assert_eq!(recover(&f, "A", "R1")["result"], applied);
    assert_eq!(prepare(&f, "A", "R1", &["K1"])["duplicate"], true);
    assert_eq!(
        f.call("A", json!({"operation":"wire_reclaim","receipt":receipt}))["duplicate"],
        true
    );
    assert_eq!(bytes(&f, "A"), saved);
}

#[test]
fn first_preparation_at_8mib_proof_budget_rejects_without_mutating_candidate() {
    let (f, key, sent, _) = fixture(false, "deleted");
    let receipt = serde_json::from_value(permit(&f, &key, "A", &sent, "R1", "deleted")).unwrap();
    let mut state = load(&f, "A");
    let mut ledger = State::default();
    // 仅内存中的合成计费填充，不是可加载的成功回收证明；真实prepare必须先预算拒绝。
    ledger.plans.insert(
        "filler".into(),
        Plan {
            receipt,
            result: json!("x".repeat(BYTE_LIMIT)),
            request_json: None,
        },
    );
    let excess = serde_json::to_vec(&ledger).unwrap().len() - BYTE_LIMIT;
    ledger.plans.get_mut("filler").unwrap().result = json!("x".repeat(BYTE_LIMIT - excess));
    assert_eq!(ledger.budget().unwrap(), BYTE_LIMIT);
    state.wire_reclamation = Some(ledger);
    let before = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        lab::wire_reclaim::request(&mut state, "R1".into(), vec!["K1".into()])
            .unwrap_err()
            .code,
        "resource_exhausted"
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    assert_eq!(state.wire.outbox.len(), 1);
    assert!(state.wire_reclamation.as_ref().unwrap().prepared.is_empty());
}

#[test]
fn first_preparation_cannot_borrow_future_reclaimed_bytes_from_full_16mib_snapshot() {
    let (f, _, _, _) = fixture(false, "deleted");
    // 合成独立控制记录填充设备完整快照；计费包含provider、原载荷、所有设备字段。
    // 不提高阈值、不先清正文，也不把占额记成自然业务容量。
    alter_invalid(&f, "A", |state| {
        state.control_outbox.insert(
            "synthetic_padding".into(),
            lab::state::ControlRecord {
                request_digest: [0; 32],
                result: json!(""),
            },
        );
        state.capture_provider().unwrap();
        let base = serde_json::to_vec(state).unwrap().len();
        let padding = crate::snapshot::MAX_PLAINTEXT_BYTES - base;
        state
            .control_outbox
            .get_mut("synthetic_padding")
            .unwrap()
            .result = json!("x".repeat(padding));
        assert_eq!(
            serde_json::to_vec(state).unwrap().len(),
            crate::snapshot::MAX_PLAINTEXT_BYTES
        );
    });
    let state = load(&f, "A");
    assert_eq!(
        serde_json::to_vec(&state).unwrap().len(),
        crate::snapshot::MAX_PLAINTEXT_BYTES
    );
    assert!(state.wire_reclamation.is_none());
    assert_eq!(state.wire.outbox.len(), 1);
    reject(
        &f,
        "A",
        json!({"operation":"wire_reclaim_request","plan_id":"R1","acceptance_ids":["K1"]}),
        "resource_exhausted",
    );
    let reopened = load(&f, "A");
    assert!(reopened.wire_reclamation.is_none());
    assert_eq!(reopened.wire.outbox.len(), 1);
    assert_eq!(
        serde_json::to_vec(&reopened).unwrap(),
        serde_json::to_vec(&state).unwrap()
    );
}
