//! 缓存填充只触发真实限额分支；被测末条控制来自原 OpenMLS 成员变更。
use super::*;

#[test]
fn quota_control_outbox_full_rejects_new_commit_but_returns_existing_cache() {
    let f = Fixture::new();
    seed(&f, "A", |state| {
        while state.control_outbox.len() < MAX_RECORDS - 1 {
            state.control_outbox.insert(
                format!("synthetic_filler_{}", state.control_outbox.len()),
                crate::lab::state::ControlRecord {
                    request_digest: [0; 32],
                    result: json!(null),
                },
            );
        }
    });
    let operation = json!({"operation":"remove","id":"last","member":"C"});
    let result = f.call("A", operation.clone());
    assert_eq!(load(&f, "A").control_outbox.len(), MAX_RECORDS);
    let saved = state_bytes(&f, "A");
    // 新控制的容量检查在 MLS 动作之后；外层失败必须丢弃候选 provider 与成员变化。
    reject(
        &f,
        "A",
        json!({"operation":"remove","id":"overflow","member":"B"}),
        "resource_limit",
    );
    assert!(state_bytes(&f, "A") == saved);
    let snapshot = std::fs::read(f.root.join("A/state.enc")).unwrap();
    assert!(f.call("A", operation) == result);
    assert!(std::fs::read(f.root.join("A/state.enc")).unwrap() == snapshot);
    assert!(state_bytes(&f, "A") == saved);
}

#[test]
fn quota_dependency_count_accepts_last_control_and_full_duplicate_without_reapply() {
    let f = Fixture::new();
    let last = control(&f, "C", "last");
    seed(&f, "B", |state| {
        for index in 0..MAX_RECORDS - 1 {
            let mut filler: crate::lab::wire_sync::Control =
                serde_json::from_value(last.clone()).unwrap();
            filler.control_id = format!("synthetic_filler_{index}");
            filler.payload_bytes = "AA==".into();
            state
                .wire_sync
                .applied_controls
                .insert(filler.control_id.clone(), filler);
        }
    });
    assert_eq!(f.call("B", dependency(&last))["duplicate"], false);
    assert_eq!(load(&f, "B").wire_sync.applied_controls.len(), MAX_RECORDS);
    let saved = state_bytes(&f, "B");
    assert_eq!(f.call("B", dependency(&last))["duplicate"], true);
    assert!(state_bytes(&f, "B") == saved);
    let overflow = control(&f, "B", "overflow");
    reject(&f, "B", dependency(&overflow), "resource_exhausted");
    assert!(state_bytes(&f, "B") == saved);
}

#[test]
fn quota_dependency_base64_bytes_at_four_mib_and_one_control_beyond() {
    let f = Fixture::new();
    let last = control(&f, "C", "last");
    let remaining = 4 * 1024 * 1024 - last["payload_bytes"].as_str().unwrap().len();
    let chunk_bytes = 64 * 1024;
    let filler_count = remaining.div_ceil(chunk_bytes);
    seed(&f, "B", |state| {
        // 每条 Base64 不超过 64 KiB；仍只是合成计数填充，不是合法控制历史。
        for index in 0..filler_count {
            let mut filler: crate::lab::wire_sync::Control =
                serde_json::from_value(last.clone()).unwrap();
            filler.control_id = format!("synthetic_byte_filler_{index}");
            let length = (remaining - index * chunk_bytes).min(chunk_bytes);
            assert_eq!(length % 4, 0);
            filler.payload_bytes = "A".repeat(length);
            state
                .wire_sync
                .applied_controls
                .insert(filler.control_id.clone(), filler);
        }
    });
    assert_eq!(f.call("B", dependency(&last))["duplicate"], false);
    let state = load(&f, "B");
    assert_eq!(state.wire_sync.applied_controls.len(), filler_count + 1);
    assert!(state
        .wire_sync
        .applied_controls
        .values()
        .filter(|c| c.control_id.starts_with("synthetic_byte_filler_"))
        .all(|c| c.payload_bytes.len() <= chunk_bytes));
    assert_eq!(
        state
            .wire_sync
            .applied_controls
            .values()
            .map(|c| c.payload_bytes.len())
            .sum::<usize>(),
        4 * 1024 * 1024
    );
    let saved = state_bytes(&f, "B");
    assert_eq!(f.call("B", dependency(&last))["duplicate"], true);
    assert!(state_bytes(&f, "B") == saved);
    let overflow = control(&f, "B", "overflow");
    reject(&f, "B", dependency(&overflow), "resource_exhausted");
    assert!(state_bytes(&f, "B") == saved);
}
