//! 仅合成接近阈值的记录数量；填充项不代表真实消息、已验证控制或自然累计负载。
use super::*;
use crate::lab::{state::DeviceState, wire_sync_types::StoredSlot, wire_types};

pub(super) fn seed(f: &Fixture, device: &str, change: impl FnOnce(&mut DeviceState)) {
    let locked = crate::lab::store::LockedDevice::open(&f.root.join(device)).unwrap();
    let context = crate::lab::Context {
        service: "S1".into(),
        account: device.into(),
        device: device.into(),
    };
    let mut state = locked.load(&context).unwrap().unwrap();
    change(&mut state);
    locked
        .save(&mut state, crate::lab::CrashPoint::None)
        .unwrap();
}

pub(super) fn state_bytes(f: &Fixture, device: &str) -> Vec<u8> {
    serde_json::to_vec(&load(f, device)).unwrap()
}

pub(super) fn fill_outbox(f: &Fixture, sent: &Value, count: usize) {
    seed(f, "A", |state| {
        let envelope: wire_types::Envelope =
            serde_json::from_value(sent["envelope"].clone()).unwrap();
        while state.wire.outbox.len() < count {
            let id = format!("synthetic_filler_{}", state.wire.outbox.len());
            state.wire.outbox.insert(
                id.clone(),
                wire_types::Outbound {
                    logical_key: id,
                    attempt_id: "P1".into(),
                    payload: String::new(),
                    envelope: envelope.clone(),
                    replaces_attempt_id: None,
                    closure_id: None,
                    acceptance_receipt: None,
                },
            );
        }
    });
}

pub(super) fn fill_inbox(f: &Fixture, sent: &Value, count: usize) {
    seed(f, "B", |state| {
        let envelope: wire_types::Envelope =
            serde_json::from_value(sent["envelope"].clone()).unwrap();
        while state.wire.inbox.len() < count {
            let id = format!("synthetic_filler_{}", state.wire.inbox.len());
            state.wire.inbox.insert(
                id.clone(),
                wire_types::Inbound {
                    logical_key: id,
                    attempt_id: "P1".into(),
                    envelope: envelope.clone(),
                    payload_digest: [0; 32],
                    acceptance_id: None,
                    payload: None,
                    acceptance_receipt: None,
                },
            );
        }
    });
}

pub(super) fn message(sent: &Value, key: &SigningKey, seq: u64) -> Value {
    let acceptance = format!("K{seq}");
    let proof = crate::lab::wire_send_order_test_support::accept(sent, key, &acceptance);
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),
        "availability":"available","event":{"type":"message","acceptance_id":acceptance,
        "envelope":sent["envelope"],"acceptance_receipt":proof["acceptance_receipt"]}})
}

pub(super) fn download(f: &Fixture, key: &SigningKey, events: Vec<Value>, after: u64, next: u64) {
    f.call("B", signed(key, &page(events, next, next), after, 100));
}

pub(super) fn fill_slots(f: &Fixture, key: &SigningKey, count: u64, processed: bool) {
    // 先经真实空签页固定源，再只在测试内填充不可用槽；不伪造成功消息或服务确认。
    download(f, key, vec![], 0, 0);
    seed(f, "B", |state| {
        for seq in 1..=count {
            let slot = serde_json::from_value(json!({"stream_id":"B_stream",
                "event_seq":seq.to_string(),"event_id":format!("E{seq}"),"availability":"deleted"}))
            .unwrap();
            state.wire_sync.slots.insert(
                seq,
                StoredSlot {
                    slot,
                    result: processed
                        .then(|| json!({"status":"unavailable","availability":"deleted"})),
                    waiting: false,
                },
            );
        }
        state.wire_sync.download_cursor = count;
        state.wire_sync.processed_cursor = if processed { count } else { 0 };
    });
}

pub(super) fn control(f: &Fixture, member: &str, id: &str) -> Value {
    let from = f.call("A", json!({"operation":"wire_inspect"}))["crypto_state_ref"].clone();
    let removed = f.call("A", json!({"operation":"remove","id":id,"member":member}));
    let to = f.call("A", json!({"operation":"wire_inspect"}))["crypto_state_ref"].clone();
    json!({"control_id":id,"from_state_ref":from,"to_state_ref":to,"payload_bytes":removed["commit"]})
}

pub(super) fn dependency(control: &Value) -> Value {
    json!({"operation":"wire_apply_dependency","control":control})
}
