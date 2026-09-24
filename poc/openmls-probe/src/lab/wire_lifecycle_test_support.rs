//! 合成 Service 签名、真实 MLS 原包与持久快照观察；不构造产品删除 API。

use super::*;
use crate::lab::wire_send_order_test_support::accept;

pub(super) fn message(f: &Fixture, key: &SigningKey, seq: u64) -> Value {
    let sent = f.send("A", &format!("M{seq}"));
    let receipt = accept(&sent, key, &format!("K{seq}"));
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),
        "availability":"available","event":{"type":"message","acceptance_id":format!("K{seq}"),
        "envelope":sent["envelope"],"acceptance_receipt":receipt["acceptance_receipt"]}})
}

pub(super) fn notice(seq: u64, target: u64, availability: &str) -> Value {
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),
        "availability":"available","event":{"type":"message_availability",
        "target_event_seq":target.to_string(),"target_event_id":format!("E{target}"),
        "acceptance_id":format!("K{target}"),"attempt_id":"P1","availability":availability}})
}

pub(super) fn tombstone(seq: u64, availability: &str) -> Value {
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),
        "availability":availability})
}

pub(super) fn request(key: &SigningKey, events: Vec<Value>, after: u64, next: u64) -> Value {
    signed(key, &page(events, next, next), after, 100)
}

pub(super) fn download(
    f: &Fixture,
    key: &SigningKey,
    events: Vec<Value>,
    after: u64,
    next: u64,
) -> Value {
    f.call("B", request(key, events, after, next))
}

pub(super) fn process(f: &Fixture) -> Value {
    f.call("B", json!({"operation":"wire_process"}))
}

pub(super) fn slot(f: &Fixture, seq: u64) -> Value {
    f.call(
        "B",
        json!({"operation":"wire_slot_inspect","event_seq":seq.to_string()}),
    )
}

pub(super) fn business(f: &Fixture) -> Value {
    let state = load(f, "B");
    json!({"provider":state.provider_entries,"wire":state.wire,"reads":state.wire_reads})
}

pub(super) fn state_bytes(f: &Fixture) -> Vec<u8> {
    serde_json::to_vec(&load(f, "B")).unwrap()
}

pub(super) fn no_plaintext(f: &Fixture, output: &Value, availability: &str) {
    assert_eq!(
        output["results"][0]["result"],
        json!({"status":"unavailable","availability":availability})
    );
    assert_eq!(
        output["results"][1]["result"]["status"],
        "availability_recorded"
    );
    assert_eq!(output["deliveries"], json!([]));
    assert_eq!(output["sync"]["processed_cursor"], "2");
    assert_eq!(output["sync"]["pending_count"], 0);
    assert_eq!(
        f.call("B", json!({"operation":"wire_inspect"}))["inbox_count"],
        0
    );
    assert_eq!(
        f.call("B", json!({"operation":"wire_read_pending"}))["pending_count"],
        0
    );
}
