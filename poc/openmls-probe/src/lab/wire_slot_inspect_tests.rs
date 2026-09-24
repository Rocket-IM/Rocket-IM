//! 每次 execute 都重新加载加密快照；有界观察必须反映已保存槽，而非下载输入缓存。

use super::{codec, wire_tests::Fixture};
use serde_json::{json, Value};
use std::fs;

fn event(seq: u64, envelope: &Value) -> Value {
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),
        "availability":"available","event":{"type":"message","acceptance_id":"K1","envelope":envelope}})
}

fn inspect(f: &Fixture, seq: &str) -> Value {
    let before = fs::read(f.root.join("B/state.enc")).unwrap();
    let result = f.call(
        "B",
        json!({"operation":"wire_slot_inspect","event_seq":seq}),
    );
    assert_eq!(before, fs::read(f.root.join("B/state.enc")).unwrap());
    result
}

#[test]
fn slot_inspect_reloads_exact_persisted_record_without_exposing_secrets() {
    let f = Fixture::new();
    let sent = f.send("A", "M1");
    let original = event(1, &sent["envelope"]);
    f.download(vec![original.clone()], 1);
    let pending = inspect(&f, "1");
    assert_eq!(
        pending,
        json!({"event_seq":"1","found":true,"slot":original,
        "result":null,"waiting":false})
    );
    let processed = f.call("B", json!({"operation":"wire_process"}));
    let saved = inspect(&f, "1");
    assert_eq!(
        saved,
        json!({"event_seq":"1","found":true,"slot":original,
        "result":processed["results"][0]["result"],"waiting":false})
    );
    assert_eq!(saved["result"]["message"]["duplicate"], false);
    assert!(saved["result"]["message"]["payload_sha256"].is_string());
    let output = saved.to_string();
    assert!(!output.contains("synthetic test content"));
    let snapshot_key = fs::read(f.root.join("B/device.key")).unwrap();
    assert!(!output.contains(&codec::encode(&snapshot_key)));
    for field in ["provider", "signature_id", "inbox", "outbox", "payload"] {
        assert!(!output.contains(&format!("\"{field}\":")));
    }
    // 再次执行读取仍只来自磁盘，且只含五个约定字段。
    assert_eq!(inspect(&f, "1"), saved);
    assert_eq!(saved.as_object().unwrap().len(), 5);
}

#[test]
fn slot_inspect_missing_and_other_device_are_explicit() {
    let f = Fixture::new();
    let sent = f.send("A", "M1");
    f.download(vec![event(1, &sent["envelope"])], 1);
    for seq in ["2", "9007199254740993", "18446744073709551615"] {
        assert_eq!(
            inspect(&f, seq),
            json!({"event_seq":seq,"found":false,
            "slot":null,"result":null,"waiting":false})
        );
    }
    let before = fs::read(f.root.join("A/state.enc")).unwrap();
    assert_eq!(
        f.call(
            "A",
            json!({"operation":"wire_slot_inspect","event_seq":"1"})
        ),
        json!({"event_seq":"1","found":false,"slot":null,"result":null,"waiting":false})
    );
    assert_eq!(before, fs::read(f.root.join("A/state.enc")).unwrap());
}

#[test]
fn slot_inspect_rejects_noncanonical_or_out_of_range_sequences_without_save() {
    let f = Fixture::new();
    let before = fs::read(f.root.join("B/state.enc")).unwrap();
    for seq in [
        "",
        "01",
        "-1",
        "+1",
        "1.0",
        " 1",
        "1 ",
        "一",
        "18446744073709551616",
    ] {
        f.fails(
            "B",
            json!({"operation":"wire_slot_inspect","event_seq":seq}),
            "invalid_envelope",
        );
    }
    f.fails(
        "B",
        json!({"operation":"wire_slot_inspect","event_seq":"0"}),
        "cursor_invalid",
    );
    for value in [Value::Null, json!(1), json!(["1"])] {
        f.fails(
            "B",
            json!({"operation":"wire_slot_inspect","event_seq":value}),
            "invalid_request",
        );
    }
    f.fails(
        "B",
        json!({"operation":"wire_slot_inspect"}),
        "invalid_request",
    );
    f.fails(
        "B",
        json!({"operation":"wire_slot_inspect","event_seq":"1","events":[]}),
        "invalid_request",
    );
    assert_eq!(before, fs::read(f.root.join("B/state.enc")).unwrap());
}

#[test]
fn slot_conflict_preserves_original_record_and_remains_observable_after_halt() {
    for mutate_id in [true, false] {
        let f = Fixture::new();
        let sent = f.send("A", "M1");
        let original = event(1, &sent["envelope"]);
        f.download(vec![original.clone()], 1);
        f.call("B", json!({"operation":"wire_process"}));
        let saved = inspect(&f, "1");
        let before = f.call("B", json!({"operation":"wire_inspect"}));
        let mut changed = original;
        if mutate_id {
            changed["event_id"] = json!("different_event");
        } else {
            changed["event"]["envelope"]["payload_bytes"] = json!(codec::encode(b"changed"));
        }
        assert_eq!(f.download(vec![changed], 1)["status"], "stream_conflict");
        assert_eq!(inspect(&f, "1"), saved);
        let after = f.call("B", json!({"operation":"wire_inspect"}));
        assert_eq!(after["sync"]["halted"], true);
        for field in ["download_cursor", "processed_cursor", "slot_count"] {
            assert_eq!(after["sync"][field], before["sync"][field]);
        }
        assert_eq!(after["inbox_count"], before["inbox_count"]);
        f.fails("B", json!({"operation":"wire_process"}), "stream_conflict");
        assert_eq!(inspect(&f, "1"), saved);
    }
}

#[test]
fn same_message_in_two_slots_keeps_both_progress_and_one_business_record() {
    let f = Fixture::new();
    let sent = f.send("A", "M1");
    let slots = [event(1, &sent["envelope"]), event(2, &sent["envelope"])];
    f.download(slots.to_vec(), 2);
    let processed = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(processed["sync"]["processed_cursor"], "2");
    let records = [inspect(&f, "1"), inspect(&f, "2")];
    for (index, saved) in records.iter().enumerate() {
        assert_eq!(saved["slot"], slots[index]);
        assert_eq!(saved["result"], processed["results"][index]["result"]);
        assert_eq!(saved["result"]["message"]["duplicate"], index == 1);
        assert_eq!(saved["waiting"], false);
    }
    let status = f.call("B", json!({"operation":"wire_inspect"}));
    assert_eq!(status["inbox_count"], 1);
    assert_eq!(status["sync"]["slot_count"], 2);
    assert_eq!(status["sync"]["download_cursor"], "2");
    let replay = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(replay["results"], json!([]));
    assert_eq!(inspect(&f, "1"), records[0]);
    assert_eq!(inspect(&f, "2"), records[1]);
}

#[test]
fn slot_inspect_reports_persisted_waiting_summary() {
    let f = Fixture::new();
    f.call(
        "A",
        json!({"operation":"remove","id":"removeC","member":"C"}),
    );
    f.call(
        "A",
        json!({"operation":"wire_configure","conversation_id":"G1","authorization_version":"2"}),
    );
    let sent = f.send("A", "M1");
    let original = event(1, &sent["envelope"]);
    f.download(vec![original.clone()], 1);
    let processed = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(processed["sync"]["processed_cursor"], "0");
    assert_eq!(
        inspect(&f, "1"),
        json!({"event_seq":"1","found":true,"slot":original,
        "result":{"status":"waiting_dependency","code":"missing_crypto_state"},"waiting":true})
    );
}
