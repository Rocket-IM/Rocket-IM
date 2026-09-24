use super::{codec, execute, state::DeviceState, wire_types::Header, Context};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) identities: Vec<Value>,
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self::with_devices(&["A", "B", "C"])
    }

    pub(super) fn with_devices(devices: &[&str]) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rim-wire-test-{}-{stamp}-{sequence}",
                std::process::id()
            ));
        fs::create_dir(&root).unwrap();
        let mut fixture = Self {
            root,
            identities: Vec::new(),
        };
        for device in devices {
            fixture
                .identities
                .push(fixture.call(device, json!({"operation":"init"})));
        }
        let peers: Vec<_> = fixture.identities[1..].iter().map(|peer| json!({"account":peer["account"],
            "device":peer["device"],"signature_key":peer["signature_key"],"key_package":peer["key_package"]})).collect();
        let created = fixture.call("A", json!({"operation":"create","peers":peers}));
        let pins: Vec<_> = fixture
            .identities
            .iter()
            .map(|peer| {
                json!({"account":peer["account"],
            "device":peer["device"],"signature_key":peer["signature_key"]})
            })
            .collect();
        for device in &devices[1..] {
            fixture.call(
                device,
                json!({"operation":"join","welcome":created["welcome"],"pins":pins}),
            );
        }
        for device in devices {
            fixture.call(device, json!({"operation":"wire_configure","conversation_id":"G1","authorization_version":"1"}));
        }
        fixture
    }

    pub(super) fn request(&self, device: &str, mut operation: Value) -> String {
        let map = operation.as_object_mut().unwrap();
        map.insert("directory".into(), json!(self.root.join(device)));
        map.insert("service".into(), json!("S1"));
        map.insert("account".into(), json!(device));
        map.insert("device".into(), json!(device));
        operation.to_string()
    }

    pub(super) fn call(&self, device: &str, operation: Value) -> Value {
        execute(&self.request(device, operation)).unwrap()["result"].clone()
    }

    pub(super) fn fails(&self, device: &str, operation: Value, code: &str) {
        assert_eq!(
            execute(&self.request(device, operation)).unwrap_err().code,
            code
        );
    }

    pub(super) fn send(&self, device: &str, id: &str) -> Value {
        self.call(device, json!({"operation":"wire_send","logical_message_id":id,"attempt_id":"P1","payload":"synthetic test content"}))
    }

    pub(super) fn receive(&self, device: &str, envelope: &Value) -> Value {
        self.call(device, json!({"operation":"wire_receive","header_bytes":envelope["header_bytes"],"payload_bytes":envelope["payload_bytes"]}))
    }

    pub(super) fn download(&self, events: Vec<Value>, next: u64) -> Value {
        self.call(
            "B",
            json!({"operation":"wire_download","stream_id":"B_stream","events":events,
            "next_after_seq":next.to_string(),"watermark":next.to_string(),"has_more":false}),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn event(seq: u64, envelope: &Value) -> Value {
    json!({"stream_id":"B_stream","event_seq":seq.to_string(),"event_id":format!("E{seq}"),"availability":"available",
        "event":{"type":"message","acceptance_id":format!("K{seq}"),"envelope":envelope}})
}

#[test]
fn wire_public_context_matches_and_retry_survives_new_process_state() {
    let f = Fixture::new();
    let a = f.call("A", json!({"operation":"wire_inspect"}));
    let b = f.call("B", json!({"operation":"wire_inspect"}));
    assert_eq!(a["crypto_state_ref"], b["crypto_state_ref"]);
    assert_eq!(a["crypto_state_ref"].as_str().unwrap().len(), 64);
    let first = f.send("A", "M1");
    let retry = f.send("A", "M1");
    assert_eq!(first["envelope"], retry["envelope"]);
    assert_eq!(retry["reused"], true);
    assert_eq!(f.receive("B", &first["envelope"])["duplicate"], false);
    assert_eq!(f.receive("B", &first["envelope"])["duplicate"], true);
    let same_id_other_sender = f.send("C", "M1");
    f.receive("B", &same_id_other_sender["envelope"]);
    assert_eq!(
        f.call("B", json!({"operation":"wire_inspect"}))["inbox_count"],
        2
    );
}

#[test]
fn wire_rejects_raw_aad_change_without_consuming_valid_ciphertext() {
    let f = Fixture::new();
    let sent = f.send("A", "M1");
    let envelope = &sent["envelope"];
    let mut header = vec![b' '];
    header.extend(codec::decode(envelope["header_bytes"].as_str().unwrap()).unwrap());
    let before = fs::read(f.root.join("B/state.enc")).unwrap();
    f.fails(
        "B",
        json!({"operation":"wire_receive","header_bytes":codec::encode(&header),
        "payload_bytes":envelope["payload_bytes"]}),
        "identity_mismatch",
    );
    assert_eq!(before, fs::read(f.root.join("B/state.enc")).unwrap());
    assert_eq!(f.receive("B", envelope)["duplicate"], false);
}

#[test]
fn wire_quarantine_does_not_poison_logical_dedupe_or_cursor() {
    let f = Fixture::new();
    let sent = f.send("A", "M1");
    let mut bad = sent["envelope"].clone();
    let mut bytes = codec::decode(bad["payload_bytes"].as_str().unwrap()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    bad["payload_bytes"] = json!(codec::encode(&bytes));
    f.download(vec![event(1, &bad), event(2, &sent["envelope"])], 2);
    let result = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(result["sync"]["processed_cursor"], "2");
    assert_eq!(result["sync"]["quarantined_count"], 1);
    assert_eq!(result["deliveries"].as_array().unwrap().len(), 1);
    assert_eq!(
        f.call("B", json!({"operation":"wire_inspect"}))["inbox_count"],
        1
    );
    let replay = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(replay["deliveries"], result["deliveries"]);
    let mut different_slot = event(1, &sent["envelope"]);
    different_slot["event_id"] = json!("another_event");
    let conflict = f.download(vec![different_slot, event(2, &sent["envelope"])], 2);
    assert_eq!(conflict["status"], "stream_conflict");
    f.fails("B", json!({"operation":"wire_process"}), "stream_conflict");
}

#[test]
fn wire_full_queue_can_apply_independent_dependency_exactly_once() {
    let f = Fixture::new();
    let before = f.call("A", json!({"operation":"wire_inspect"}))["crypto_state_ref"].clone();
    f.call("B", json!({"operation":"wire_configure","conversation_id":"G1","authorization_version":"1","pending_limit":1}));
    let removed = f.call(
        "A",
        json!({"operation":"remove","id":"removeC","member":"C"}),
    );
    let after = f.call(
        "A",
        json!({"operation":"wire_configure","conversation_id":"G1","authorization_version":"2"}),
    )["crypto_state_ref"]
        .clone();
    assert_ne!(before, after);
    let sent = f.send("A", "M1");
    f.download(vec![event(1, &sent["envelope"])], 1);
    assert_eq!(
        f.call("B", json!({"operation":"wire_process"}))["sync"]["processed_cursor"],
        "0"
    );
    let control = json!({"control_id":"control1","from_state_ref":before,"to_state_ref":after,"payload_bytes":removed["commit"]});
    let slot = json!({"stream_id":"B_stream","event_seq":"2","event_id":"E2","availability":"available",
        "event":{"type":"crypto_control","control":control}});
    f.fails(
        "B",
        json!({"operation":"wire_download","stream_id":"B_stream","events":[slot],
        "next_after_seq":"2","watermark":"2","has_more":false}),
        "resource_exhausted",
    );
    f.call(
        "B",
        json!({"operation":"wire_apply_dependency","control":control}),
    );
    f.call(
        "B",
        json!({"operation":"wire_configure","conversation_id":"G1","authorization_version":"2"}),
    );
    let result = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(result["deliveries"].as_array().unwrap().len(), 1);
    assert_eq!(result["sync"]["processed_cursor"], "1");
    f.download(vec![slot], 2);
    let result = f.call("B", json!({"operation":"wire_process"}));
    assert_eq!(result["sync"]["processed_cursor"], "2");
    assert_eq!(result["sync"]["applied_control_count"], 1);
}

#[test]
fn wire_replacement_requires_tail_closure_and_same_plaintext() {
    let f = Fixture::new();
    let first = f.send("A", "M1");
    f.fails("A", json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P2","payload":"synthetic test content"}), "attempt_closed");
    f.fails("A", json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P2","payload":"modified",
        "replaces_attempt_id":"P1","closure_id":"closure1"}), "idempotency_conflict");
    let next = f.call("A", json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P2","payload":"synthetic test content",
        "replaces_attempt_id":"P1","closure_id":"closure1"}));
    assert_ne!(first["envelope"], next["envelope"]);
    assert_eq!(f.send("A", "M1")["envelope"], first["envelope"]);
}

#[test]
fn wire_strict_header_and_old_snapshot_defaults() {
    let state = DeviceState::new(Context {
        service: "S1".into(),
        account: "A".into(),
        device: "A1".into(),
    })
    .unwrap();
    let mut old = serde_json::to_value(state).unwrap();
    old.as_object_mut().unwrap().remove("wire");
    old.as_object_mut().unwrap().remove("wire_sync");
    let restored: DeviceState = serde_json::from_value(old).unwrap();
    assert!(restored.wire.configuration.is_none());
    let f = Fixture::new();
    let sent = f.send("A", "M1");
    let raw = codec::decode(sent["envelope"]["header_bytes"].as_str().unwrap()).unwrap();
    let parsed = Header::parse(&raw).unwrap();
    assert_eq!(parsed.authorization_version, "1");
    let original = String::from_utf8(raw).unwrap();
    let duplicate = original.replacen('{', "{\"protocol_version\":\"rim-poc-1\",", 1);
    assert!(Header::parse(duplicate.as_bytes()).is_err());
    let mut wrong: Value = serde_json::from_str(&original).unwrap();
    wrong["authorization_version"] = json!(9007199254740993u64);
    assert!(Header::parse(&serde_json::to_vec(&wrong).unwrap()).is_err());
    wrong["authorization_version"] = json!("9007199254740993");
    assert!(Header::parse(&serde_json::to_vec(&wrong).unwrap()).is_ok());
    let mut invalid_slot = event(1, &sent["envelope"]);
    invalid_slot["availability"] = json!("expired");
    invalid_slot["event"] = Value::Null;
    f.fails(
        "B",
        json!({"operation":"wire_download","stream_id":"B_stream","events":[invalid_slot],
        "next_after_seq":"1","watermark":"1","has_more":false}),
        "invalid_request",
    );
}

#[test]
fn wire_processing_capacity_failure_preserves_pending_event_and_snapshot() {
    let f = Fixture::new();
    let sent = f.send("A", "M1");
    f.download(vec![event(1, &sent["envelope"])], 1);
    {
        let locked = super::store::LockedDevice::open(&f.root.join("B")).unwrap();
        let context = Context {
            service: "S1".into(),
            account: "B".into(),
            device: "B".into(),
        };
        let mut state = locked.load(&context).unwrap().unwrap();
        let envelope: super::wire_types::Envelope =
            serde_json::from_value(sent["envelope"].clone()).unwrap();
        for index in 0..super::MAX_RECORDS {
            state.wire.inbox.insert(
                format!("fixture_{index}"),
                super::wire_types::Inbound {
                    logical_key: format!("fixture_{index}"),
                    attempt_id: "P1".into(),
                    envelope: envelope.clone(),
                    acceptance_id: None,
                    payload_digest: [0; 32],
                    payload: None,
                    acceptance_receipt: None,
                },
            );
        }
        locked.save(&mut state, super::CrashPoint::None).unwrap();
    }
    let before = fs::read(f.root.join("B/state.enc")).unwrap();
    f.fails(
        "B",
        json!({"operation":"wire_process"}),
        "resource_exhausted",
    );
    assert_eq!(before, fs::read(f.root.join("B/state.enc")).unwrap());
    let status = f.call("B", json!({"operation":"wire_inspect"}));
    assert_eq!(status["sync"]["processed_cursor"], "0");
    assert_eq!(status["sync"]["pending_count"], 1);
    assert_eq!(status["sync"]["quarantined_count"], 0);
}
