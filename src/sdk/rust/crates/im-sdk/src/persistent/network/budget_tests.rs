//! 下载/处理使用生产路径；合成接受事实和边界填充不代表真实Service验收。
use super::{queue, rejection_tests::attach, types::*};
use crate::persistent::{
    budget_tests::{pad_data, pad_meta},
    data::{Saved, MAX_DATA},
    operations, store,
    tests::{send, Pair},
    types::*,
};

fn downloaded(pair: &mut Pair, id: &str) -> Event {
    let envelope = send(&mut pair.a, id);
    let event = Event {
        sequence: "1".into(),
        kind: "message".into(),
        acceptance: Acceptance {
            request_id: id.into(),
            message_id: id.into(),
            sequence: "1".into(),
            envelope_hash: hash(&encode(&envelope).unwrap()),
        },
        envelope: Some(envelope),
    };
    let copy = event.clone();
    pair.b
        .database
        .call(move |db| {
            db.update(false, |s| {
                let mut network = s.data.network.take().unwrap();
                network.download(
                    &s.data,
                    Page {
                        after: "0".into(),
                        upper: "1".into(),
                        next: "1".into(),
                        events: vec![copy],
                    },
                )?;
                s.data.network = Some(network);
                Ok(())
            })
        })
        .unwrap();
    event
}

fn check_blocked(pair: &mut Pair, event: Event, code: &str) {
    pair.reopen();
    let before = pair.b.database.call(|db| db.read(Ok)).unwrap();
    let network = before.data.network.as_ref().unwrap();
    assert_eq!(network.events.len(), 1);
    assert_eq!((&*network.processed, &*network.reported), ("0", "0"));
    let diagnostic = crate::persistent::capacity_tests::measured(&pair.b);
    let process = diagnostic
        .operations
        .iter()
        .find(|v| v.operation == "process")
        .unwrap();
    assert_eq!(
        process.state,
        crate::persistent::CapacityOperationState::Blocked
    );
    assert!(process
        .blockers
        .iter()
        .any(|v| v == code || (code == "storage_limit" && v.ends_with("preflight_limit"))));
    let error = queue::process_event(&mut pair.b, &before, event).unwrap_err();
    assert_eq!(error.code, code);
    assert!(!error.paused);
    let after = pair.b.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(
        operations::fingerprint(&before).unwrap(),
        operations::fingerprint(&after).unwrap()
    );
    assert_eq!(
        pair.b.request("network-receive-1".into()).unwrap(),
        RequestState::Missing
    );
    println!("BUDGET blocked code={code} requests={} data={} meta={} downloaded=1 processed=0 reported=0", after.data.requests.len(), encode(&after.data).unwrap().len(), encode(&after.meta).unwrap().len());
}

#[test]
fn request_limit_after_real_cached_receives_blocks_downloaded_event() {
    let mut pair = Pair::new();
    pair.group();
    let envelope = send(&mut pair.a, "duplicate");
    let action = Action::Receive { envelope };
    pair.b.execute("original".into(), action.clone()).unwrap();
    // 1021个不同请求号真实走缓存写事务；只有一条密文，不冒充1024次MLS解密。
    for n in 0..1021 {
        assert!(
            pair.b
                .execute(format!("duplicate-{n}"), action.clone())
                .unwrap()
                .cached
        );
    }
    attach(&mut pair);
    let event = downloaded(&mut pair, "next");
    check_blocked(&mut pair, event, "request_limit");
    assert!(
        pair.b
            .recover_request("original".into(), action)
            .unwrap()
            .cached
    );
    assert_eq!(
        pair.b
            .database
            .call(|db| db.read(|s| Ok(s.data.requests.len())))
            .unwrap(),
        1024
    );
}

fn replace(pair: &mut Pair, saved: Saved) {
    pair.b
        .database
        .call(move |db| {
            db.update(false, |s| {
                *s = saved;
                Ok(())
            })
        })
        .unwrap();
}

#[test]
fn downloaded_event_at_data_limit_keeps_original_and_cursors() {
    let mut pair = Pair::new();
    pair.group();
    attach(&mut pair);
    let event = downloaded(&mut pair, "data-limit");
    let mut saved = pair.b.database.call(|db| db.read(Ok)).unwrap();
    pad_data(&mut saved.data, MAX_DATA - 512 * 1024);
    assert!(saved.data.requests.len() < 1024);
    replace(&mut pair, saved);
    check_blocked(&mut pair, event, "storage_limit");
}

#[test]
fn downloaded_event_at_meta_limit_keeps_original_and_cursors() {
    let mut pair = Pair::new();
    pair.group();
    attach(&mut pair);
    let event = downloaded(&mut pair, "meta-limit");
    let mut saved = pair.b.database.call(|db| db.read(Ok)).unwrap();
    pad_meta(&mut saved, store::MAX_META - 128);
    replace(&mut pair, saved);
    check_blocked(&mut pair, event, "storage_limit");
}

#[test]
fn maximum_service_receive_representation_fits_the_design_envelope() {
    use crate::persistent::data::{Data, Record, StoredMessage};
    // 仅序列化上界：Service允许96KiB密文；这里的合成字节不执行解密。
    let scope = Scope {
        service: "s".repeat(64),
        account: "a".repeat(64),
        device: "d".repeat(64),
    };
    let mut data = Data::empty(scope.clone());
    data.network = Some(NetworkData::new(Binding {
        url: "wss://127.0.0.1:1/v1/ws".into(),
        ca_hash: "01".repeat(32),
        conversation: "c".repeat(64),
        peer: Identity {
            scope: Scope {
                account: "b".repeat(64),
                ..scope.clone()
            },
            identity_key: "02".repeat(32),
        },
        creator: false,
    }));
    let before = encode(&data).unwrap().len();
    let message = Message {
        service: scope.service,
        conversation: "c".repeat(64),
        sender_account: "b".repeat(64),
        sender_device: scope.device,
        message_id: "m".repeat(64),
        context: "01".repeat(32),
        text: "\0".repeat(32768),
    };
    let envelope = Envelope {
        service: message.service.clone(),
        conversation: message.conversation.clone(),
        sender_account: message.sender_account.clone(),
        sender_device: message.sender_device.clone(),
        message_id: message.message_id.clone(),
        context: message.context.clone(),
        ciphertext: "ab".repeat(96 * 1024),
    };
    let action = Action::Receive {
        envelope: envelope.clone(),
    };
    action.validate().unwrap();
    let outcome = Outcome {
        revision: u64::MAX.to_string(),
        cached: false,
        value: Value::Received {
            message: message.clone(),
            position: u64::MAX.to_string(),
        },
    };
    data.requests.insert(
        "r".repeat(64),
        Record {
            hash: hash(&encode(&action).unwrap()),
            input: Some(action.clone()),
            action: "receive".into(),
            result: RequestState::Complete {
                outcome: outcome.clone(),
            },
            rejection: None,
        },
    );
    data.messages.push(StoredMessage {
        message,
        envelope: envelope.clone(),
        receipt: Some(outcome),
    });
    let network = data.network.as_mut().unwrap();
    network.events.push(Event {
        sequence: "512".into(),
        kind: "message".into(),
        acceptance: Acceptance {
            request_id: "r".repeat(64),
            message_id: "m".repeat(64),
            sequence: "256".into(),
            envelope_hash: hash(&encode(&envelope).unwrap()),
        },
        envelope: Some(envelope),
    });
    network.processed = "512".into();
    network.reported = "512".into();
    network.upper = Some("512".into());
    data.state.revision = u64::MAX.to_string();
    data.state.received_count = u64::MAX.to_string();
    let delta = encode(&data).unwrap().len() - before;
    // 多条时最多补3个集合逗号；已存在字段增长只计一次。不是密码快照增长证明。
    assert!(delta + 3 < 1_200_000);
    assert!(encode(&action).unwrap().len() < 200_000);
    println!(
        "BUDGET service_receive_encoded_delta={delta} per_message_envelope=1200000 action_bytes={}",
        encode(&action).unwrap().len()
    );
}
