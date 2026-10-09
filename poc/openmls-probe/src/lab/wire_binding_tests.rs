//! 仅测试：真实 MLS 签名身份与头声明者分开，避免在目标集合或 AAD 门提前失败。
//! 每次 execute 都重新加载加密快照；本模块不新增实验 CLI 或公开攻击入口。

use super::{
    codec, execute, groups,
    state::DeviceState,
    store::LockedDevice,
    wire,
    wire_types::{Device, Envelope, Header},
    Context, CrashPoint, Peer, Pin,
};
use crate::authorization::{key_package_sha256, AuthorizationRequest, DeviceAuthorization};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct BindingFixture {
    root: PathBuf,
    contexts: [Context; 3],
}

impl BindingFixture {
    fn new(claimed: Device) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rim-wire-binding-{}-{stamp}-{sequence}",
                std::process::id()
            ));
        fs::create_dir(&root).unwrap();
        let contexts = [
            Context {
                service: "S1".into(),
                account: "A".into(),
                device: "A".into(),
            },
            Context {
                service: "S1".into(),
                account: "B".into(),
                device: "B".into(),
            },
            Context {
                service: "S1".into(),
                account: claimed.account_id,
                device: claimed.device_id,
            },
        ];
        let mut states: Vec<_> = contexts
            .iter()
            .cloned()
            .map(|context| DeviceState::new(context).unwrap())
            .collect();
        if states[0].context.account == states[2].context.account {
            // 备用同账号设备必须经过实际设备授权，不能伪造 roster 或跳过成员校验。
            let authorization = DeviceAuthorization::sign(
                AuthorizationRequest {
                    service: "S1".into(),
                    account: "A".into(),
                    signer_device: "A".into(),
                    new_device: states[2].context.device.clone(),
                    new_signature_key: states[2].own_signature_key,
                    key_package_sha256: key_package_sha256(&states[2].key_package),
                    expected_roster_version: 0,
                    nonce: [1; 32],
                    issued_at_unix_secs: 1,
                    expires_at_unix_secs: 301,
                },
                &states[0].signer().unwrap(),
            )
            .unwrap();
            let peer_package = states[2].key_package.clone();
            let peer_key = states[2].own_signature_key;
            states[0]
                .roster
                .apply(&authorization, &peer_package, &peer_key, 1)
                .unwrap();
            states[2].roster = states[0].roster.clone();
        }
        let pins: Vec<_> = states
            .iter()
            .map(|state| Pin {
                account: state.context.account.clone(),
                device: state.context.device.clone(),
                signature_key: codec::encode(&state.own_signature_key),
            })
            .collect();
        let peers: Vec<_> = states[1..]
            .iter()
            .map(|state| Peer {
                account: state.context.account.clone(),
                device: state.context.device.clone(),
                signature_key: codec::encode(&state.own_signature_key),
                key_package: codec::encode(&state.key_package),
            })
            .collect();
        let created = groups::create(&mut states[0], peers).unwrap();
        for state in &mut states[1..] {
            groups::join(state, created["welcome"].as_str().unwrap(), pins.clone()).unwrap();
        }
        for (index, state) in states.iter_mut().enumerate() {
            wire::configure(state, "G1".into(), "1".into()).unwrap();
            LockedDevice::open(&root.join(index.to_string()))
                .unwrap()
                .save(state, CrashPoint::None)
                .unwrap();
        }
        for (index, observer) in states.iter().enumerate() {
            for (other, peer) in states.iter().enumerate() {
                if index != other {
                    super::identity_test_support::verify(
                        &root.join(index.to_string()),
                        &observer.context.service,
                        &observer.context.account,
                        &observer.context.device,
                        &peer.public_identity(),
                    );
                }
            }
        }
        Self { root, contexts }
    }

    fn request(&self, index: usize, mut operation: Value) -> String {
        let context = &self.contexts[index];
        let map = operation.as_object_mut().unwrap();
        map.insert("directory".into(), json!(self.root.join(index.to_string())));
        map.insert("service".into(), json!(context.service));
        map.insert("account".into(), json!(context.account));
        map.insert("device".into(), json!(context.device));
        operation.to_string()
    }

    fn call(&self, index: usize, operation: Value) -> Value {
        execute(&self.request(index, operation)).unwrap()["result"].clone()
    }

    fn load(&self, index: usize) -> DeviceState {
        LockedDevice::open(&self.root.join(index.to_string()))
            .unwrap()
            .load(&self.contexts[index])
            .unwrap()
            .unwrap()
    }

    fn receiver_provider(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut state = self.load(1);
        state.capture_provider().unwrap();
        state.provider_entries
    }

    fn download(&self, seq: u64, envelope: &Envelope) {
        self.call(
            1,
            json!({"operation":"wire_download","stream_id":"binding_stream",
            "events":[{"stream_id":"binding_stream","event_seq":seq.to_string(),
                "event_id":format!("E{seq}"),"availability":"available",
                "event":{"type":"message","acceptance_id":format!("K{seq}"),"envelope":envelope}}],
            "next_after_seq":seq.to_string(),"watermark":seq.to_string(),"has_more":false}),
        );
    }

    fn signed_wrong_sender(&self) -> (Envelope, Header) {
        let state = self.load(0);
        let mut group = state.group().unwrap();
        let claimed = &self.contexts[2];
        let sender = Device {
            account_id: claimed.account.clone(),
            device_id: claimed.device.clone(),
        };
        let config = wire::configuration(&state).unwrap();
        let header = Header {
            protocol_version: "rim-poc-1".into(),
            service_id: "S1".into(),
            conversation_id: "G1".into(),
            sender: sender.clone(),
            logical_message_id: "M1".into(),
            attempt_id: "P1".into(),
            security_mode: "e2ee".into(),
            crypto_profile: "mls-poc".into(),
            authorization_version: "1".into(),
            crypto_state_ref: config.crypto_state_ref.clone(),
            recipients: config
                .members
                .iter()
                .filter(|member| **member != sender)
                .cloned()
                .collect(),
        };
        let raw = serde_json::to_vec(&header).unwrap();
        Header::parse(&raw).unwrap();
        group.set_aad(raw.clone());
        let message = group
            .create_message(
                &state.provider,
                &state.signer().unwrap(),
                b"synthetic test content",
            )
            .unwrap();
        // 不保存此测试分支。随后合法原件从相同的真实发送者 ratchet generation 生成，
        // 只有接收失败确实恢复 provider 时才可正常处理，而非依靠下一个 generation 成功。
        (
            Envelope {
                header_bytes: codec::encode(&raw),
                payload_bytes: codec::encode(&message.to_bytes().unwrap()),
            },
            header,
        )
    }
}

impl Drop for BindingFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn assert_sender_binding_and_recovery(claimed: Device) {
    let f = BindingFixture::new(claimed);
    let (bad, header) = f.signed_wrong_sender();
    let before_provider = f.receiver_provider();
    let before_snapshot = fs::read(f.root.join("1/state.enc")).unwrap();
    let error = execute(&f.request(
        1,
        json!({"operation":"wire_receive","header_bytes":bad.header_bytes,
            "payload_bytes":bad.payload_bytes}),
    ))
    .unwrap_err();
    assert_eq!(error.code, "identity_mismatch");
    // 精确消息证明已经完成真实 MLS 解密、AAD 和目标校验，并触达 credential 绑定门。
    assert_eq!(error.message, "头发送者与真实密码身份不同");
    assert!(before_snapshot == fs::read(f.root.join("1/state.enc")).unwrap());
    assert!(before_provider == f.receiver_provider());
    assert!(f.load(1).wire.inbox.is_empty());

    f.download(1, &bad);
    assert!(before_provider == f.receiver_provider());
    let quarantined = f.call(1, json!({"operation":"wire_process"}));
    assert_eq!(quarantined["results"][0]["result"]["status"], "quarantined");
    assert_eq!(
        quarantined["results"][0]["result"]["code"],
        "identity_mismatch"
    );
    assert_eq!(quarantined["deliveries"], json!([]));
    assert_eq!(quarantined["sync"]["download_cursor"], "1");
    assert_eq!(quarantined["sync"]["processed_cursor"], "1");
    assert_eq!(quarantined["sync"]["quarantined_count"], 1);
    assert_eq!(quarantined["sync"]["pending_count"], 0);
    assert!(before_provider == f.receiver_provider());
    assert!(f.load(1).wire.inbox.is_empty());

    let sent = f.call(
        0,
        json!({"operation":"wire_send","logical_message_id":"M1",
        "attempt_id":"P1","payload":"synthetic test content"}),
    );
    let original: Envelope = serde_json::from_value(sent["envelope"].clone()).unwrap();
    let valid_header = Header::parse(&codec::decode(&original.header_bytes).unwrap()).unwrap();
    assert_eq!(header.logical_message_id, valid_header.logical_message_id);
    assert_eq!(header.attempt_id, valid_header.attempt_id);
    assert_eq!(
        usize::from(header.sender.account_id != valid_header.sender.account_id)
            + usize::from(header.sender.device_id != valid_header.sender.device_id),
        1,
        "发送者账号与设备两个字段中恰有一个不同"
    );
    f.download(2, &original);
    let result = f.call(1, json!({"operation":"wire_process"}));
    assert_eq!(result["results"][0]["event_seq"], "2");
    assert_eq!(result["results"][0]["result"]["status"], "valid");
    assert_eq!(
        result["results"][0]["result"]["message"]["duplicate"],
        false
    );
    assert_eq!(
        result["deliveries"],
        json!([{"acceptance_id":"K2","attempt_id":"P1","event_id":"E2"}])
    );
    assert_eq!(result["sync"]["download_cursor"], "2");
    assert_eq!(result["sync"]["processed_cursor"], "2");
    assert_eq!(result["sync"]["quarantined_count"], 1);
    assert_eq!(result["sync"]["pending_count"], 0);
    let received = f.load(1);
    assert_eq!(received.wire.inbox.len(), 1);
    assert!(!received
        .wire
        .inbox
        .contains_key(&header.logical_key().unwrap()));
    assert_eq!(
        received.wire.inbox[&valid_header.logical_key().unwrap()].envelope,
        original
    );
    let after_provider = f.receiver_provider();
    assert!(before_provider != after_provider);
    let replay = f.call(1, json!({"operation":"wire_process"}));
    assert_eq!(replay["results"], json!([]));
    assert_eq!(replay["deliveries"], result["deliveries"]);
    let duplicate = f.call(
        1,
        json!({"operation":"wire_receive",
        "header_bytes":original.header_bytes,"payload_bytes":original.payload_bytes}),
    );
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(f.load(1).wire.inbox.len(), 1);
    assert!(after_provider == f.receiver_provider());
}

#[test]
fn wire_sender_account_binding_survives_quarantine_and_snapshot_reload() {
    assert_sender_binding_and_recovery(Device {
        account_id: "C".into(),
        device_id: "A".into(),
    });
}

#[test]
fn wire_sender_device_binding_survives_quarantine_and_snapshot_reload() {
    assert_sender_binding_and_recovery(Device {
        account_id: "A".into(),
        device_id: "C".into(),
    });
}
