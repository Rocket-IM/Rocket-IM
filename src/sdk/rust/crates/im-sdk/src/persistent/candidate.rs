//! 密码计算在调用者的协调线程完成，不占数据库线程；只有最终事务写入完整候选。
use super::{
    data::{same_header, Saved, StoredMessage},
    types::*,
};
use rocket_crypto_core::{storage::Snapshot, Device};

pub(super) fn restore(s: &Saved) -> Result<Device> {
    let scope = &s.data.state.scope;
    if s.crypto.is_empty() {
        return Err(Error::new("initialize_required"));
    }
    let snapshot: Snapshot = decode(&s.crypto)?;
    let device = Device::restore(snapshot, &scope.service, &scope.account, &scope.device)
        .map_err(|_| Error::paused("crypto_state_invalid"))?;
    let identity = s
        .data
        .state
        .identity
        .as_ref()
        .ok_or_else(|| Error::paused("store_invalid"))?;
    if hex(&device.identity_key()?) != identity.identity_key {
        return Err(Error::paused("crypto_state_invalid"));
    }
    match (
        device.binding()?,
        &s.data.state.conversation,
        &s.data.state.peer,
    ) {
        (None, None, None) => {}
        (Some(b), Some(c), Some(p))
            if b.conversation
                == (if s.data.state.context == "initial" {
                    c.clone()
                } else {
                    s.data.state.context.clone()
                })
                && b.account == p.scope.account
                && b.device == p.scope.device
                && hex(&b.key) == p.identity_key => {}
        _ => return Err(Error::paused("crypto_state_invalid")),
    }
    Ok(device)
}
pub(super) fn apply(
    mut s: Box<Saved>,
    request_id: &str,
    action: &Action,
) -> Result<(Saved, Outcome)> {
    let st = &mut s.data.state;
    let mut device = if matches!(action, Action::Initialize) {
        let bytes = s
            .meta
            .journal
            .as_ref()
            .and_then(|j| j.seed.as_ref())
            .ok_or_else(|| Error::paused("initialization_evidence_missing"))?;
        Device::restore(
            decode(bytes)?,
            &st.scope.service,
            &st.scope.account,
            &st.scope.device,
        )?
    } else {
        restore(&s)?
    };
    let st = &mut s.data.state;
    let rev = number(&st.revision)?
        .checked_add(1)
        .ok_or_else(|| Error::new("revision_limit"))?
        .to_string();
    let mut message = None;
    let value = match action {
        Action::Initialize => {
            let identity = Identity {
                scope: st.scope.clone(),
                identity_key: hex(&device.identity_key()?),
            };
            st.identity = Some(identity.clone());
            Value::Initialized { identity }
        }
        Action::CreateGroup {
            conversation,
            peer,
            key_package,
        } => {
            let welcome = device.create_group(
                conversation.clone(),
                peer.scope.account.clone(),
                peer.scope.device.clone(),
                unhex(&peer.identity_key, 32)?,
                unhex(key_package, 262144)?,
            )?;
            st.conversation = Some(conversation.clone());
            st.peer = Some(peer.clone());
            Value::Created {
                welcome: hex(&welcome),
            }
        }
        Action::JoinGroup {
            conversation,
            peer,
            welcome,
        } => {
            device.join_group(
                conversation.clone(),
                peer.scope.account.clone(),
                peer.scope.device.clone(),
                unhex(&peer.identity_key, 32)?,
                unhex(welcome, 262144)?,
            )?;
            st.conversation = Some(conversation.clone());
            st.peer = Some(peer.clone());
            Value::Joined
        }
        Action::Send { message_id, text } => {
            let m = Message {
                service: st.scope.service.clone(),
                conversation: st
                    .conversation
                    .clone()
                    .ok_or_else(|| Error::new("group_required"))?,
                sender_account: st.scope.account.clone(),
                sender_device: st.scope.device.clone(),
                message_id: message_id.clone(),
                text: text.clone(),
                context: st.context.clone(),
            };
            let ciphertext = device.encrypt(pack_message(&m)?)?;
            let e = Envelope {
                service: m.service.clone(),
                conversation: m.conversation.clone(),
                sender_account: m.sender_account.clone(),
                sender_device: m.sender_device.clone(),
                message_id: m.message_id.clone(),
                ciphertext: hex(&ciphertext),
                context: st.context.clone(),
            };
            message = Some(StoredMessage {
                message: m,
                envelope: e.clone(),
                receipt: None,
            });
            Value::Sent { envelope: e }
        }
        Action::Receive { envelope } => {
            let plain = device.decrypt(unhex(&envelope.ciphertext, 262144)?)?;
            let m = unpack_message(&plain)?;
            if !same_header(&m, envelope) || m.text.is_empty() || m.text.len() > 32768 {
                return Err(Error::paused("message_invalid"));
            }
            st.received_count = number(&st.received_count)?
                .checked_add(1)
                .ok_or_else(|| Error::paused("receive_limit"))?
                .to_string();
            message = Some(StoredMessage {
                message: m.clone(),
                envelope: envelope.clone(),
                receipt: None,
            });
            Value::Received {
                message: m,
                position: st.received_count.clone(),
            }
        }
    };
    s.crypto = encode(&device.snapshot()?)?;
    if s.crypto.len() > rocket_crypto_core::storage::MAX_SNAPSHOT_BYTES {
        return Err(Error::paused("snapshot_limit"));
    }
    let outcome = Outcome {
        revision: rev.clone(),
        cached: false,
        value,
    };
    if let Some(mut m) = message {
        if matches!(outcome.value, Value::Received { .. }) {
            m.receipt = Some(outcome.clone());
        }
        s.data.messages.push(m);
    }
    s.data.state.revision = rev;
    s.data.state.pending_request = None;
    s.data
        .requests
        .get_mut(request_id)
        .ok_or_else(|| Error::paused("store_invalid"))?
        .result = RequestState::Complete {
        outcome: outcome.clone(),
    };
    if let Action::Receive { envelope } = action {
        super::network::mark_received(&mut s.data, envelope)?;
    }
    s.data.validate(&s.crypto)?;
    Ok((*s, outcome))
}

const MESSAGE_DOMAIN: &[u8] = b"Rocket-IM/SDK/message/v1\0";
fn pack_message(message: &Message) -> Result<Vec<u8>> {
    // 正文保留原 UTF-8 字节，避免控制字符的 JSON 转义把合法32KiB正文放大到密码上限之外。
    let mut header = message.clone();
    header.text.clear();
    let header = encode(&header)?;
    let mut bytes = MESSAGE_DOMAIN.to_vec();
    bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(message.text.as_bytes());
    Ok(bytes)
}
fn unpack_message(bytes: &[u8]) -> Result<Message> {
    let bad = || Error::paused("message_invalid");
    let body = bytes.strip_prefix(MESSAGE_DOMAIN).ok_or_else(bad)?;
    let length: [u8; 4] = body
        .get(..4)
        .ok_or_else(bad)?
        .try_into()
        .map_err(|_| bad())?;
    let length = u32::from_be_bytes(length) as usize;
    if length > 2048 {
        return Err(bad());
    }
    let mut message: Message =
        decode(body.get(4..4 + length).ok_or_else(bad)?).map_err(|_| bad())?;
    if !message.text.is_empty() {
        return Err(bad());
    }
    message.text = std::str::from_utf8(body.get(4 + length..).ok_or_else(bad)?)
        .map_err(|_| bad())?
        .into();
    Ok(message)
}
