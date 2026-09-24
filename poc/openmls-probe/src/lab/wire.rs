//! 完整原始头作为 MLS AAD。此适配不从 Relay 的标签建立密码信任。

use super::{
    checked, codec, ensure, groups, state::DeviceState, wire_types::*, LabError, MAX_MESSAGE_BYTES,
    MAX_RECORDS,
};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use serde_json::{json, Value};

pub(super) fn state_ref(group: &MlsGroup) -> Result<String, LabError> {
    // GroupContext 包含协议/套件、群 ID、epoch、树摘要、confirmed transcript 和扩展。
    // 它是各成员一致的公共上下文；不能使用私有快照或 exporter secret。
    let context = checked(
        "context_encoding",
        group
            .public_group()
            .group_context()
            .tls_serialize_detached(),
    )?;
    let mut bytes = b"Rocket-IM/rim-poc-1/MLS-GroupContext\0".to_vec();
    bytes.extend(context);
    Ok(codec::digest_hex(&codec::digest(&bytes)))
}

pub(super) fn members(state: &DeviceState, group: &MlsGroup) -> Result<Vec<Device>, LabError> {
    groups::validate_members(state, group)?;
    let mut result = group
        .members()
        .map(|member| {
            let context = codec::credential_context(&member.credential)?;
            id(&context.account)?;
            id(&context.device)?;
            Ok(Device {
                account_id: context.account,
                device_id: context.device,
            })
        })
        .collect::<Result<Vec<_>, LabError>>()?;
    result.sort();
    ensure(
        (2..=6).contains(&result.len()) && result.windows(2).all(|pair| pair[0] != pair[1]),
        "recipient_set_mismatch",
        "实验群需 2—6 个唯一设备",
    )?;
    Ok(result)
}

pub(super) fn configure(
    state: &mut DeviceState,
    conversation_id: String,
    authorization_version: String,
) -> Result<Value, LabError> {
    id(&conversation_id)?;
    let version = decimal(&authorization_version)?;
    let group = state.group()?;
    ensure(group.is_active(), "device_revoked", "本机不在当前群中")?;
    let reference = state_ref(&group)?;
    let members = members(state, &group)?;
    if let Some(old) = &state.wire.configuration {
        ensure(
            old.conversation_id == conversation_id,
            "wrong_context",
            "已有会话不能重新绑定",
        )?;
        ensure(
            version >= decimal(&old.authorization_version)?
                && (old.crypto_state_ref == reference
                    || version > decimal(&old.authorization_version)?),
            "state_conflict",
            "密码状态变化需要递增权限检查点，不能回退",
        )?;
    }
    state.wire.configuration = Some(Configuration {
        conversation_id,
        authorization_version,
        crypto_state_ref: reference,
        members,
    });
    inspect(state)
}

pub(super) fn inspect(state: &DeviceState) -> Result<Value, LabError> {
    let group = state.group()?;
    let reference = state_ref(&group)?;
    let mut result = json!({"crypto_state_ref":reference,"epoch":group.epoch().as_u64().to_string(),
        "group_id":codec::encode(group.group_id().as_slice()),"active":group.is_active(),
        "configuration":state.wire.configuration,"outbox_count":state.wire.outbox.len(),
        "inbox_count":state.wire.inbox.len(),"accepted_outbox_count":state.wire.outbox.values().filter(|r|r.acceptance_receipt.is_some()).count(),
        "sync":state.wire_sync.summary(),"history":super::wire_history::summary(state)});
    if state.wire_send_order.is_some() {
        result["send_order"] = super::wire_send_order::summary(state)?;
    }
    Ok(result)
}

pub(super) fn configuration(state: &DeviceState) -> Result<&Configuration, LabError> {
    state
        .wire
        .configuration
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "尚未绑定可信实验会话检查点"))
}

pub(super) fn send(
    state: &mut DeviceState,
    logical_message_id: String,
    attempt_id: String,
    payload: String,
    replaces_attempt_id: Option<String>,
    closure_id: Option<String>,
) -> Result<Value, LabError> {
    id(&logical_message_id)?;
    id(&attempt_id)?;
    ensure(
        payload.len() <= MAX_MESSAGE_BYTES,
        "resource_exhausted",
        "内容超过 64 KiB",
    )?;
    let config = configuration(state)?;
    let sender = Device {
        account_id: state.context.account.clone(),
        device_id: state.context.device.clone(),
    };
    let header = Header {
        protocol_version: "rim-poc-1".into(),
        service_id: state.context.service.clone(),
        conversation_id: config.conversation_id.clone(),
        sender: sender.clone(),
        logical_message_id: logical_message_id.clone(),
        attempt_id: attempt_id.clone(),
        security_mode: "e2ee".into(),
        crypto_profile: "mls-poc".into(),
        authorization_version: config.authorization_version.clone(),
        crypto_state_ref: config.crypto_state_ref.clone(),
        recipients: config
            .members
            .iter()
            .filter(|member| **member != sender)
            .cloned()
            .collect(),
    };
    let key = header.attempt_key()?;
    let logical_key = header.logical_key()?;
    ensure(
        !state.wire.outbox.iter().any(|(other_key, record)| {
            record.logical_key == logical_key
                && record.acceptance_receipt.is_some()
                && *other_key != key
        }),
        "acceptance_conflict",
        "同逻辑消息已由另一尝试接受，只能重试已接受的原尝试",
    )?;
    if let Some(previous) = state.wire.outbox.get(&key) {
        ensure(
            previous.payload == payload
                && previous.replaces_attempt_id == replaces_attempt_id
                && previous.closure_id == closure_id,
            "idempotency_conflict",
            "同尝试对应不同内容或替代证明",
        )?;
        return Ok(
            json!({"envelope":previous.envelope,"reused":true,"logical_message_id":logical_message_id,"attempt_id":attempt_id}),
        );
    }
    super::wire_send_order::new_attempt(
        state,
        &logical_key,
        &payload,
        replaces_attempt_id.as_deref(),
        closure_id.as_deref(),
    )?;
    ensure(
        state.wire.outbox.len() < MAX_RECORDS,
        "resource_exhausted",
        "发送队列已满",
    )?;
    if let Some(tail) = state.wire.tails.get(&logical_key) {
        let old = state
            .wire
            .outbox
            .get(tail)
            .ok_or_else(|| LabError::new("state_conflict", "尝试链缺少尾记录"))?;
        ensure(
            replaces_attempt_id.as_ref() == Some(&old.attempt_id) && closure_id.is_some(),
            "attempt_closed",
            "替代需可信调度器提供当前尾尝试的封口结果",
        )?;
        ensure(
            old.payload == payload,
            "idempotency_conflict",
            "替代不能修改原逻辑内容",
        )?;
        id(closure_id.as_deref().unwrap_or_default())?;
    } else {
        ensure(
            replaces_attempt_id.is_none() && closure_id.is_none(),
            "attempt_closed",
            "初次发送不能携带替代参数",
        )?;
    }
    let mut group = state.group()?;
    ensure(group.is_active(), "device_revoked", "本机不在当前群中")?;
    ensure(
        state_ref(&group)? == config.crypto_state_ref && members(state, &group)? == config.members,
        "state_stale",
        "需先验证并绑定新密码检查点",
    )?;
    let raw_header = checked("header_encoding", serde_json::to_vec(&header))?;
    Header::parse(&raw_header)?;
    group.set_aad(raw_header.clone());
    let signer = state.signer()?;
    #[cfg(feature = "wire-send-probe")]
    super::wire_send_probe::record_create_message();
    let ciphertext = checked(
        "send_encrypt",
        group.create_message(&state.provider, &signer, payload.as_bytes()),
    )?;
    let envelope = Envelope {
        header_bytes: codec::encode(&raw_header),
        payload_bytes: codec::encode(&checked("message_encoding", ciphertext.to_bytes())?),
    };
    let result = json!({"envelope":envelope,"reused":false,"logical_message_id":logical_message_id,"attempt_id":attempt_id});
    state.wire.outbox.insert(
        key.clone(),
        Outbound {
            logical_key: logical_key.clone(),
            attempt_id,
            payload,
            envelope,
            replaces_attempt_id,
            closure_id,
            acceptance_receipt: None,
        },
    );
    state.wire.tails.insert(logical_key, key);
    Ok(result)
}

pub(super) use super::wire_receive::receive;
