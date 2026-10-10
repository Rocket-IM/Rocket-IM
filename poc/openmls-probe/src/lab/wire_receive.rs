//! 接受证据先于去重；历史解密只使用当前provider内的官方past-epoch状态。
use super::{
    checked, codec, ensure, state::DeviceState, wire, wire_history, wire_types::*, LabError,
    MAX_MESSAGE_BYTES, MAX_RECORDS,
};
use crate::{message_acceptance, permission::receipts::SignedRecord};
use openmls::prelude::*;
use serde_json::{json, Value};

fn verify_acceptance(
    state: &DeviceState,
    header: &Header,
    raw: &[u8],
    ciphertext: &[u8],
    acceptance_id: Option<&str>,
    receipt: Option<&SignedRecord>,
) -> Result<(), LabError> {
    if let Some(id_value) = acceptance_id {
        id(id_value)?;
    }
    if let Some(receipt) = receipt {
        let key = state
            .permissions
            .recovery
            .relay_receipt_key
            .as_ref()
            .ok_or_else(|| LabError::new("receipt_pin_required", "未固定Service消息接受签名钥"))?;
        let statement = message_acceptance::verify(key, receipt)?;
        ensure(
            acceptance_id == Some(statement.acceptance_id.as_str())
                && statement.service_id == header.service_id
                && statement.conversation_id == header.conversation_id
                && statement.authorization_version == header.authorization_version
                && statement.crypto_state_ref == header.crypto_state_ref
                && statement.envelope_sha256
                    == message_acceptance::envelope_digest(raw, ciphertext),
            "acceptance_conflict",
            "接受记录未绑定精确密文、接受ID和头上下文",
        )?;
    }
    Ok(())
}

pub(super) fn receive(
    state: &mut DeviceState,
    envelope: Envelope,
    acceptance_id: Option<String>,
    acceptance_receipt: Option<SignedRecord>,
) -> Result<Value, LabError> {
    let raw_header = bytes(&envelope.header_bytes, 16 * 1024)?;
    let header = Header::parse(&raw_header)?;
    let ciphertext = bytes(&envelope.payload_bytes, 512 * 1024)?;
    let key = header.logical_key()?;
    let config = wire::configuration(state)?;
    ensure(
        header.service_id == state.context.service
            && header.conversation_id == config.conversation_id,
        "identity_mismatch",
        "实例或会话上下文不匹配",
    )?;
    verify_acceptance(
        state,
        &header,
        &raw_header,
        &ciphertext,
        acceptance_id.as_deref(),
        acceptance_receipt.as_ref(),
    )?;
    if let Some(result) = super::wire_reclaimed::receive(
        state,
        &header,
        &raw_header,
        &ciphertext,
        acceptance_id.as_deref(),
    )? {
        return Ok(result);
    }
    if let Some(id) = &acceptance_id {
        let exact_owner = state
            .wire
            .inbox
            .get(&key)
            .filter(|record| record.envelope == envelope)
            .map(|_| super::wire_acceptance::Owner::Inbox(key.as_str()));
        super::wire_acceptance::available(state, id, exact_owner)?;
    }
    if let Some(record) = state.wire.inbox.get_mut(&key) {
        if record.envelope == envelope {
            if let Some(incoming) = &acceptance_id {
                ensure(
                    record.acceptance_id.is_some()
                        || acceptance_receipt.is_some()
                        || state.permissions.recovery.relay_receipt_key.is_none(),
                    "acceptance_required",
                    "固定签名模式补绑定接受ID需要有效回执",
                )?;
                ensure(
                    record
                        .acceptance_id
                        .as_ref()
                        .is_none_or(|saved| saved == incoming),
                    "acceptance_conflict",
                    "成功记录的接受ID不能替换",
                )?;
                if acceptance_receipt.is_some()
                    || state.permissions.recovery.relay_receipt_key.is_none()
                {
                    record.acceptance_id = Some(incoming.clone());
                }
            }
            if let Some(receipt) = acceptance_receipt {
                record.acceptance_receipt = Some(receipt);
            }
            // 已成功且字节完全相同，不重解密，也不赋予新的历史接收权限。
            return Ok(
                json!({"logical_message_id":header.logical_message_id,"attempt_id":header.attempt_id,
                "payload_sha256":codec::digest_hex(&record.payload_digest),"duplicate":true}),
            );
        }
    }
    ensure(
        state.wire.inbox.len() < MAX_RECORDS,
        "resource_exhausted",
        "接收去重记录已满",
    )?;
    let mut group = state.group()?;
    ensure(group.is_active(), "device_revoked", "本机不在当前群中")?;
    let config = wire::configuration(state)?;
    ensure(
        config.crypto_state_ref == wire::state_ref(&group)?,
        "trust_required",
        "当前权限检查点与密码状态不同",
    )?;
    wire_history::current_identity(state, &header)?;
    let protocol = codec::protocol(&ciphertext)?;
    ensure(
        protocol.group_id() == group.group_id(),
        "identity_mismatch",
        "消息不属于当前群",
    )?;
    ensure(
        protocol.content_type() == ContentType::Application,
        "invalid_envelope",
        "预期应用密文",
    )?;
    ensure(
        protocol.epoch() <= group.epoch(),
        "missing_crypto_state",
        "需先验证后续权限与密码状态",
    )?;
    let epoch = protocol.epoch().as_u64();
    let historical = epoch < group.epoch().as_u64();
    let all_members =
        wire_history::recipients(state, &group, &header, epoch, acceptance_receipt.is_some())?;
    ensure(
        all_members.contains(&header.sender),
        "identity_mismatch",
        "发送者不属于消息对应的已验证群",
    )?;
    let targets: Vec<_> = all_members
        .into_iter()
        .filter(|member| *member != header.sender)
        .collect();
    let own = Device {
        account_id: state.context.account.clone(),
        device_id: state.context.device.clone(),
    };
    ensure(
        header.recipients == targets && targets.contains(&own),
        "recipient_set_mismatch",
        "目标集合与消息epoch的真实成员不符",
    )?;
    ensure(
        historical
            || acceptance_id.is_none()
            || acceptance_receipt.is_some()
            || state.permissions.recovery.relay_receipt_key.is_none(),
        "acceptance_required",
        "固定签名模式首次绑定接受ID需要有效回执",
    )?;
    let processed = checked(
        "decryption_failed",
        group.process_message(&state.provider, protocol),
    )?;
    ensure(
        processed.aad() == raw_header,
        "identity_mismatch",
        "完整原始头与密码认证AAD不同",
    )?;
    let sender = codec::credential_context(processed.credential())?;
    ensure(
        sender.service == header.service_id
            && sender.account == header.sender.account_id
            && sender.device == header.sender.device_id,
        "identity_mismatch",
        "头发送者与真实密码身份不同",
    )?;
    let plaintext = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
        _ => return Err(LabError::new("invalid_envelope", "预期应用密文")),
    };
    ensure(
        plaintext.len() <= MAX_MESSAGE_BYTES,
        "resource_exhausted",
        "内容超过64KiB",
    )?;
    checked("invalid_envelope", std::str::from_utf8(&plaintext))?;
    ensure(
        !state.wire.inbox.contains_key(&key),
        "idempotency_conflict",
        "同逻辑键出现另一份有效密文",
    )?;
    let payload_digest = codec::digest(&plaintext);
    let acceptance_id =
        if acceptance_receipt.is_some() || state.permissions.recovery.relay_receipt_key.is_none() {
            acceptance_id
        } else {
            None
        };
    state.wire.inbox.insert(
        key.clone(),
        Inbound {
            logical_key: key,
            attempt_id: header.attempt_id.clone(),
            envelope,
            payload_digest,
            acceptance_id,
            payload: Some(checked("invalid_envelope", String::from_utf8(plaintext))?),
            acceptance_receipt,
        },
    );
    Ok(
        json!({"logical_message_id":header.logical_message_id,"attempt_id":header.attempt_id,"payload_sha256":codec::digest_hex(&payload_digest),"duplicate":false,"historical":historical,"epoch":epoch.to_string()}),
    )
}
