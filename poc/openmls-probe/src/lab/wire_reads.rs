//! 显式阅读意图的唯一持久归属；原消息槽与本机收件共同证明目标，签页 Read 槽证明服务确认。
use super::{
    checked, codec, ensure,
    state::DeviceState,
    wire_sync_types::{Event, StoredSlot},
    wire_types::{self, Header},
    LabError,
};
use crate::message_acceptance;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const LIMIT: usize = 10_000;
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reads {
    pub records: BTreeMap<String, Intent>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    pub service_id: String,
    pub conversation_id: String,
    pub account_id: String,
    pub device_id: String,
    pub stream_id: String,
    pub message_event_id: String,
    pub message_event_seq: String,
    pub acceptance_id: String,
    pub attempt_id: String,
    pub logical_key: String,
    pub envelope_sha256: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Confirmation {
    pub event_id: String,
    pub event_seq: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub target: Target,
    pub confirmation: Option<Confirmation>,
}

pub(super) fn source(state: &DeviceState) -> Result<(&str, &str), LabError> {
    ensure(
        state.rebuild.is_none() && state.wire_sync.source_verified,
        "read_source_required",
        "显式阅读仅支持已验证的普通设备签页",
    )?;
    let pin = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_deref()
        .ok_or_else(|| LabError::new("read_source_required", "阅读缺少固定 Service 公钥"))?;
    let stream = state
        .wire_sync
        .stream_id
        .as_deref()
        .ok_or_else(|| LabError::new("read_source_required", "阅读缺少已验证设备流"))?;
    Ok((pin, stream))
}

pub(super) fn message<'a>(
    state: &'a DeviceState,
    event_id: &str,
) -> Result<(&'a StoredSlot, Target), LabError> {
    let (pin, stream) = source(state)?;
    checked("read_invalid", wire_types::id(event_id))?;
    let mut matches = state
        .wire_sync
        .slots
        .iter()
        .filter(|(_, s)| s.slot.event_id == event_id);
    let (seq, stored) = matches
        .next()
        .ok_or_else(|| LabError::new("read_target_not_found", "没有该已下载消息槽"))?;
    ensure(
        matches.next().is_none(),
        "read_target_invalid",
        "消息事件 ID 对应多个槽",
    )?;
    ensure(
        stored.slot.stream_id == stream
            && wire_types::decimal(&stored.slot.event_seq)? == *seq
            && !stored.waiting,
        "read_target_invalid",
        "阅读目标的设备流或处理状态无效",
    )?;
    let Event::Message {
        acceptance_id,
        envelope,
        acceptance_receipt,
    } = stored
        .slot
        .event
        .as_ref()
        .ok_or_else(|| LabError::new("read_target_invalid", "阅读目标没有原消息事件"))?
    else {
        return Err(LabError::new(
            "read_target_invalid",
            "控制或回执槽不是阅读目标",
        ));
    };
    let result = stored
        .result
        .as_ref()
        .ok_or_else(|| LabError::new("read_target_invalid", "消息尚未处理"))?;
    let raw = wire_types::bytes(&envelope.header_bytes, 16 * 1024)?;
    let encrypted = wire_types::bytes(&envelope.payload_bytes, 512 * 1024)?;
    let header = Header::parse(&raw)?;
    let logical = header.logical_key()?;
    let inbound = state
        .wire
        .inbox
        .get(&logical)
        .ok_or_else(|| LabError::new("read_target_invalid", "目标缺少实际成功收件"))?;
    let proof = acceptance_receipt
        .as_ref()
        .ok_or_else(|| LabError::new("read_target_invalid", "消息槽缺少精确接受证明"))?;
    let accepted = checked(
        "read_target_invalid",
        message_acceptance::verify(pin, proof),
    )?;
    let inbox_proof = inbound
        .acceptance_receipt
        .as_ref()
        .ok_or_else(|| LabError::new("read_target_invalid", "成功收件缺少精确接受证明"))?;
    // 原收件重试允许保存同声明的新签名字节；两份证明须各自验签后逐字段相等。
    let received = checked(
        "read_target_invalid",
        message_acceptance::verify(pin, inbox_proof),
    )?;
    let digest = message_acceptance::envelope_digest(&raw, &encrypted);
    let conversation = state
        .wire
        .configuration
        .as_ref()
        .ok_or_else(|| LabError::new("read_target_invalid", "缺少当前会话范围"))?;
    ensure(
        header.service_id == state.context.service
            && header.conversation_id == conversation.conversation_id
            && header.recipients.iter().any(|r| {
                r.account_id == state.context.account && r.device_id == state.context.device
            })
            && accepted.service_id == header.service_id
            && accepted.conversation_id == header.conversation_id
            && accepted.acceptance_id == *acceptance_id
            && accepted.envelope_sha256 == digest
            && accepted.authorization_version == header.authorization_version
            && accepted.crypto_state_ref == header.crypto_state_ref
            && result["status"] == "valid"
            && result["acceptance_id"] == *acceptance_id
            && result["event_id"] == event_id
            && result["message"]["logical_message_id"] == header.logical_message_id
            && result["message"]["attempt_id"] == header.attempt_id
            && result["message"]["payload_sha256"] == codec::digest_hex(&inbound.payload_digest)
            && inbound.logical_key == logical
            && inbound.attempt_id == header.attempt_id
            && inbound.envelope == *envelope
            && inbound.acceptance_id.as_deref() == Some(acceptance_id)
            && received == accepted
            && inbound
                .payload
                .as_ref()
                .is_some_and(|payload| codec::digest(payload.as_bytes()) == inbound.payload_digest),
        "read_target_invalid",
        "阅读目标不对应本设备签页中实际解密的精确接受消息",
    )?;
    Ok((
        stored,
        Target {
            service_id: state.context.service.clone(),
            conversation_id: header.conversation_id,
            account_id: state.context.account.clone(),
            device_id: state.context.device.clone(),
            stream_id: stream.into(),
            message_event_id: event_id.into(),
            message_event_seq: stored.slot.event_seq.clone(),
            acceptance_id: acceptance_id.clone(),
            attempt_id: header.attempt_id,
            logical_key: logical,
            envelope_sha256: digest,
        },
    ))
}

pub(super) fn same_message(left: &Target, right: &Target) -> bool {
    left.service_id == right.service_id
        && left.conversation_id == right.conversation_id
        && left.account_id == right.account_id
        && left.device_id == right.device_id
        && left.stream_id == right.stream_id
        && left.acceptance_id == right.acceptance_id
        && left.attempt_id == right.attempt_id
        && left.logical_key == right.logical_key
        && left.envelope_sha256 == right.envelope_sha256
}

/// 已处理 Read 是不可逆事实；后续可用性投影不撤销已保存确认，也不赋予新的阅读意图。
pub(super) fn confirms(state: &DeviceState, stored: &StoredSlot, target: &Target) -> bool {
    stored.slot.stream_id == target.stream_id
        && !stored.waiting
        && stored
            .result
            .as_ref()
            .is_some_and(|r| r["status"] == "receipt_recorded")
        && matches!(&stored.slot.event,Some(Event::Read {acceptance_id,attempt_id,device})
            if acceptance_id==&target.acceptance_id && attempt_id==&target.attempt_id
                && device.account_id==state.context.account && device.device_id==state.context.device)
}

/// 普通与锚定加载都在恢复 provider 前检查；不会用裸 HTTP 布尔补造确认。
pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    let Some(reads) = &state.wire_reads else {
        return Ok(());
    };
    checked("read_state", source(state))?;
    ensure(
        !reads.records.is_empty() && reads.records.len() <= LIMIT,
        "read_state",
        "阅读记录为空或超过槽位上限",
    )?;
    for (key, intent) in &reads.records {
        let target =
            match super::wire_reclaimed::read_target(state, &intent.target.message_event_id)? {
                Some(target) => {
                    ensure(
                        intent.confirmation.is_some(),
                        "read_state",
                        "已回收消息不能保留未确认阅读",
                    )?;
                    target
                }
                None => {
                    checked(
                        "read_state",
                        message(state, &intent.target.message_event_id),
                    )?
                    .1
                }
            };
        ensure(
            key == &intent.target.acceptance_id && target == intent.target,
            "read_state",
            "阅读意图与原消息槽或本机范围不符",
        )?;
        if let Some(confirmation) = &intent.confirmation {
            let seq = checked("read_state", wire_types::decimal(&confirmation.event_seq))?;
            let stored = state
                .wire_sync
                .slots
                .get(&seq)
                .ok_or_else(|| LabError::new("read_state", "确认缺少原 Read 槽"))?;
            ensure(
                stored.slot.event_id == confirmation.event_id
                    && stored.slot.event_seq == confirmation.event_seq
                    && confirms(state, stored, &target),
                "read_state",
                "确认不是本设备精确消息的已处理签页 Read",
            )?;
        }
    }
    Ok(())
}
