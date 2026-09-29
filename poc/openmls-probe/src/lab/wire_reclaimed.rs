//! 原请求遇到已回收内容时只读紧凑事实；不重新加密、解密或生成历史副本。
use super::{
    checked, codec, ensure,
    state::DeviceState,
    wire_reads::Target,
    wire_reclaim_types::{Message, Terminal},
    wire_types::{self, Header},
    LabError,
};
use crate::{message_acceptance, permission::receipts::SignedRecord};
use serde_json::{json, Value};

pub(super) fn message<'a>(state: &'a DeviceState, logical: &str) -> Option<&'a Message> {
    state.wire_reclamation.as_ref()?.messages.get(logical)
}
pub(super) fn acceptance<'a>(state: &'a DeviceState, id: &str) -> Option<&'a Message> {
    state
        .wire_reclamation
        .as_ref()?
        .messages
        .values()
        .find(|m| m.acceptance_id == id)
}
pub(super) fn active_slots(state: &DeviceState) -> usize {
    state
        .wire_sync
        .slots
        .len()
        .saturating_sub(state.wire_reclamation.as_ref().map_or(0, |r| r.slots.len()))
}
pub(super) fn send(
    state: &DeviceState,
    logical: &str,
    attempt_id: &str,
    payload: &str,
    replaces: Option<&str>,
    closure: Option<&str>,
) -> Result<Option<Value>, LabError> {
    let Some(saved) = message(state, logical) else {
        return Ok(None);
    };
    ensure(
        !saved.outbound.is_empty(),
        "acceptance_conflict",
        "逻辑消息已属于紧凑收件",
    )?;
    let original = saved
        .outbound
        .iter()
        .find(|a| a.attempt_id == attempt_id)
        .ok_or_else(|| {
            LabError::new(
                "acceptance_conflict",
                "该逻辑消息已接受且内容已回收，不能新建尝试",
            )
        })?;
    ensure(
        codec::digest(payload.as_bytes()) == saved.payload_digest
            && original.replaces_attempt_id.as_deref() == replaces
            && original.closure_id.as_deref() == closure,
        "idempotency_conflict",
        "已回收尝试对应不同正文或替代参数",
    )?;
    let header = Header::parse(&wire_types::bytes(&original.header_bytes, 16 * 1024)?)?;
    let mut result = terminal(
        state,
        &header.logical_message_id,
        attempt_id,
        original.terminal.receipt(),
        original.terminal.status(),
    )?
    .ok_or_else(|| LabError::new("reclaim_state", "已回收尝试缺少终态"))?;
    result["reused"] = json!(true);
    Ok(Some(result))
}
pub(super) fn receive(
    state: &DeviceState,
    header: &Header,
    raw: &[u8],
    encrypted: &[u8],
    acceptance_id: Option<&str>,
) -> Result<Option<Value>, LabError> {
    let Some(saved) = message(state, &header.logical_key()?) else {
        return Ok(None);
    };
    ensure(
        saved.outbound.is_empty()
            && header.recipients.iter().any(|d| {
                d.account_id == state.context.account && d.device_id == state.context.device
            }),
        "identity_mismatch",
        "已回收内容不属于本设备收件",
    )?;
    ensure(
        saved.attempt_id == header.attempt_id
            && saved.envelope_sha256 == message_acceptance::envelope_digest(raw, encrypted)
            && acceptance_id.is_none_or(|id| id == saved.acceptance_id),
        "idempotency_conflict",
        "已回收逻辑消息不能替换密文或接受ID",
    )?;
    Ok(Some(
        json!({"logical_message_id":header.logical_message_id,"attempt_id":header.attempt_id,
        "payload_sha256":codec::digest_hex(&saved.payload_digest),"duplicate":true,"payload_reclaimed":true}),
    ))
}
pub(super) fn terminal(
    state: &DeviceState,
    message_id: &str,
    attempt_id: &str,
    proof: &SignedRecord,
    expected: &str,
) -> Result<Option<Value>, LabError> {
    let key = super::wire_closures::key(state, message_id, attempt_id)?;
    let pair: (String, String) = checked("reclaim_state", serde_json::from_str(&key))?;
    let Some(saved) = message(state, &pair.0) else {
        return Ok(None);
    };
    let original = saved
        .outbound
        .iter()
        .find(|a| a.attempt_id == attempt_id)
        .ok_or_else(|| LabError::new("attempt_not_found", "紧凑记录没有此尝试"))?;
    ensure(
        original.terminal.status() == expected && original.terminal.receipt() == proof,
        "acceptance_conflict",
        "迟到证明不能替换已回收尝试终态",
    )?;
    let mut result = json!({"logical_message_id":message_id,"attempt_id":attempt_id,
        "status":expected,"duplicate":true,"payload_reclaimed":true});
    let pin = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_deref()
        .ok_or_else(|| LabError::new("reclaim_state", "紧凑证明缺少固定Service回执钥"))?;
    match &original.terminal {
        Terminal::Accepted { receipt } => {
            result["acceptance_id"] =
                json!(message_acceptance::verify(pin, receipt)?.acceptance_id);
        }
        Terminal::Closed { receipt } => {
            let fact = crate::message_closure::verify(pin, receipt)?;
            result["closure_id"] = json!(fact.closure_id);
            result["outcome"] = json!(fact.outcome);
        }
        Terminal::Rejected { receipt } => {
            let fact = crate::message_rejection::verify(pin, receipt)?;
            result["closure_id"] = json!(fact.closure_id);
            result["outcome"] = json!(fact.outcome);
            result["code"] = json!(fact.code);
        }
    }
    Ok(Some(result))
}
pub(super) fn close_request(
    state: &DeviceState,
    message_id: &str,
    attempt_id: &str,
) -> Result<Option<Value>, LabError> {
    let key = super::wire_closures::key(state, message_id, attempt_id)?;
    let pair: (String, String) = checked("reclaim_state", serde_json::from_str(&key))?;
    let Some(saved) = message(state, &pair.0) else {
        return Ok(None);
    };
    let original = saved
        .outbound
        .iter()
        .find(|a| a.attempt_id == attempt_id)
        .ok_or_else(|| LabError::new("closure_not_found", "紧凑记录没有此发送尝试"))?;
    match original.terminal {
        Terminal::Accepted { .. } => {
            return Err(LabError::new("closure_conflict", "已接受尝试不能封口"))
        }
        Terminal::Rejected { .. } => {
            return Err(LabError::new(
                "rejection_conflict",
                "已拒绝尝试不能主动封口",
            ))
        }
        Terminal::Closed { .. } => {}
    }
    let header = Header::parse(&wire_types::bytes(&original.header_bytes, 16 * 1024)?)?;
    let mut result = json!({"service_id":header.service_id,"conversation_id":header.conversation_id,
        "logical_message_id":message_id,"attempt_id":attempt_id,"envelope_sha256":original.envelope_sha256});
    if let (Some(previous), Some(closure)) = (&original.replaces_attempt_id, &original.closure_id) {
        result["replaces_attempt_id"] = json!(previous);
        result["closure_id"] = json!(closure);
    }
    Ok(Some(result))
}
pub(super) fn read_target(state: &DeviceState, event_id: &str) -> Result<Option<Target>, LabError> {
    let Some(compacted) = &state.wire_reclamation else {
        return Ok(None);
    };
    let Some((seq, fact)) = compacted
        .slots
        .iter()
        .find(|(_, s)| s.kind == "message" && s.event_id == event_id)
    else {
        return Ok(None);
    };
    let saved = acceptance(state, &fact.acceptance_id)
        .ok_or_else(|| LabError::new("reclaim_state", "紧凑槽缺少消息证明"))?;
    let header = Header::parse(&wire_types::bytes(&saved.header_bytes, 16 * 1024)?)?;
    ensure(
        saved.outbound.is_empty()
            && header.recipients.iter().any(|d| {
                d.account_id == state.context.account && d.device_id == state.context.device
            }),
        "reclaim_state",
        "阅读紧凑范围不符",
    )?;
    Ok(Some(Target {
        service_id: state.context.service.clone(),
        conversation_id: header.conversation_id,
        account_id: state.context.account.clone(),
        device_id: state.context.device.clone(),
        stream_id: state
            .wire_sync
            .stream_id
            .clone()
            .ok_or_else(|| LabError::new("reclaim_state", "缺少设备流"))?,
        message_event_id: event_id.into(),
        message_event_seq: seq.to_string(),
        acceptance_id: saved.acceptance_id.clone(),
        attempt_id: saved.attempt_id.clone(),
        logical_key: saved.logical_key.clone(),
        envelope_sha256: saved.envelope_sha256.clone(),
    }))
}
