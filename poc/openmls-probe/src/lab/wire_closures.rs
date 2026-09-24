//! 已验签封口的唯一持久归属；原 outbox 继续保存全部原字节及尝试尾。
use super::{
    checked, ensure,
    state::DeviceState,
    wire, wire_rejections,
    wire_types::{self, Device, Header, Outbound},
    LabError,
};
use crate::{
    message_acceptance,
    message_closure::{self, MessageClosureStatement},
    message_rejection::MessageRejectionStatement,
    permission::receipts::SignedRecord,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Closures {
    pub records: BTreeMap<String, SignedRecord>,
}

pub(super) fn receipt<'a>(state: &'a DeviceState, key: &str) -> Option<&'a SignedRecord> {
    state.wire_closures.as_ref()?.records.get(key)
}

pub(super) fn key(state: &DeviceState, message: &str, attempt: &str) -> Result<String, LabError> {
    checked("closure_invalid", wire_types::id(message))?;
    checked("closure_invalid", wire_types::id(attempt))?;
    let sender = Device {
        account_id: state.context.account.clone(),
        device_id: state.context.device.clone(),
    };
    let logical = wire_types::logical_key(
        &state.context.service,
        &wire::configuration(state)?.conversation_id,
        &sender,
        message,
    )?;
    checked(
        "closure_invalid",
        serde_json::to_string(&(&logical, &attempt)),
    )
}

pub(super) fn verify_record(
    state: &DeviceState,
    key: &str,
    receipt: &SignedRecord,
) -> Result<MessageClosureStatement, LabError> {
    let original = state
        .wire
        .outbox
        .get(key)
        .ok_or_else(|| LabError::new("closure_not_found", "本机没有该发送尝试"))?;
    let pin = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_ref()
        .ok_or_else(|| LabError::new("closure_state", "封口缺少固定 Service 回执公钥"))?;
    let fact = message_closure::verify(pin, receipt)?;
    let raw = wire_types::bytes(&original.envelope.header_bytes, 16 * 1024)?;
    let payload = wire_types::bytes(&original.envelope.payload_bytes, 512 * 1024)?;
    let header = Header::parse(&raw)?;
    ensure(
        fact.service_id == header.service_id
            && fact.conversation_id == header.conversation_id
            && fact.sender.account_id == header.sender.account_id
            && fact.sender.device_id == header.sender.device_id
            && fact.logical_message_id == header.logical_message_id
            && fact.attempt_id == header.attempt_id
            && fact.envelope_sha256 == message_acceptance::envelope_digest(&raw, &payload)
            && fact.replaces_attempt_id == original.replaces_attempt_id
            && fact.predecessor_closure_id == original.closure_id,
        "closure_conflict",
        "封口证明未绑定本机精确原尝试及前驱",
    )?;
    Ok(fact)
}

/// 只表达已验证终态的业务差异，不另存第二套 pending 或后继计数。
pub(super) enum Terminal {
    Closed(MessageClosureStatement),
    Rejected(MessageRejectionStatement),
}
impl Terminal {
    pub(super) fn closure_id(&self) -> &str {
        match self {
            Self::Closed(fact) => &fact.closure_id,
            Self::Rejected(fact) => &fact.closure_id,
        }
    }
    pub(super) fn conflict_code(&self) -> &'static str {
        match self {
            Self::Closed(_) => "closure_conflict",
            Self::Rejected(_) => "rejection_conflict",
        }
    }
}
pub(super) fn terminal(state: &DeviceState, key: &str) -> Result<Option<Terminal>, LabError> {
    if let Some(proof) = wire_rejections::receipt(state, key) {
        ensure(
            receipt(state, key).is_none(),
            "rejection_state",
            "拒绝与主动封口终态冲突",
        )?;
        return Ok(Some(Terminal::Rejected(wire_rejections::verify_record(
            state, key, proof,
        )?)));
    }
    receipt(state, key)
        .map(|proof| verify_record(state, key, proof).map(Terminal::Closed))
        .transpose()
}

pub(super) fn pending(state: &DeviceState) -> Option<(&String, &Outbound)> {
    state.wire.tails.values().find_map(|key| {
        state
            .wire
            .outbox
            .get_key_value(key)
            .filter(|(_, r)| r.acceptance_receipt.is_none())
    })
}

/// 恢复前核验终态、原链与尾；已终结祖先不计为第二个未决槽。
pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    if state.wire_send_order.is_none() {
        ensure(
            state.wire_rejections.is_none(),
            "rejection_state",
            "拒绝快照不能丢失发送门标记",
        )?;
        return ensure(
            state.wire_closures.is_none(),
            "closure_state",
            "封口快照不能丢失发送门标记",
        );
    }
    let mut facts = BTreeMap::new();
    let mut ids = BTreeSet::new();
    if let Some(closures) = &state.wire_closures {
        ensure(
            !closures.records.is_empty(),
            "closure_state",
            "封口容器不能为空",
        )?;
        for (key, proof) in &closures.records {
            let fact = checked("closure_state", verify_record(state, key, proof))?;
            ensure(
                state
                    .wire
                    .outbox
                    .get(key)
                    .is_some_and(|r| r.acceptance_receipt.is_none())
                    && ids.insert(fact.closure_id.clone()),
                "closure_state",
                "封口与接受终态冲突或封口 ID 重复",
            )?;
            facts.insert(key, Terminal::Closed(fact));
        }
    }
    if let Some(rejections) = &state.wire_rejections {
        ensure(
            !rejections.records.is_empty(),
            "rejection_state",
            "拒绝容器不能为空",
        )?;
        for (key, proof) in &rejections.records {
            let fact = checked(
                "rejection_state",
                wire_rejections::verify_record(state, key, proof),
            )?;
            ensure(
                state
                    .wire
                    .outbox
                    .get(key)
                    .is_some_and(|record| record.acceptance_receipt.is_none())
                    && !facts.contains_key(key)
                    && ids.insert(fact.closure_id.clone()),
                "rejection_state",
                "拒绝与既存接受、封口或终态 ID 冲突",
            )?;
            facts.insert(key, Terminal::Rejected(fact));
        }
    }
    let mut visited = BTreeSet::new();
    let mut pending_count = 0;
    for (logical, tail) in &state.wire.tails {
        let mut key = tail.clone();
        let mut count = 0;
        loop {
            let original = state
                .wire
                .outbox
                .get(&key)
                .ok_or_else(|| LabError::new("closure_state", "尝试链缺少原记录"))?;
            ensure(
                original.logical_key == *logical && visited.insert(key.clone()),
                "closure_state",
                "尝试链范围或前驱循环无效",
            )?;
            count += 1;
            ensure(count <= 5, "closure_state", "持久后继超过四个")?;
            if key == *tail {
                pending_count += usize::from(original.acceptance_receipt.is_none());
            } else {
                ensure(
                    facts.contains_key(&key),
                    "closure_state",
                    "非尾尝试缺少签名终态",
                )?;
            }
            match (&original.replaces_attempt_id, &original.closure_id) {
                (None, None) => break,
                (Some(previous), Some(closure)) => {
                    let previous_key =
                        checked("closure_state", serde_json::to_string(&(logical, previous)))?;
                    let predecessor = state
                        .wire
                        .outbox
                        .get(&previous_key)
                        .ok_or_else(|| LabError::new("closure_state", "后继缺少原前驱"))?;
                    ensure(
                        facts
                            .get(&previous_key)
                            .is_some_and(|fact| fact.closure_id() == closure)
                            && predecessor.payload == original.payload,
                        "closure_state",
                        "后继未引用原内容的已验签终态",
                    )?;
                    if let Some(Terminal::Rejected(fact)) = facts.get(&previous_key) {
                        wire_rejections::validate_successor(state, fact, original)?;
                    }
                    key = previous_key;
                }
                _ => return Err(LabError::new("closure_state", "后继证明字段必须成对")),
            }
        }
    }
    ensure(
        visited.len() == state.wire.outbox.len(),
        "closure_state",
        "原尝试不在当前持久链内",
    )?;
    ensure(
        pending_count <= 1,
        "send_order_state",
        "单未决模式包含多个未决逻辑消息",
    )
}
