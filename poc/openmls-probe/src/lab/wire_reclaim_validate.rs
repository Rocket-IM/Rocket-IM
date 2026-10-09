//! 恢复provider前核验紧凑证明与每个原槽/阅读引用；缺证据不默认为从未见过。
use super::{
    checked, codec, ensure,
    state::DeviceState,
    wire_reclaim_types::{Message, Terminal},
    wire_sync_types::Availability,
    wire_types::{self, Header},
    LabError,
};
use crate::{message_acceptance, message_reclamation};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

fn header(raw: &str) -> Result<Header, LabError> {
    Header::parse(&wire_types::bytes(raw, 16 * 1024)?)
}
fn attempts(state: &DeviceState, message: &Message, pin: &str) -> Result<(), LabError> {
    if message.outbound.is_empty() {
        return Ok(());
    }
    ensure(
        message.outbound.len() <= 5,
        "reclaim_state",
        "紧凑尝试链过长",
    )?;
    let mut facts = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for (index, attempt) in message.outbound.iter().enumerate() {
        let h = header(&attempt.header_bytes)?;
        ensure(
            h.logical_key()? == message.logical_key
                && h.attempt_id == attempt.attempt_id
                && h.sender.account_id == state.context.account
                && h.sender.device_id == state.context.device
                && ids.insert(attempt.attempt_id.clone()),
            "reclaim_state",
            "紧凑尝试范围不符或重复",
        )?;
        match &attempt.terminal {
            Terminal::Accepted { receipt } => {
                let fact = message_acceptance::verify(pin, receipt)?;
                ensure(
                    index == 0
                        && attempt.attempt_id == message.attempt_id
                        && attempt.header_bytes == message.header_bytes
                        && attempt.envelope_sha256 == message.envelope_sha256
                        && *receipt == message.acceptance_receipt
                        && fact.envelope_sha256 == attempt.envelope_sha256
                        && fact.acceptance_id == message.acceptance_id,
                    "reclaim_state",
                    "紧凑链接受尾不一致",
                )?;
            }
            Terminal::Closed { receipt } => {
                let f = crate::message_closure::verify(pin, receipt)?;
                ensure(
                    index > 0
                        && f.service_id == h.service_id
                        && f.conversation_id == h.conversation_id
                        && f.sender.account_id == h.sender.account_id
                        && f.sender.device_id == h.sender.device_id
                        && f.logical_message_id == h.logical_message_id
                        && f.attempt_id == h.attempt_id
                        && f.envelope_sha256 == attempt.envelope_sha256
                        && f.replaces_attempt_id == attempt.replaces_attempt_id
                        && f.predecessor_closure_id == attempt.closure_id,
                    "reclaim_state",
                    "紧凑封口原件不一致",
                )?;
                facts.insert(attempt.attempt_id.clone(), f.closure_id);
            }
            Terminal::Rejected { receipt } => {
                let f = crate::message_rejection::verify(pin, receipt)?;
                ensure(
                    index > 0
                        && f.service_id == h.service_id
                        && f.conversation_id == h.conversation_id
                        && f.sender.account_id == h.sender.account_id
                        && f.sender.device_id == h.sender.device_id
                        && f.logical_message_id == h.logical_message_id
                        && f.attempt_id == h.attempt_id
                        && f.envelope_sha256 == attempt.envelope_sha256
                        && f.replaces_attempt_id == attempt.replaces_attempt_id
                        && f.predecessor_closure_id == attempt.closure_id
                        && super::wire_rejections::checkpoint_satisfied(state, &f)?,
                    "reclaim_state",
                    "紧凑拒绝原件或权限链不一致",
                )?;
                facts.insert(attempt.attempt_id.clone(), f.closure_id);
            }
        }
    }
    for (index, attempt) in message.outbound.iter().enumerate() {
        if let Some(previous) = message.outbound.get(index + 1) {
            ensure(
                attempt.replaces_attempt_id.as_ref() == Some(&previous.attempt_id)
                    && attempt.closure_id.as_ref() == facts.get(&previous.attempt_id),
                "reclaim_state",
                "紧凑前驱链断裂",
            )?;
        } else {
            ensure(
                attempt.replaces_attempt_id.is_none() && attempt.closure_id.is_none(),
                "reclaim_state",
                "紧凑链根不完整",
            )?;
        }
    }
    Ok(())
}

pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    let Some(compacted) = &state.wire_reclamation else {
        return Ok(());
    };
    ensure(
        ((compacted.version == 1
            && compacted.prepared.is_empty()
            && compacted.plans.values().all(|p| p.request_json.is_none())
            && !compacted.messages.is_empty()
            && !compacted.plans.is_empty())
            || (compacted.version == 2
                && (!compacted.prepared.is_empty()
                    || compacted.plans.values().any(|p| p.request_json.is_some()))))
            && state.wire_sync.source_verified,
        "reclaim_state",
        "紧凑状态版本、来源或账本无效",
    )?;
    compacted.budget()?;
    super::wire_reclaim_preparation::validate(state)?;
    let pin = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_deref()
        .ok_or_else(|| LabError::new("reclaim_state", "紧凑状态缺少Service固定钥"))?;
    let stream = state
        .wire_sync
        .stream_id
        .as_deref()
        .ok_or_else(|| LabError::new("reclaim_state", "紧凑状态缺少流"))?;
    let conversation = &super::wire::configuration(state)?.conversation_id;
    let mut plans = BTreeMap::new();
    for (id, plan) in &compacted.plans {
        let statement = message_reclamation::verify(pin, &plan.receipt)?;
        ensure(
            statement.plan_id == *id
                && statement.service_id == state.context.service
                && statement.conversation_id == *conversation
                && statement.account_id == state.context.account
                && statement.device_id == state.context.device
                && statement.stream_id == stream
                && wire_types::decimal(&statement.processed_seq)?
                    <= state.wire_sync.processed_cursor,
            "reclaim_state",
            "紧凑许可范围或处理前缀不符",
        )?;
        let expected = json!({"status":"reclaimed","plan_id":id,"reclaimed_count":statement.messages.len(),"duplicate":false,
            "finish_request":{"service_id":statement.service_id,"conversation_id":statement.conversation_id,"plan_id":id,"receipt":plan.receipt}});
        ensure(
            plan.result == expected,
            "reclaim_state",
            "回收原结果不完整或被替换",
        )?;
        plans.insert(id, statement);
    }
    let mut ids = BTreeSet::new();
    for (key, message) in &compacted.messages {
        let h = header(&message.header_bytes)?;
        let proof = message_acceptance::verify(pin, &message.acceptance_receipt)?;
        let plan = plans
            .get(&message.plan_id)
            .ok_or_else(|| LabError::new("reclaim_state", "消息缺少原回收许可"))?;
        let permit = plan
            .messages
            .iter()
            .find(|p| p.acceptance_id == message.acceptance_id)
            .ok_or_else(|| LabError::new("reclaim_state", "消息不在原回收选择中"))?;
        ensure(
            key == &message.logical_key
                && h.logical_key()? == *key
                && h.attempt_id == message.attempt_id
                && h.service_id == state.context.service
                && h.conversation_id == *conversation
                && proof.acceptance_id == message.acceptance_id
                && proof.envelope_sha256 == message.envelope_sha256
                && proof.service_id == h.service_id
                && proof.conversation_id == h.conversation_id
                && proof.authorization_version == h.authorization_version
                && proof.crypto_state_ref == h.crypto_state_ref
                && permit.envelope_sha256 == message.envelope_sha256
                && serde_json::to_value(message.availability)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .as_deref()
                    == Some(&permit.availability)
                && permit.recipients.len() == h.recipients.len()
                && permit
                    .recipients
                    .iter()
                    .zip(&h.recipients)
                    .all(|(a, b)| a.account_id == b.account_id && a.device_id == b.device_id)
                && ids.insert(message.acceptance_id.clone())
                && !state.wire.inbox.contains_key(key)
                && !state.wire.tails.contains_key(key)
                && !state.wire.outbox.values().any(|o| o.logical_key == *key),
            "reclaim_state",
            "紧凑消息的原接受、终态、身份或唯一性不符",
        )?;
        if message.outbound.is_empty() {
            ensure(
                h.recipients.iter().any(|d| {
                    d.account_id == state.context.account && d.device_id == state.context.device
                }) && compacted.slots.values().any(|s| s.acceptance_id == message.acceptance_id && s.kind == "message")
                    && compacted.slots.iter().any(|(seq, fact)| fact.acceptance_id == message.acceptance_id
                        && fact.kind == "delivery" && state.wire_sync.slots.get(seq).is_some_and(|stored|
                            matches!(&stored.slot.event, Some(super::wire_sync_types::Event::Delivery { attempt_id, device, .. })
                                if attempt_id == &message.attempt_id && device.account_id == state.context.account && device.device_id == state.context.device)
                                && stored.result.as_ref().is_some_and(|r| r["status"] == "receipt_recorded"))),
                "reclaim_state",
                "紧凑收件不属于本机",
            )?;
        }
        attempts(state, message, pin)?;
    }
    for (id, plan) in plans {
        ensure(
            plan.messages.iter().all(|p| {
                compacted
                    .messages
                    .values()
                    .any(|m| m.plan_id == *id && m.acceptance_id == p.acceptance_id)
            }),
            "reclaim_state",
            "计划中的紧凑消息丢失",
        )?;
    }
    for original in state.wire.outbox.values() {
        if let Some(receipt) = &original.acceptance_receipt {
            ensure(
                !ids.contains(&message_acceptance::verify(pin, receipt)?.acceptance_id),
                "reclaim_state",
                "接受ID与原发送冲突",
            )?;
        }
    }
    ensure(
        state
            .wire
            .inbox
            .values()
            .all(|r| r.acceptance_id.as_ref().is_none_or(|id| !ids.contains(id))),
        "reclaim_state",
        "接受ID与原收件冲突",
    )?;
    for stored in state.wire_sync.slots.values() {
        if let Some(super::wire_sync_types::Event::Message {
            acceptance_id,
            envelope,
            ..
        }) = &stored.slot.event
        {
            ensure(
                !ids.contains(acceptance_id)
                    && !compacted
                        .messages
                        .contains_key(&header(&envelope.header_bytes)?.logical_key()?),
                "reclaim_state",
                "已回收消息仍有原密文槽副本",
            )?;
        }
    }
    for (seq, fact) in &compacted.slots {
        let stored = state
            .wire_sync
            .slots
            .get(seq)
            .ok_or_else(|| LabError::new("reclaim_state", "紧凑证明缺少槽身份"))?;
        let message = compacted
            .messages
            .values()
            .find(|m| m.acceptance_id == fact.acceptance_id)
            .ok_or_else(|| LabError::new("reclaim_state", "紧凑槽缺少消息"))?;
        ensure(
            stored.slot.event_id == fact.event_id
                && stored.slot.event_seq == seq.to_string()
                && stored.slot.stream_id == stream
                && *seq <= state.wire_sync.processed_cursor
                && !stored.waiting
                && stored.result.is_some(),
            "reclaim_state",
            "紧凑槽范围或处理状态错误",
        )?;
        wire_types::reference(&fact.original_event_sha256)?;
        if fact.kind == "message" {
            let h = header(&message.header_bytes)?;
            let result = stored
                .result
                .as_ref()
                .ok_or_else(|| LabError::new("reclaim_state", "缺少成功结果"))?;
            ensure(
                stored.slot.event.is_none()
                    && matches!(
                        stored.slot.availability,
                        Availability::Deleted | Availability::Expired
                    )
                    && stored.slot.availability == message.availability
                    && result["status"] == "valid"
                    && result["acceptance_id"] == message.acceptance_id
                    && result["event_id"] == fact.event_id
                    && result["message"]["logical_message_id"] == h.logical_message_id
                    && result["message"]["attempt_id"] == message.attempt_id
                    && result["message"]["payload_sha256"]
                        == codec::digest_hex(&message.payload_digest),
                "reclaim_state",
                "紧凑收件成功事实不完整",
            )?;
        } else {
            let event = stored
                .slot
                .event
                .as_ref()
                .ok_or_else(|| LabError::new("reclaim_state", "紧凑回执或终态事件缺失"))?;
            ensure(
                super::wire_reclaim_compact::event_identity(event)
                    == Some((fact.acceptance_id.as_str(), fact.kind.as_str()))
                    && fact.original_event_sha256
                        == codec::digest_hex(&codec::digest(&checked(
                            "reclaim_state",
                            serde_json::to_vec(event),
                        )?)),
                "reclaim_state",
                "紧凑小事件原件不一致",
            )?;
        }
    }
    Ok(())
}
