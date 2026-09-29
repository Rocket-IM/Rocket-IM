//! 原尝试链和槽的有界转换；完整新证明先通过预算，才移除任何载荷。
use super::{
    checked, codec, ensure, state::DeviceState, wire_reclaim_types as compact,
    wire_sync_types::Event, wire_types, LabError,
};
use crate::{message_acceptance, permission::receipts::SignedRecord};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn chain(
    state: &DeviceState,
    logical: &str,
    attempt: &str,
) -> Result<Vec<compact::Attempt>, LabError> {
    ensure(
        state.wire_send_order.is_some(),
        "reclaim_source_required",
        "发送回收要求已启用M03发送门",
    )?;
    super::wire_send_order::validate(state)?;
    let mut key = state
        .wire
        .tails
        .get(logical)
        .cloned()
        .ok_or_else(|| LabError::new("reclaim_state", "已接受消息缺少尾尝试"))?;
    let mut records = Vec::new();
    loop {
        let original = state
            .wire
            .outbox
            .get(&key)
            .ok_or_else(|| LabError::new("reclaim_state", "发送链缺少原件"))?;
        if records.is_empty() {
            ensure(
                original.attempt_id == attempt && original.acceptance_receipt.is_some(),
                "reclaim_dependency",
                "发送链仍有未决或未接受尾",
            )?;
        }
        let terminal = if let Some(receipt) = &original.acceptance_receipt {
            compact::Terminal::Accepted {
                receipt: receipt.clone(),
            }
        } else if let Some(receipt) = super::wire_closures::receipt(state, &key) {
            compact::Terminal::Closed {
                receipt: receipt.clone(),
            }
        } else if let Some(receipt) = super::wire_rejections::receipt(state, &key) {
            compact::Terminal::Rejected {
                receipt: receipt.clone(),
            }
        } else {
            return Err(LabError::new("reclaim_dependency", "发送祖先缺少真实终态"));
        };
        let raw = wire_types::bytes(&original.envelope.header_bytes, 16 * 1024)?;
        let payload = wire_types::bytes(&original.envelope.payload_bytes, 512 * 1024)?;
        records.push(compact::Attempt {
            attempt_id: original.attempt_id.clone(),
            header_bytes: original.envelope.header_bytes.clone(),
            envelope_sha256: message_acceptance::envelope_digest(&raw, &payload),
            replaces_attempt_id: original.replaces_attempt_id.clone(),
            closure_id: original.closure_id.clone(),
            terminal,
        });
        match &original.replaces_attempt_id {
            Some(previous) => {
                key = checked("reclaim_state", serde_json::to_string(&(logical, previous)))?
            }
            None => break,
        }
    }
    Ok(records)
}

pub(super) fn event_identity(event: &Event) -> Option<(&str, &'static str)> {
    match event {
        Event::Message { acceptance_id, .. } => Some((acceptance_id, "message")),
        Event::Delivery { acceptance_id, .. } => Some((acceptance_id, "delivery")),
        Event::Read { acceptance_id, .. } => Some((acceptance_id, "read")),
        Event::MessageAvailability { acceptance_id, .. } => {
            Some((acceptance_id, "message_availability"))
        }
        _ => None,
    }
}

pub(super) fn apply(
    state: &mut DeviceState,
    candidates: Vec<compact::Message>,
    plan_id: String,
    receipt: SignedRecord,
    result: Value,
) -> Result<(), LabError> {
    let selected: BTreeMap<_, _> = candidates
        .iter()
        .map(|c| (c.acceptance_id.clone(), c))
        .collect();
    ensure(
        selected.len() == candidates.len(),
        "reclaim_conflict",
        "重复回收目标",
    )?;
    let mut compacted = state.wire_reclamation.clone().unwrap_or_default();
    for candidate in &candidates {
        ensure(
            !compacted.messages.contains_key(&candidate.logical_key)
                && !compacted
                    .messages
                    .values()
                    .any(|old| old.acceptance_id == candidate.acceptance_id),
            "reclaim_conflict",
            "选中消息已由另一计划回收",
        )?;
        compacted
            .messages
            .insert(candidate.logical_key.clone(), candidate.clone());
    }
    for (seq, stored) in &state.wire_sync.slots {
        let Some(event) = &stored.slot.event else {
            continue;
        };
        let Some((id, kind)) = event_identity(event) else {
            continue;
        };
        if selected.contains_key(id) {
            ensure(
                !compacted.slots.contains_key(seq),
                "reclaim_conflict",
                "槽已由另一计划回收",
            )?;
            compacted.slots.insert(
                *seq,
                compact::SlotFact {
                    event_id: stored.slot.event_id.clone(),
                    acceptance_id: id.into(),
                    original_event_sha256: codec::digest_hex(&codec::digest(&checked(
                        "reclaim_state",
                        serde_json::to_vec(event),
                    )?)),
                    kind: kind.into(),
                },
            );
        }
    }
    compacted
        .plans
        .insert(plan_id, compact::Plan { receipt, result });
    compacted.budget()?;
    // 下列状态只会随外层完整快照原子保存；失败不会交付成功或半份回收结果。
    for candidate in candidates {
        state.wire.inbox.remove(&candidate.logical_key);
        if !candidate.outbound.is_empty() {
            state.wire.tails.remove(&candidate.logical_key);
            for attempt in &candidate.outbound {
                let key = checked(
                    "reclaim_state",
                    serde_json::to_string(&(&candidate.logical_key, &attempt.attempt_id)),
                )?;
                state.wire.outbox.remove(&key);
                if let Some(records) = &mut state.wire_closures {
                    records.records.remove(&key);
                }
                if let Some(records) = &mut state.wire_rejections {
                    records.records.remove(&key);
                }
            }
        }
    }
    if state
        .wire_closures
        .as_ref()
        .is_some_and(|c| c.records.is_empty())
    {
        state.wire_closures = None;
    }
    if state
        .wire_rejections
        .as_ref()
        .is_some_and(|c| c.records.is_empty())
    {
        state.wire_rejections = None;
    }
    for (seq, fact) in &compacted.slots {
        if fact.kind == "message" {
            state
                .wire_sync
                .slots
                .get_mut(seq)
                .ok_or_else(|| LabError::new("reclaim_state", "回收目标槽消失"))?
                .slot
                .event = None;
        }
    }
    state.wire_reclamation = Some(compacted);
    super::wire_reclaim_validate::validate(state)?;
    super::wire_send_order::validate(state)?;
    super::wire_reads::validate(state)?;
    ensure(
        checked("state_encoding", serde_json::to_vec(state))?.len()
            <= crate::snapshot::MAX_PLAINTEXT_BYTES,
        "resource_exhausted",
        "回收后完整快照仍超过16MiB",
    )?;
    Ok(())
}
