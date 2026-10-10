//! 终态签页保留公开回执身份；只补来源，不恢复消息、已读意图或可用性。
use super::{
    ensure,
    state::DeviceState,
    wire_sync_types::{validate_event, Availability, Event, Slot, StoredSlot},
    wire_types, LabError,
};
use serde_json::json;

/// 调用方仍须核对签页来源、处理前缀及原消息绑定；终态引用不补阅读确认状态。
pub(super) fn processed_receipt(stored: &StoredSlot) -> Option<&Event> {
    if stored.waiting {
        return None;
    }
    let result = stored.result.as_ref()?;
    let event = if result["status"] == "receipt_recorded" {
        stored.slot.event.as_ref()
    } else if result["status"] == "unavailable"
        && matches!(
            stored.slot.availability,
            Availability::Deleted | Availability::Expired
        )
        && result["availability"] == json!(stored.slot.availability)
    {
        stored.slot.terminal_reference.as_ref()
    } else {
        None
    }?;
    matches!(event, Event::Delivery { .. } | Event::Read { .. }).then_some(event)
}

pub(super) fn validate(slot: &Slot) -> Result<(), LabError> {
    let Some(reference) = &slot.terminal_reference else {
        return Ok(());
    };
    ensure(
        matches!(
            slot.availability,
            Availability::Deleted | Availability::Expired
        ) && slot.event.is_none()
            && matches!(reference, Event::Delivery { .. } | Event::Read { .. }),
        "terminal_reference_invalid",
        "终态引用只允许删除或到期槽的公开送达/阅读身份",
    )?;
    validate_event(reference)
}

pub(super) fn source(slots: &[Slot], verified: bool) -> Result<(), LabError> {
    for slot in slots {
        if slot.terminal_reference.is_some() {
            ensure(
                verified,
                "stream_source_required",
                "终态回执引用必须来自本次已验签分页",
            )?;
        }
        validate(slot)?;
    }
    Ok(())
}

pub(super) fn overlap(old: &Slot, incoming: &Slot) -> Result<(), LabError> {
    ensure(
        old.terminal_reference.is_none() || old.availability == incoming.availability,
        "terminal_reference_conflict",
        "已有终态引用不能改变终态投影",
    )?;
    let Some(reference) = &incoming.terminal_reference else {
        return Ok(());
    };
    ensure(
        (old.availability == Availability::Available || old.availability == incoming.availability)
            && old.event.as_ref().is_none_or(|event| event == reference)
            && old
                .terminal_reference
                .as_ref()
                .is_none_or(|original| original == reference),
        "terminal_reference_conflict",
        "终态回执引用与原事件、终态或已有引用冲突",
    )
}

/// 锚预约前仅核对已认证页的新引用，不恢复provider，也不修改任何槽。
pub(super) fn preflight(
    state: &DeviceState,
    slots: &[Slot],
    verified: bool,
) -> Result<(), LabError> {
    source(slots, verified)?;
    for slot in slots {
        let seq = wire_types::decimal(&slot.event_seq)?;
        if let Some(old) = state.wire_sync.slots.get(&seq) {
            if slot.terminal_reference.is_some() || old.slot.terminal_reference.is_some() {
                ensure(
                    old.slot.event_id == slot.event_id && old.slot.stream_id == slot.stream_id,
                    "terminal_reference_conflict",
                    "终态引用不能移到不同槽身份",
                )?;
                overlap(&old.slot, slot)?;
            }
        }
    }
    Ok(())
}

/// 保存的原事件可能仍在；输入页的event缺失约束不能错误拒绝这类完整旧事实。
pub(super) fn stored(state: &DeviceState) -> Result<(), LabError> {
    for (seq, stored) in &state.wire_sync.slots {
        let slot = &stored.slot;
        let Some(reference) = &slot.terminal_reference else {
            continue;
        };
        ensure(
            state.wire_sync.source_verified
                && state.wire_sync.stream_id.as_deref() == Some(slot.stream_id.as_str())
                && wire_types::decimal(&slot.event_seq)? == *seq
                && matches!(
                    slot.availability,
                    Availability::Deleted | Availability::Expired
                )
                && matches!(reference, Event::Delivery { .. } | Event::Read { .. })
                && slot.event.as_ref().is_none_or(|event| event == reference),
            "terminal_reference_invalid",
            "已保存终态引用缺少普通签页来源或与原槽不一致",
        )?;
        validate_event(reference)?;
    }
    Ok(())
}
