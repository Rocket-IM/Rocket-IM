//! 双游标、失败隔离及独立控制依赖；状态与 MLS 快照共同提交。

use super::wire_sync_types::{validate_control, validate_event, Availability, Event, StoredSlot};
pub(super) use super::wire_sync_types::{Control, Slot, SyncState};
use super::{
    checked, codec, ensure, groups,
    state::DeviceState,
    wire,
    wire_types::{bytes, decimal, id},
    LabError,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) fn download(
    state: &mut DeviceState,
    stream_id: String,
    events: Vec<Slot>,
    next_after_seq: String,
    watermark: String,
    has_more: bool,
) -> Result<Value, LabError> {
    download_with_source(
        state,
        stream_id,
        events,
        next_after_seq,
        watermark,
        has_more,
        false,
    )
}

/// 仅供已核验本次普通页或重建页原字节签名的内部入口调用。
pub(super) fn download_verified(
    state: &mut DeviceState,
    stream_id: String,
    events: Vec<Slot>,
    next_after_seq: String,
    watermark: String,
    has_more: bool,
) -> Result<Value, LabError> {
    download_with_source(
        state,
        stream_id,
        events,
        next_after_seq,
        watermark,
        has_more,
        true,
    )
}

fn download_with_source(
    state: &mut DeviceState,
    stream_id: String,
    events: Vec<Slot>,
    next_after_seq: String,
    watermark: String,
    has_more: bool,
    verified: bool,
) -> Result<Value, LabError> {
    super::wire_lifecycle::require_source(&events, verified)?;
    id(&stream_id)?;
    ensure(
        !state.wire_sync.halted,
        "stream_conflict",
        "设备流已停止自动合并",
    )?;
    let next = decimal(&next_after_seq)?;
    let high = decimal(&watermark)?;
    ensure(
        next <= high && events.len() <= 100,
        "cursor_invalid",
        "分页范围无效",
    )?;
    ensure(
        state
            .wire_sync
            .stream_id
            .as_ref()
            .is_none_or(|old| *old == stream_id),
        "cursor_invalid",
        "设备流代际不匹配",
    )?;
    let cursor = state.wire_sync.download_cursor;
    ensure(
        high >= cursor && (has_more == (next < high)),
        "cursor_invalid",
        "水位回退或分页标记不一致",
    )?;
    let mut new_count = 0;
    let mut previous = None;
    let mut event_sequences = BTreeMap::new();
    for (seq, stored) in &state.wire_sync.slots {
        ensure(
            event_sequences
                .insert(stored.slot.event_id.as_str(), *seq)
                .is_none_or(|old| old == *seq),
            "invalid_envelope",
            "同一事件 ID 不能对应多个槽位序号",
        )?;
    }
    for slot in &events {
        id(&slot.event_id)?;
        if let Some(event) = &slot.event {
            validate_event(event)?;
        }
        ensure(
            slot.stream_id == stream_id
                && (slot.availability == Availability::Available) == slot.event.is_some(),
            "invalid_envelope",
            "事件流或载荷可用性不一致",
        )?;
        let seq = decimal(&slot.event_seq)?;
        ensure(
            seq > 0 && seq <= high && previous.is_none_or(|prev| seq == prev + 1),
            "cursor_invalid",
            "页内序号不连续",
        )?;
        previous = Some(seq);
        if let Some(old) = state.wire_sync.slots.get(&seq) {
            let conflict = old.slot.event_id != slot.event_id
                || (slot.availability == Availability::Available
                    && old.slot.availability != Availability::Available)
                || (slot.availability == Availability::Available && old.slot.event != slot.event);
            if conflict {
                state.wire_sync.halted = true;
                return Ok(json!({"status":"stream_conflict","sync":state.wire_sync.summary()}));
            }
        } else {
            ensure(
                seq == cursor + new_count + 1,
                "cursor_invalid",
                "不能跳过未下载槽位",
            )?;
            new_count += 1;
        }
        // 阅读等持久引用按事件 ID 定位；跨序号复用会令成功保存的快照无法重载。
        ensure(
            event_sequences
                .insert(slot.event_id.as_str(), seq)
                .is_none_or(|old| old == seq),
            "invalid_envelope",
            "同一事件 ID 不能对应多个槽位序号",
        )?;
    }
    ensure(
        events
            .last()
            .is_none_or(|slot| decimal(&slot.event_seq).ok() == Some(next))
            && (!events.is_empty() || (next == cursor && high == cursor))
            && next >= cursor,
        "cursor_invalid",
        "下一游标不对应完整页面",
    )?;
    // 完整页先规划目标变更；任一声明失败都不插槽、不推进游标、更不解密前缀。
    let lifecycle = super::wire_lifecycle::plan(state, &events)?;
    let pending = state
        .wire_sync
        .slots
        .values()
        .filter(|slot| slot.result.is_none() || slot.waiting)
        .count();
    ensure(
        pending + new_count as usize <= state.wire_sync.pending_limit
            && state.wire_sync.slots.len() + new_count as usize <= 10_000,
        "resource_exhausted",
        "待处理队列或设备流记录已满",
    )?;
    for slot in events {
        let seq = decimal(&slot.event_seq)?;
        if let Some(old) = state.wire_sync.slots.get_mut(&seq) {
            // 可用性单独投影；保留已存原始事件与成功去重，不覆盖业务记录。
            old.slot.availability = slot.availability;
        } else {
            state.wire_sync.slots.insert(
                seq,
                StoredSlot {
                    slot,
                    result: None,
                    waiting: false,
                },
            );
        }
    }
    super::wire_lifecycle::apply(state, lifecycle)?;
    state.wire_sync.stream_id = Some(stream_id);
    state.wire_sync.download_cursor = next;
    Ok(json!({"status":"downloaded","sync":state.wire_sync.summary()}))
}

fn checkpoint(state: &mut DeviceState) -> Result<Vec<u8>, LabError> {
    state.capture_provider()?;
    checked("state_encoding", serde_json::to_vec(state))
}

fn restore(state: &mut DeviceState, checkpoint: &[u8]) -> Result<(), LabError> {
    let mut restored: DeviceState = checked("state_decoding", serde_json::from_slice(checkpoint))?;
    restored.restore_provider()?;
    *state = restored;
    Ok(())
}

pub(super) fn process(state: &mut DeviceState) -> Result<Value, LabError> {
    ensure(
        !state.wire_sync.halted,
        "stream_conflict",
        "设备流已停止自动合并",
    )?;
    let work: Vec<_> = state
        .wire_sync
        .slots
        .iter()
        .filter(|(_, slot)| slot.result.is_none() || slot.waiting)
        .map(|(seq, slot)| (*seq, slot.slot.clone()))
        .collect();
    let mut results = Vec::new();
    for (seq, slot) in work {
        let backup = checkpoint(state)?;
        let outcome = if slot.availability != Availability::Available {
            Ok(json!({"status":"unavailable","availability":slot.availability}))
        } else {
            match slot.event.clone().ok_or_else(|| LabError::new("invalid_envelope", "事件缺少载荷"))? {
                Event::Message { acceptance_id, envelope, acceptance_receipt } => wire::receive(state, envelope, Some(acceptance_id.clone()), acceptance_receipt).map(|result|
                    json!({"status":"valid","acceptance_id":acceptance_id,"event_id":slot.event_id,"message":result})),
                Event::CryptoControl { control } => apply_dependency(state, control),
                Event::Delivery { .. } | Event::Read { .. } => Ok(json!({"status":"receipt_recorded"})),
                Event::MessageAvailability { .. } => Ok(json!({"status":"availability_recorded"})),
            }
        };
        let (result, waiting) = match outcome {
            Ok(result) => (result, false),
            Err(error) => {
                restore(state, &backup)?;
                // 容量不足不是密文失败。整个调用不提交，让原始事件仍可恢复处理。
                if error.code == "resource_exhausted" {
                    return Err(error);
                }
                let waiting = matches!(error.code, "missing_crypto_state" | "trust_required");
                (
                    json!({"status":if waiting {"waiting_dependency"} else {"quarantined"},"code":error.code}),
                    waiting,
                )
            }
        };
        let saved = state
            .wire_sync
            .slots
            .get_mut(&seq)
            .ok_or_else(|| LabError::new("state_conflict", "待处理事件丢失"))?;
        saved.result = Some(result.clone());
        saved.waiting = waiting;
        results.push(json!({"event_seq":seq.to_string(),"event_id":slot.event_id,"result":result}));
    }
    while state.wire_sync.processed_cursor < state.wire_sync.download_cursor {
        let next = state.wire_sync.processed_cursor + 1;
        if state
            .wire_sync
            .slots
            .get(&next)
            .is_some_and(|slot| slot.result.is_some() && !slot.waiting)
        {
            state.wire_sync.processed_cursor = next;
        } else {
            break;
        }
    }
    // 保留可重复报告的成功结果；报告响应丢失或进程重启后不依赖临时输出恢复。
    let deliveries: Vec<_> = state
        .wire_sync
        .slots
        .values()
        .filter_map(|slot| {
            let result = slot.result.as_ref()?;
            (result["status"] == "valid").then(|| {
                json!({"acceptance_id":result["acceptance_id"],
            "attempt_id":result["message"]["attempt_id"],"event_id":result["event_id"]})
            })
        })
        .collect();
    let confirmed = super::wire_read::reconcile(state)?;
    let mut result =
        json!({"results":results,"deliveries":deliveries,"sync":state.wire_sync.summary()});
    if state.wire_reads.is_some() {
        result["read_confirmed_count"] = json!(confirmed);
    }
    Ok(result)
}

pub(super) fn apply_dependency(
    state: &mut DeviceState,
    control: Control,
) -> Result<Value, LabError> {
    ensure(
        state.permissions.checkpoint.is_none(),
        "signed_permission_required",
        "签名权限模式不接受无签名控制依赖",
    )?;
    validate_control(&control)?;
    if let Some(old) = state.wire_sync.applied_controls.get(&control.control_id) {
        ensure(
            *old == control,
            "state_conflict",
            "相同控制 ID 对应不同内容",
        )?;
        return Ok(
            json!({"status":"control_applied","duplicate":true,"control_id":control.control_id}),
        );
    }
    let raw = bytes(&control.payload_bytes, 512 * 1024)?;
    let cache_bytes: usize = state
        .wire_sync
        .applied_controls
        .values()
        .map(|entry| entry.payload_bytes.len())
        .sum();
    ensure(
        cache_bytes + control.payload_bytes.len() <= 4 * 1024 * 1024
            && state.wire_sync.applied_controls.len() < 4096,
        "resource_exhausted",
        "独立控制缓存已满",
    )?;
    let group = state.group()?;
    ensure(
        wire::state_ref(&group)? == control.from_state_ref,
        "missing_crypto_state",
        "控制记录前序状态不一致",
    )?;
    groups::apply_commit(state, &codec::encode(&raw))?;
    ensure(
        wire::state_ref(&state.group()?)? == control.to_state_ref,
        "state_conflict",
        "Commit 验证后的状态与后继引用不一致",
    )?;
    let result =
        json!({"status":"control_applied","duplicate":false,"control_id":control.control_id});
    state
        .wire_sync
        .applied_controls
        .insert(control.control_id.clone(), control);
    Ok(result)
}
