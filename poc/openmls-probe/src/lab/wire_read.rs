//! 显式阅读只建持久待报；服务确认只能来自原签页处理后的本设备 Read 事件。
use super::{
    checked, ensure,
    state::DeviceState,
    wire_reads::{self, Confirmation, Intent, Target},
    wire_sync_types::Availability,
    wire_types, LabError,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn counts(state: &DeviceState) -> (usize, usize) {
    state.wire_reads.as_ref().map_or((0, 0), |reads| {
        let confirmed = reads
            .records
            .values()
            .filter(|record| record.confirmation.is_some())
            .count();
        (reads.records.len() - confirmed, confirmed)
    })
}
pub(super) fn mark(state: &mut DeviceState, event_ids: Vec<String>) -> Result<Value, LabError> {
    ensure(
        !state.wire_sync.halted,
        "stream_conflict",
        "设备流已停止，不能新增阅读意图",
    )?;
    wire_reads::source(state)?;
    ensure(
        (1..=100).contains(&event_ids.len()),
        "read_invalid",
        "一次阅读必须明确选择 1—100 个消息事件",
    )?;
    let mut unique = BTreeSet::new();
    let mut targets: BTreeMap<String, Target> = BTreeMap::new();
    // 全部目标先验证，任一错误不允许先写入批次的一部分。
    for id in event_ids {
        checked("read_invalid", wire_types::id(&id))?;
        ensure(
            unique.insert(id.clone()),
            "read_invalid",
            "同批消息事件不能重复",
        )?;
        if let Some(target) = super::wire_reclaimed::read_target(state, &id)? {
            let original = state
                .wire_reads
                .as_ref()
                .and_then(|r| r.records.get(&target.acceptance_id))
                .ok_or_else(|| LabError::new("payload_reclaimed", "已回收正文不能首次阅读"))?;
            ensure(
                wire_reads::same_message(&original.target, &target)
                    && original.confirmation.is_some(),
                "read_state",
                "紧凑阅读事实不一致",
            )?;
            targets.insert(target.acceptance_id.clone(), target);
            continue;
        }
        let (stored, target) = wire_reads::message(state, &id)?;
        let saved = state
            .wire_reads
            .as_ref()
            .and_then(|reads| reads.records.get(&target.acceptance_id));
        if let Some(original) = saved {
            ensure(
                wire_reads::same_message(&original.target, &target),
                "read_target_invalid",
                "同接受 ID 对应另一阅读消息",
            )?;
        } else {
            ensure(
                stored.slot.availability == Availability::Available,
                "read_target_invalid",
                "首次阅读目标当前不可用",
            )?;
        }
        if let Some(previous) = targets.get(&target.acceptance_id) {
            ensure(
                wire_reads::same_message(previous, &target),
                "read_target_invalid",
                "批次接受 ID 存在冲突",
            )?;
        } else {
            targets.insert(target.acceptance_id.clone(), target);
        }
    }
    let existing = state.wire_reads.as_ref();
    let duplicate = targets
        .keys()
        .filter(|key| existing.is_some_and(|reads| reads.records.contains_key(*key)))
        .count();
    let marked = targets.len() - duplicate;
    ensure(
        existing.map_or(0, |reads| reads.records.len()) + marked <= wire_reads::LIMIT,
        "resource_exhausted",
        "阅读记录达到槽位上限",
    )?;
    if marked > 0 {
        let reads = state.wire_reads.get_or_insert_with(Default::default);
        for (key, target) in targets {
            reads.records.entry(key).or_insert(Intent {
                target,
                confirmation: None,
            });
        }
    }
    let (pending_count, confirmed_count) = counts(state);
    Ok(
        json!({"marked_count":marked,"duplicate_count":duplicate,"pending_count":pending_count,"confirmed_count":confirmed_count}),
    )
}
pub(super) fn pending(state: &DeviceState) -> Value {
    let (pending_count, _) = counts(state);
    let ids: Vec<_> = state
        .wire_reads
        .iter()
        .flat_map(|reads| &reads.records)
        .filter(|(_, record)| record.confirmation.is_none())
        .take(100)
        .map(|(id, _)| id)
        .collect();
    let request =
        (!ids.is_empty()).then(|| json!({"service_id":state.context.service,"acceptance_ids":ids}));
    json!({"request":request,"pending_count":pending_count,"has_more":pending_count>100})
}
pub(super) fn inspect(state: &DeviceState) -> Value {
    let (pending_count, confirmed_count) = counts(state);
    let records:Vec<_>=state.wire_reads.iter().flat_map(|reads|reads.records.values()).map(|record| {
        let target=&record.target;
        json!({"service_id":target.service_id,"conversation_id":target.conversation_id,
            "account_id":target.account_id,"device_id":target.device_id,"stream_id":target.stream_id,
            "message_event_id":target.message_event_id,"message_event_seq":target.message_event_seq,
            "acceptance_id":target.acceptance_id,"attempt_id":target.attempt_id,
            "status":if record.confirmation.is_some(){"confirmed"}else{"pending"},"confirmation":record.confirmation})
    }).collect();
    json!({"pending_count":pending_count,"confirmed_count":confirmed_count,"records":records})
}

pub(super) fn reconcile(state: &mut DeviceState) -> Result<usize, LabError> {
    let Some(reads) = &state.wire_reads else {
        return Ok(0);
    };
    wire_reads::source(state)?;
    let mut completed = Vec::new();
    for (key, intent) in &reads.records {
        if intent.confirmation.is_some() {
            continue;
        }
        if let Some((_, stored)) = state
            .wire_sync
            .slots
            .iter()
            .find(|(_, stored)| wire_reads::confirms(state, stored, &intent.target))
        {
            completed.push((
                key.clone(),
                Confirmation {
                    event_id: stored.slot.event_id.clone(),
                    event_seq: stored.slot.event_seq.clone(),
                },
            ));
        }
    }
    let count = completed.len();
    if let Some(reads) = &mut state.wire_reads {
        for (key, confirmation) in completed {
            reads
                .records
                .get_mut(&key)
                .ok_or_else(|| LabError::new("read_state", "确认前阅读意图消失"))?
                .confirmation = Some(confirmation);
        }
    }
    Ok(count)
}
