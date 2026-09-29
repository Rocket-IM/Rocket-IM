//! Service 签页内的消息终态先于处理生效；保留已验证正文副本与原成功事实。

use super::{
    ensure,
    state::DeviceState,
    wire_sync_types::{Availability, Event, Slot},
    wire_types::{bytes, decimal, Header},
    LabError,
};
use std::collections::BTreeMap;

#[derive(PartialEq, Eq)]
struct Claim<'a> {
    stream_id: &'a str,
    event_id: &'a str,
    acceptance_id: &'a str,
    attempt_id: &'a str,
    availability: Availability,
}

pub(super) struct Plan(BTreeMap<u64, Availability>);

pub(super) fn require_source(incoming: &[Slot], verified: bool) -> Result<(), LabError> {
    ensure(
        verified
            || !incoming
                .iter()
                .any(|slot| matches!(slot.event, Some(Event::MessageAvailability { .. }))),
        "stream_source_required",
        "消息生命周期声明必须来自本次已验证的签名分页",
    )
}

pub(super) fn plan(state: &DeviceState, incoming: &[Slot]) -> Result<Plan, LabError> {
    let mut claims = BTreeMap::new();
    // 已保存通知保留无正文目标的绑定，并阻止后来的投影改写已知终态。
    for slot in state
        .wire_sync
        .slots
        .values()
        .map(|s| &s.slot)
        .chain(incoming)
    {
        let Some(Event::MessageAvailability {
            target_event_seq,
            target_event_id,
            acceptance_id,
            attempt_id,
            availability,
        }) = &slot.event
        else {
            continue;
        };
        let target = decimal(target_event_seq)?;
        ensure(
            target > 0
                && target < decimal(&slot.event_seq)?
                && matches!(availability, Availability::Deleted | Availability::Expired),
            "lifecycle_target_invalid",
            "生命周期目标必须先于声明且终态必须是删除或到期",
        )?;
        let claim = Claim {
            stream_id: &slot.stream_id,
            event_id: target_event_id,
            acceptance_id,
            attempt_id,
            availability: *availability,
        };
        if let Some(original) = claims.get(&target) {
            ensure(
                *original == claim,
                "lifecycle_target_invalid",
                "同一目标的生命周期绑定或终态冲突",
            )?;
        } else {
            claims.insert(target, claim);
        }
    }
    let mut changes = BTreeMap::new();
    for (seq, claim) in claims {
        let old = state.wire_sync.slots.get(&seq).map(|s| &s.slot);
        let sequence = seq.to_string();
        let projected = incoming.iter().find(|slot| slot.event_seq == sequence);
        let target = old
            .or(projected)
            .ok_or_else(|| LabError::new("lifecycle_target_invalid", "生命周期目标槽尚未下载"))?;
        // 同页的不可用投影不能遮蔽已保存原消息的接受 ID 或尝试绑定。
        for candidate in [old, projected].into_iter().flatten() {
            ensure(
                candidate.stream_id == claim.stream_id
                    && candidate.event_id == claim.event_id
                    && (candidate.availability == Availability::Available
                        || candidate.availability == claim.availability),
                "lifecycle_target_invalid",
                "生命周期目标 ID 或已有终态不一致",
            )?;
        }
        match &target.event {
            Some(Event::Message {
                acceptance_id,
                envelope,
                ..
            }) => {
                let header = Header::parse(&bytes(&envelope.header_bytes, 16 * 1024)?)?;
                ensure(
                    acceptance_id == claim.acceptance_id && header.attempt_id == claim.attempt_id,
                    "lifecycle_target_invalid",
                    "生命周期声明未绑定原消息接受记录与尝试",
                )?;
            }
            // 首次下载已经不可用的槽没有原正文头，只能信任已验证的 Service 声明。
            None if target.availability != Availability::Available => {
                if let Some(fact) = state
                    .wire_reclamation
                    .as_ref()
                    .and_then(|r| r.slots.get(&seq))
                {
                    let message = super::wire_reclaimed::acceptance(state, &fact.acceptance_id)
                        .ok_or_else(|| {
                            LabError::new("lifecycle_target_invalid", "紧凑目标缺少消息事实")
                        })?;
                    ensure(
                        fact.kind == "message"
                            && fact.acceptance_id == claim.acceptance_id
                            && message.attempt_id == claim.attempt_id
                            && message.availability == claim.availability,
                        "lifecycle_target_invalid",
                        "生命周期声明与已回收消息绑定冲突",
                    )?;
                }
            }
            _ => {
                return Err(LabError::new(
                    "lifecycle_target_invalid",
                    "回执、控制或生命周期槽不能作为消息目标",
                ))
            }
        }
        changes.insert(seq, claim.availability);
    }
    Ok(Plan(changes))
}

pub(super) fn apply(state: &mut DeviceState, plan: Plan) -> Result<(), LabError> {
    for (seq, availability) in plan.0 {
        let stored = state
            .wire_sync
            .slots
            .get_mut(&seq)
            .ok_or_else(|| LabError::new("state_conflict", "已验证的生命周期目标合并后消失"))?;
        stored.slot.availability = availability;
        // result、waiting、原事件与 inbox 均保留；下一次处理只结算未完成目标。
    }
    Ok(())
}
