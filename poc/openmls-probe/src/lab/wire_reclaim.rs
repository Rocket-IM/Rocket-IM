//! 显式回收先验证整批候选；许可不替代本机收件、阅读和迁移依赖检查。
use super::{
    checked, codec, ensure,
    state::DeviceState,
    wire_reclaim_types as compact,
    wire_sync_types::{Availability, Event},
    wire_types::{self, Header},
    LabError,
};
use crate::{message_acceptance, message_reclamation, permission::receipts::SignedRecord};
use serde_json::{json, Value};

pub(super) fn source(state: &DeviceState) -> Result<(&str, &str), LabError> {
    ensure(
        state.rebuild.is_none() && state.wire_sync.source_verified && !state.wire_sync.halted,
        "reclaim_source_required",
        "回收仅支持已验证且未停止的普通设备流",
    )?;
    ensure(
        state.permissions.pending.is_none() && state.permissions.recovery.intent.is_none(),
        "reclaim_dependency",
        "权限恢复尚未完成，不能回收",
    )?;
    let pin = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_deref()
        .ok_or_else(|| LabError::new("reclaim_source_required", "缺少固定Service回执钥"))?;
    let stream = state
        .wire_sync
        .stream_id
        .as_deref()
        .ok_or_else(|| LabError::new("reclaim_source_required", "缺少普通设备流"))?;
    Ok((pin, stream))
}

pub(super) fn selection(ids: &[String]) -> Result<(), LabError> {
    ensure(
        !ids.is_empty()
            && ids.len() <= message_reclamation::MAX_MESSAGES
            && ids.windows(2).all(|p| p[0] < p[1]),
        "reclaim_invalid",
        "回收选择必须为排序唯一的1—16个接受ID",
    )?;
    for id in ids {
        wire_types::id(id)?;
    }
    Ok(())
}

pub(super) fn history_unused(state: &DeviceState, id: &str) -> Result<(), LabError> {
    for request in state
        .history_transfers
        .requests
        .values()
        .map(|r| &r.request)
        .chain(state.history_transfers.exports.values().map(|r| &r.request))
    {
        let raw = codec::decode(&request.statement_bytes)?;
        let parsed: crate::history_transfer::RequestStatement =
            checked("reclaim_state", serde_json::from_slice(&raw))?;
        ensure(
            !parsed.selection.iter().any(|s| s.acceptance_id == id),
            "reclaim_dependency",
            "选中内容曾参与历史迁移，首轮不能回收",
        )?;
    }
    let (pin, _) = source(state)?;
    for copy in state.history_transfers.copies.values() {
        ensure(
            message_acceptance::verify(pin, &copy.copy.acceptance_receipt)?.acceptance_id != id,
            "reclaim_dependency",
            "选中内容存在历史副本",
        )?;
    }
    ensure(
        state
            .wire_reads
            .as_ref()
            .is_none_or(|r| r.records.get(id).is_none_or(|r| r.confirmation.is_some())),
        "reclaim_dependency",
        "选中内容仍有待确认阅读",
    )
}

pub(super) fn candidate(
    state: &DeviceState,
    id: &str,
    plan_id: &str,
    permit: Option<&message_reclamation::Message>,
) -> Result<compact::Message, LabError> {
    let (pin, _) = source(state)?;
    history_unused(state, id)?;
    let incoming: Vec<_> = state
        .wire
        .inbox
        .values()
        .filter(|r| r.acceptance_id.as_deref() == Some(id))
        .collect();
    let mut outgoing = Vec::new();
    for original in state.wire.outbox.values() {
        if let Some(proof) = &original.acceptance_receipt {
            if message_acceptance::verify(pin, proof)?.acceptance_id == id {
                outgoing.push(original);
            }
        }
    }
    ensure(
        incoming.len() + outgoing.len() == 1,
        "reclaim_target_invalid",
        "回收目标必须唯一对应实际已接受原件",
    )?;
    let (envelope, payload, proof, mut availability) = if let Some(original) = incoming.first() {
        let body = original
            .payload
            .as_ref()
            .ok_or_else(|| LabError::new("reclaim_target_invalid", "原收件正文缺失"))?;
        ensure(
            codec::digest(body.as_bytes()) == original.payload_digest,
            "reclaim_state",
            "原正文摘要不一致",
        )?;
        (
            &original.envelope,
            body,
            original.acceptance_receipt.as_ref(),
            None,
        )
    } else {
        let original = outgoing[0];
        (
            &original.envelope,
            &original.payload,
            original.acceptance_receipt.as_ref(),
            None,
        )
    };
    let proof = proof.ok_or_else(|| LabError::new("reclaim_target_invalid", "原件缺少接受证明"))?;
    let raw = wire_types::bytes(&envelope.header_bytes, 16 * 1024)?;
    let encrypted = wire_types::bytes(&envelope.payload_bytes, 512 * 1024)?;
    let header = Header::parse(&raw)?;
    let logical = header.logical_key()?;
    let digest = message_acceptance::envelope_digest(&raw, &encrypted);
    let accepted = message_acceptance::verify(pin, proof)?;
    ensure(
        accepted.acceptance_id == id
            && accepted.envelope_sha256 == digest
            && accepted.service_id == state.context.service
            && accepted.service_id == header.service_id
            && accepted.conversation_id == super::wire::configuration(state)?.conversation_id
            && accepted.conversation_id == header.conversation_id
            && accepted.authorization_version == header.authorization_version
            && accepted.crypto_state_ref == header.crypto_state_ref,
        "reclaim_target_invalid",
        "原接受证明与精确消息不符",
    )?;
    let mut message_slots = 0;
    let mut delivery_confirmed = false;
    for (seq, stored) in &state.wire_sync.slots {
        let event = stored
            .slot
            .event
            .as_ref()
            .or(stored.slot.terminal_reference.as_ref());
        let relevant = match event {
            Some(Event::Message { acceptance_id, .. })
            | Some(Event::Delivery { acceptance_id, .. })
            | Some(Event::Read { acceptance_id, .. })
            | Some(Event::MessageAvailability { acceptance_id, .. }) => acceptance_id == id,
            _ => false,
        };
        if !relevant {
            continue;
        }
        ensure(
            *seq <= state.wire_sync.processed_cursor && !stored.waiting && stored.result.is_some(),
            "reclaim_dependency",
            "目标仍有未完成流槽",
        )?;
        let result = stored
            .result
            .as_ref()
            .ok_or_else(|| LabError::new("reclaim_dependency", "缺少处理结果"))?;
        ensure(
            result["status"] != "quarantined" && result["status"] != "waiting_dependency",
            "reclaim_dependency",
            "目标存在隔离或等待",
        )?;
        match event {
            Some(Event::Message {
                envelope: original, ..
            }) => {
                ensure(
                    original == envelope
                        && result["status"] == "valid"
                        && matches!(
                            stored.slot.availability,
                            Availability::Deleted | Availability::Expired
                        ),
                    "reclaim_target_invalid",
                    "收件尚无已处理可信终态或原件不一致",
                )?;
                if let Some(old) = availability {
                    ensure(
                        old == stored.slot.availability,
                        "reclaim_state",
                        "目标终态不一致",
                    )?;
                }
                availability = Some(stored.slot.availability);
                message_slots += 1;
            }
            Some(Event::Delivery {
                attempt_id, device, ..
            }) if device.account_id == state.context.account
                && device.device_id == state.context.device
                && attempt_id == &header.attempt_id
                && header.recipients.contains(device) =>
            {
                delivery_confirmed |= super::wire_terminal_reference::processed_receipt(stored)
                    .is_some_and(|receipt| Some(receipt) == event);
            }
            _ => {}
        }
    }
    if !incoming.is_empty() {
        ensure(
            message_slots > 0 && delivery_confirmed,
            "reclaim_dependency",
            "收件缺少原终态消息槽或本设备已处理送达确认",
        )?;
    }
    if let Some(permit) = permit {
        let terminal = match permit.availability.as_str() {
            "deleted" => Availability::Deleted,
            "expired" => Availability::Expired,
            _ => return Err(LabError::new("reclaim_invalid", "许可不是终态")),
        };
        ensure(
            permit.acceptance_id == id
                && permit.envelope_sha256 == digest
                && permit.recipients.len() == header.recipients.len()
                && permit
                    .recipients
                    .iter()
                    .zip(&header.recipients)
                    .all(|(a, b)| a.account_id == b.account_id && a.device_id == b.device_id)
                && availability.is_none_or(|a| a == terminal),
            "reclaim_conflict",
            "许可未绑定原消息、完整目标或本机终态",
        )?;
        availability = Some(terminal);
    }
    let outbound = if outgoing.is_empty() {
        Vec::new()
    } else {
        ensure(
            header.sender.account_id == state.context.account
                && header.sender.device_id == state.context.device,
            "reclaim_target_invalid",
            "原发送范围不符",
        )?;
        super::wire_reclaim_compact::chain(state, &logical, &header.attempt_id)?
    };
    Ok(compact::Message {
        logical_key: logical,
        acceptance_id: id.into(),
        attempt_id: header.attempt_id,
        header_bytes: envelope.header_bytes.clone(),
        envelope_sha256: digest,
        payload_digest: codec::digest(payload.as_bytes()),
        acceptance_receipt: proof.clone(),
        availability: availability.unwrap_or(Availability::Deleted),
        plan_id: plan_id.into(),
        outbound,
    })
}

pub(super) fn request(
    state: &mut DeviceState,
    plan_id: String,
    acceptance_ids: Vec<String>,
) -> Result<Value, LabError> {
    super::wire_reclaim_preparation::prepare(state, plan_id, acceptance_ids)
}
pub(super) fn retention(
    state: &DeviceState,
    receipt: SignedRecord,
    after_seq: String,
    limit: String,
) -> Result<Value, LabError> {
    let (pin, stream) = source(state)?;
    let statement = message_reclamation::verify_retention(pin, &receipt)?;
    ensure(
        statement.service_id == state.context.service
            && statement.account_id == state.context.account
            && statement.device_id == state.context.device
            && statement.stream_id == stream
            && statement.after_seq == after_seq
            && statement.limit == limit
            && wire_types::decimal(&after_seq)? <= state.wire_sync.download_cursor,
        "retention_conflict",
        "设备流缺口证明与原请求或设备范围不符",
    )?;
    Ok(
        json!({"status":"recovery_required","floor":statement.floor,"watermark":statement.watermark,
        "sync":state.wire_sync.summary()}),
    )
}
pub(super) fn execute(state: &mut DeviceState, receipt: SignedRecord) -> Result<Value, LabError> {
    let (pin, stream) = source(state)?;
    let statement = message_reclamation::verify(pin, &receipt)?;
    ensure(
        statement.service_id == state.context.service
            && statement.account_id == state.context.account
            && statement.device_id == state.context.device
            && statement.stream_id == stream
            && statement.conversation_id == super::wire::configuration(state)?.conversation_id
            && wire_types::decimal(&statement.processed_seq)? <= state.wire_sync.processed_cursor,
        "reclaim_conflict",
        "回收许可范围或持久处理前缀不符",
    )?;
    if let Some(saved) = state
        .wire_reclamation
        .as_ref()
        .and_then(|r| r.plans.get(&statement.plan_id))
    {
        ensure(
            saved.receipt == receipt,
            "reclaim_conflict",
            "原计划ID或许可不能替换",
        )?;
        let mut result = saved.result.clone();
        result["duplicate"] = json!(true);
        return Ok(result);
    }
    super::wire_reclaim_preparation::permit(state, &statement)?;
    let mut candidates = Vec::new();
    for permit in &statement.messages {
        candidates.push(candidate(
            state,
            &permit.acceptance_id,
            &statement.plan_id,
            Some(permit),
        )?);
    }
    let result = json!({"status":"reclaimed","plan_id":statement.plan_id,"reclaimed_count":candidates.len(),"duplicate":false,
        "finish_request":{"service_id":statement.service_id,"conversation_id":statement.conversation_id,
            "plan_id":statement.plan_id,"receipt":receipt}});
    super::wire_reclaim_compact::apply(
        state,
        candidates,
        statement.plan_id,
        receipt,
        result.clone(),
    )?;
    Ok(result)
}
