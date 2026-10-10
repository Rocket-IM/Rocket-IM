//! 仅相关的已验签处理槽证明旧P不可能被确认；全流水位、超时都不够。
use super::{
    codec, state::DeviceState, wire_reclaim, wire_reclaim_preparation::Confirm,
    wire_sync_types::Event, wire_types, LabError,
};
use serde_json::{json, Value};

pub(super) fn evidence(state: &DeviceState, request: &Confirm) -> Result<Option<Value>, LabError> {
    let previous = wire_types::decimal(&request.processed_seq)?;
    if !state.wire_sync.source_verified || state.wire_sync.processed_cursor <= previous {
        return Ok(None);
    }
    for (seq, stored) in state.wire_sync.slots.range((previous + 1)..) {
        if *seq > state.wire_sync.processed_cursor
            || stored.slot.stream_id != request.stream_id
            || wire_types::decimal(&stored.slot.event_seq)? != *seq
        {
            continue;
        }
        // Relay首次确认会冻结选择并禁止新增相关回执；因此原P之后的此事实
        // 证明原请求从未满足处理前缀，迟到原请求也不能再获准。
        let event = super::wire_terminal_reference::processed_receipt(stored);
        let Some(
            Event::Delivery {
                acceptance_id,
                attempt_id,
                device,
            }
            | Event::Read {
                acceptance_id,
                attempt_id,
                device,
            },
        ) = event
        else {
            continue;
        };
        if !request.acceptance_ids.contains(acceptance_id) {
            continue;
        }
        // 再核对原信封的尝试与完整目标；其他尝试、伪造设备名称不构成关联证据。
        let candidate = wire_reclaim::candidate(state, acceptance_id, &request.plan_id, None)?;
        let header =
            wire_types::Header::parse(&wire_types::bytes(&candidate.header_bytes, 16 * 1024)?)?;
        if header.attempt_id != *attempt_id || !header.recipients.contains(device) {
            continue;
        }
        return Ok(Some(
            json!({"event_seq":seq.to_string(),"event_id":stored.slot.event_id,
            "acceptance_id":acceptance_id}),
        ));
    }
    Ok(None)
}

pub(super) fn describe(result: &mut Value, previous: &Confirm, raw: &str, evidence: Value) {
    result["reprepared"] = json!(true);
    result["previous_processed_seq"] = json!(previous.processed_seq);
    result["previous_request_sha256"] = json!(codec::digest_hex(&codec::digest(raw.as_bytes())));
    result["evidence"] = evidence;
}
