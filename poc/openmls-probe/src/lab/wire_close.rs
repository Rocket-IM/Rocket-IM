//! 只导出原请求、核验真实签名并落盘；不能以未签名 closure_id 消费发送槽。
use super::{
    checked, ensure, state::DeviceState, wire_closures, wire_send_order, wire_types, LabError,
};
use crate::{message_acceptance, permission::receipts::SignedRecord};
use serde_json::{json, Value};

fn enabled(state: &DeviceState) -> Result<(), LabError> {
    ensure(
        state.wire_send_order.is_some(),
        "closure_required",
        "签名封口须先启用持久发送门",
    )
}

pub(super) fn request(
    state: &DeviceState,
    message: String,
    attempt: String,
) -> Result<Value, LabError> {
    enabled(state)?;
    if let Some(result) = super::wire_reclaimed::close_request(state, &message, &attempt)? {
        return Ok(result);
    }
    let key = wire_closures::key(state, &message, &attempt)?;
    ensure(
        super::wire_rejections::receipt(state, &key).is_none(),
        "rejection_conflict",
        "已拒绝尝试不能主动封口",
    )?;
    let original = state
        .wire
        .outbox
        .get(&key)
        .ok_or_else(|| LabError::new("closure_not_found", "本机没有该发送尝试"))?;
    ensure(
        original.acceptance_receipt.is_none(),
        "closure_conflict",
        "已接受尝试不能封口",
    )?;
    let raw = wire_types::bytes(&original.envelope.header_bytes, 16 * 1024)?;
    let payload = wire_types::bytes(&original.envelope.payload_bytes, 512 * 1024)?;
    let header = wire_types::Header::parse(&raw)?;
    let mut result = json!({"service_id":header.service_id,"conversation_id":header.conversation_id,
        "logical_message_id":message,"attempt_id":attempt,
        "envelope_sha256":message_acceptance::envelope_digest(&raw,&payload)});
    if let (Some(previous), Some(closure)) = (&original.replaces_attempt_id, &original.closure_id) {
        result["replaces_attempt_id"] = json!(previous);
        result["closure_id"] = json!(closure);
    }
    Ok(result)
}

pub(super) fn close(
    state: &mut DeviceState,
    message: String,
    attempt: String,
    proof: SignedRecord,
) -> Result<Value, LabError> {
    enabled(state)?;
    if let Some(result) =
        super::wire_reclaimed::terminal(state, &message, &attempt, &proof, "closed")?
    {
        return Ok(result);
    }
    let key = wire_closures::key(state, &message, &attempt)?;
    let fact = wire_closures::verify_record(state, &key, &proof)?;
    ensure(
        super::wire_rejections::receipt(state, &key).is_none(),
        "rejection_conflict",
        "已拒绝尝试不能主动封口",
    )?;
    let original = state
        .wire
        .outbox
        .get(&key)
        .ok_or_else(|| LabError::new("closure_not_found", "本机没有该发送尝试"))?;
    ensure(
        original.acceptance_receipt.is_none(),
        "closure_conflict",
        "已接受尝试不能覆盖为封口",
    )?;
    let duplicate = if let Some(saved) = wire_closures::receipt(state, &key) {
        ensure(saved == &proof, "closure_conflict", "原封口证明不能替换")?;
        true
    } else {
        ensure(
            state.wire.tails.get(&original.logical_key) == Some(&key),
            "closure_conflict",
            "只能首次封口当前尾尝试",
        )?;
        false
    };
    if !duplicate {
        state
            .wire_closures
            .get_or_insert_with(Default::default)
            .records
            .insert(key, proof);
        checked("closure_state", wire_closures::validate(state))?;
    }
    Ok(
        json!({"logical_message_id":message,"attempt_id":attempt,"closure_id":fact.closure_id,
        "status":"closed","outcome":fact.outcome,"duplicate":duplicate,"send_order":wire_send_order::summary(state)?}),
    )
}
