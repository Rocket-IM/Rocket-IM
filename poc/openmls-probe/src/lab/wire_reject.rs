//! 先持久保存真实拒绝，随后由原权限恢复路径补齐；不清队列、不创建密码消息。
use super::{
    checked, ensure, state::DeviceState, wire_closures, wire_rejections, wire_send_order, LabError,
};
use crate::permission::receipts::SignedRecord;
use serde_json::{json, Value};

pub(super) fn reject(
    state: &mut DeviceState,
    message: String,
    attempt: String,
    proof: SignedRecord,
) -> Result<Value, LabError> {
    if let Some(result) =
        super::wire_reclaimed::terminal(state, &message, &attempt, &proof, "rejected")?
    {
        return Ok(result);
    }
    ensure(
        state.wire_send_order.is_some(),
        "rejection_required",
        "签名拒绝须先启用持久发送门",
    )?;
    let key = checked(
        "rejection_invalid",
        wire_closures::key(state, &message, &attempt),
    )?;
    let fact = wire_rejections::verify_record(state, &key, &proof)?;
    let original = state
        .wire
        .outbox
        .get(&key)
        .ok_or_else(|| LabError::new("rejection_not_found", "本机没有该发送尝试"))?;
    ensure(
        original.acceptance_receipt.is_none() && wire_closures::receipt(state, &key).is_none(),
        "rejection_conflict",
        "已接受或主动封口的尝试不能覆盖为拒绝",
    )?;
    let duplicate = if let Some(saved) = wire_rejections::receipt(state, &key) {
        ensure(saved == &proof, "rejection_conflict", "原拒绝证明不能替换")?;
        true
    } else {
        ensure(
            state.wire.tails.get(&original.logical_key) == Some(&key),
            "rejection_conflict",
            "只能首次拒绝当前尾尝试",
        )?;
        wire_rejections::check_known(state, &fact)?;
        false
    };
    if !duplicate {
        state
            .wire_rejections
            .get_or_insert_with(Default::default)
            .records
            .insert(key, proof);
        checked("rejection_conflict", wire_closures::validate(state))?;
    }
    Ok(
        json!({"logical_message_id":message,"attempt_id":attempt,"closure_id":fact.closure_id,
        "status":"rejected","outcome":fact.outcome,"code":fact.code,"duplicate":duplicate,"send_order":wire_send_order::summary(state)?}),
    )
}
