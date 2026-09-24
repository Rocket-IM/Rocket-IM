//! 接受事实只附在本机原尝试上；不重建密文、不改变尝试尾或密码状态。
use super::{
    checked, ensure,
    state::DeviceState,
    wire,
    wire_types::{self, Device, Header},
    LabError,
};
use crate::{message_acceptance, permission::receipts::SignedRecord};
use serde_json::{json, Value};

pub(super) fn accept(
    state: &mut DeviceState,
    message: String,
    attempt: String,
    receipt: SignedRecord,
) -> Result<Value, LabError> {
    wire_types::id(&message)?;
    wire_types::id(&attempt)?;
    let config = wire::configuration(state)?;
    let sender = Device {
        account_id: state.context.account.clone(),
        device_id: state.context.device.clone(),
    };
    let logical = wire_types::logical_key(
        &state.context.service,
        &config.conversation_id,
        &sender,
        &message,
    )?;
    let key = checked("key_encoding", serde_json::to_string(&(&logical, &attempt)))?;
    let original = state
        .wire
        .outbox
        .get(&key)
        .ok_or_else(|| LabError::new("attempt_not_found", "本机没有该发送尝试"))?;
    let raw = wire_types::bytes(&original.envelope.header_bytes, 16 * 1024)?;
    let ciphertext = wire_types::bytes(&original.envelope.payload_bytes, 512 * 1024)?;
    let header = Header::parse(&raw)?;
    let pin = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_ref()
        .ok_or_else(|| LabError::new("receipt_pin_required", "缺少固定Service回执钥"))?;
    let accepted = message_acceptance::verify(pin, &receipt)?;
    ensure(
        header.sender == sender
            && header.service_id == state.context.service
            && header.conversation_id == config.conversation_id
            && header.logical_message_id == message
            && header.attempt_id == attempt
            && header.attempt_key()? == key
            && original.logical_key == logical
            && original.attempt_id == attempt
            && accepted.service_id == header.service_id
            && accepted.conversation_id == header.conversation_id
            && accepted.authorization_version == header.authorization_version
            && accepted.crypto_state_ref == header.crypto_state_ref
            && accepted.envelope_sha256 == message_acceptance::envelope_digest(&raw, &ciphertext),
        "acceptance_conflict",
        "接受证明未绑定本机的精确原发送尝试",
    )?;
    ensure(
        super::wire_rejections::receipt(state, &key).is_none(),
        "rejection_conflict",
        "已拒绝尝试不能覆盖为接受",
    )?;
    ensure(
        super::wire_closures::receipt(state, &key).is_none(),
        "closure_conflict",
        "已封口尝试不能覆盖为接受",
    )?;
    // 已经有另一个尝试成功或同接受ID被复用时保留第一份事实，不能默默覆盖。
    for (other_key, other) in &state.wire.outbox {
        if let Some(saved) = &other.acceptance_receipt {
            let fact = message_acceptance::verify(pin, saved)?;
            ensure(
                other_key == &key
                    || (other.logical_key != logical
                        && fact.acceptance_id != accepted.acceptance_id),
                "acceptance_conflict",
                "接受证明与已保存的逻辑消息或接受ID冲突",
            )?;
        }
    }
    for inbound in state.wire.inbox.values() {
        ensure(
            inbound.acceptance_id.as_deref() != Some(accepted.acceptance_id.as_str()),
            "acceptance_conflict",
            "接受ID已属于其他本机收件",
        )?;
    }
    let duplicate = if let Some(saved) = &original.acceptance_receipt {
        ensure(
            *saved == receipt,
            "acceptance_conflict",
            "同尝试的原接受证明不能替换",
        )?;
        true
    } else {
        false
    };
    let result = json!({"logical_message_id":message,"attempt_id":attempt,"acceptance_id":accepted.acceptance_id,"status":"accepted","duplicate":duplicate});
    if !duplicate {
        state
            .wire
            .outbox
            .get_mut(&key)
            .ok_or_else(|| LabError::new("attempt_not_found", "缺少原尝试"))?
            .acceptance_receipt = Some(receipt);
    }
    Ok(result)
}
