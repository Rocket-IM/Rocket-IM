//! 拒绝原件与权限补齐检查；只读既有已验证引用，不依据 Service 声明伪造检查点。
use super::{
    checked, ensure,
    state::DeviceState,
    wire_types::{self, Header},
    LabError,
};
use crate::{
    message_acceptance,
    message_rejection::{self, MessageRejectionStatement},
    permission::receipts::SignedRecord,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rejections {
    pub records: BTreeMap<String, SignedRecord>,
}

pub(super) fn receipt<'a>(state: &'a DeviceState, key: &str) -> Option<&'a SignedRecord> {
    state.wire_rejections.as_ref()?.records.get(key)
}
pub(super) fn verify_record(
    state: &DeviceState,
    key: &str,
    proof: &SignedRecord,
) -> Result<MessageRejectionStatement, LabError> {
    let original = state
        .wire
        .outbox
        .get(key)
        .ok_or_else(|| LabError::new("rejection_not_found", "本机没有该发送尝试"))?;
    let pin = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_ref()
        .ok_or_else(|| LabError::new("rejection_state", "拒绝缺少固定 Service 回执公钥"))?;
    let fact = message_rejection::verify(pin, proof)?;
    let raw = wire_types::bytes(&original.envelope.header_bytes, 16 * 1024)?;
    let payload = wire_types::bytes(&original.envelope.payload_bytes, 512 * 1024)?;
    let header = Header::parse(&raw)?;
    ensure(
        fact.service_id == header.service_id
            && fact.conversation_id == header.conversation_id
            && fact.sender.account_id == header.sender.account_id
            && fact.sender.device_id == header.sender.device_id
            && fact.logical_message_id == header.logical_message_id
            && fact.attempt_id == header.attempt_id
            && fact.envelope_sha256 == message_acceptance::envelope_digest(&raw, &payload)
            && fact.replaces_attempt_id == original.replaces_attempt_id
            && fact.predecessor_closure_id == original.closure_id
            && wire_types::decimal(&fact.required_authorization_version)?
                > wire_types::decimal(&header.authorization_version)?,
        "rejection_conflict",
        "拒绝未绑定精确原尝试、前驱或严格后继权限版本",
    )?;
    Ok(fact)
}

/// 已知版本不能接受另一个分支；未来未知的要求可以先存为未补齐事实。
pub(super) fn check_known(
    state: &DeviceState,
    fact: &MessageRejectionStatement,
) -> Result<(), LabError> {
    ensure(
        state
            .permissions
            .recovery
            .verified_refs
            .get(&fact.required_authorization_version)
            .is_none_or(|reference| reference == &fact.required_crypto_state_ref),
        "rejection_conflict",
        "拒绝所需检查点与本机已验证同版本引用冲突",
    )
}
pub(super) fn checkpoint_satisfied(
    state: &DeviceState,
    fact: &MessageRejectionStatement,
) -> Result<bool, LabError> {
    let current = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("rejection_state", "缺少当前权限检查点"))?;
    Ok(wire_types::decimal(&current.authorization_version)?
        >= wire_types::decimal(&fact.required_authorization_version)?
        && state
            .permissions
            .recovery
            .verified_refs
            .get(&fact.required_authorization_version)
            == Some(&fact.required_crypto_state_ref))
}

/// 已存在的后继也必须来自本机验证过的同一条权限链；加载前不恢复 provider。
pub(super) fn validate_successor(
    state: &DeviceState,
    fact: &MessageRejectionStatement,
    successor: &wire_types::Outbound,
) -> Result<(), LabError> {
    let raw = checked(
        "rejection_state",
        wire_types::bytes(&successor.envelope.header_bytes, 16 * 1024),
    )?;
    let header = checked("rejection_state", Header::parse(&raw))?;
    let current = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("rejection_state", "缺少当前权限检查点"))?;
    ensure(
        checkpoint_satisfied(state, fact)?
            && wire_types::decimal(&header.authorization_version)?
                >= wire_types::decimal(&fact.required_authorization_version)?
            && wire_types::decimal(&header.authorization_version)?
                <= wire_types::decimal(&current.authorization_version)?
            && state
                .permissions
                .recovery
                .verified_refs
                .get(&header.authorization_version)
                == Some(&header.crypto_state_ref),
        "rejection_state",
        "已存后继未经过拒绝要求的精确已验证权限链",
    )
}
