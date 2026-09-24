//! 只归档本机真实验证的公共检查点；消息秘密由同一个OpenMLS provider有界持有。
use super::{
    checked, ensure, permission_state,
    state::DeviceState,
    wire,
    wire_types::{Device, Header},
    LabError,
};
use crate::permission::PermissionCheckpoint;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) const PAST_EPOCHS: usize = 2;
#[derive(Default, Serialize, Deserialize)]
pub(super) struct History {
    pub past: BTreeMap<u64, PermissionCheckpoint>,
}

pub(super) fn enable(provider: &OpenMlsRustCrypto, group: &mut MlsGroup) -> Result<(), LabError> {
    if group.past_epoch_deletion_policy() != &PastEpochDeletionPolicy::MaxEpochs(PAST_EPOCHS) {
        checked(
            "history_storage",
            group.set_past_epoch_deletion_policy(
                provider,
                PastEpochDeletionPolicy::MaxEpochs(PAST_EPOCHS),
            ),
        )?;
    }
    Ok(())
}
pub(super) fn archive(
    state: &mut DeviceState,
    old_epoch: u64,
    old: PermissionCheckpoint,
    next: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
) -> Result<(), LabError> {
    // 旧pending可能已在MaxEpochs(0)下合并：不能仅升级配置就伪造其前驱历史。
    let retained =
        next.past_epoch_deletion_policy() == &PastEpochDeletionPolicy::MaxEpochs(PAST_EPOCHS);
    if state.permissions.recovery.relay_receipt_key.is_some() && retained {
        state.permissions.history.past.insert(old_epoch, old);
    } else {
        state.permissions.history.past.clear();
    }
    let current = next.epoch().as_u64();
    state.permissions.history.past.retain(|epoch, _| {
        *epoch < current && *epoch >= current.saturating_sub(PAST_EPOCHS as u64)
    });
    if state.permissions.recovery.relay_receipt_key.is_some() {
        enable(provider, next)
    } else {
        Ok(())
    }
}
pub(super) fn summary(state: &DeviceState) -> Value {
    let past:Vec<_>=state.permissions.history.past.iter().map(|(epoch,cp)|json!({"epoch":epoch.to_string(),"authorization_version":cp.authorization_version,"crypto_state_ref":cp.crypto_state_ref})).collect();
    json!({"retained_epoch_limit":PAST_EPOCHS,"past_epochs":past})
}
pub(super) fn current_identity(state: &DeviceState, header: &Header) -> Result<(), LabError> {
    if state.permissions.recovery.relay_receipt_key.is_none() {
        return Ok(());
    }
    let cp = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "缺少当前权限检查点"))?;
    ensure(
        cp.members.iter().any(|m| {
            m.account_id == header.sender.account_id && m.device_id == header.sender.device_id
        }),
        "history_sender_revoked",
        "发送设备已不在当前权限检查点",
    )?;
    ensure(
        cp.members
            .iter()
            .any(|m| m.account_id == state.context.account && m.device_id == state.context.device),
        "access_removed",
        "接收设备已不在当前权限检查点",
    )
}
pub(super) fn recipients(
    state: &DeviceState,
    group: &MlsGroup,
    header: &Header,
    epoch: u64,
    has_receipt: bool,
) -> Result<Vec<Device>, LabError> {
    if epoch == group.epoch().as_u64() {
        let config = state
            .wire
            .configuration
            .as_ref()
            .ok_or_else(|| LabError::new("trust_required", "缺少当前会话"))?;
        ensure(
            header.crypto_state_ref == wire::state_ref(group)?
                && header.authorization_version == config.authorization_version,
            "state_context_mismatch",
            "消息epoch与头中权限/密码引用不符",
        )?;
        return wire::members(state, group);
    }
    ensure(
        state.permissions.recovery.relay_receipt_key.is_some() && has_receipt,
        "historical_acceptance_required",
        "首次接收历史消息需要固定Service钥及精确接受回执",
    )?;
    let current = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "缺少当前权限检查点"))?;
    permission_state::validate_current(state, current, group)?;
    let old = state.permissions.history.past.get(&epoch).ok_or_else(|| {
        LabError::new(
            "history_unavailable",
            "缺少本机已验证历史或已超两个epoch保留范围",
        )
    })?;
    ensure(
        old.authorization_version == header.authorization_version
            && old.crypto_state_ref == header.crypto_state_ref
            && old.service_id == header.service_id
            && old.conversation_id == header.conversation_id,
        "history_context_mismatch",
        "历史头与实际已验证检查点不符",
    )?;
    for (account, device, code) in [
        (
            &header.sender.account_id,
            &header.sender.device_id,
            "history_sender_revoked",
        ),
        (
            &state.context.account,
            &state.context.device,
            "access_removed",
        ),
    ] {
        let historical = old
            .members
            .iter()
            .find(|m| m.account_id == *account && m.device_id == *device)
            .ok_or_else(|| LabError::new("identity_mismatch", "设备不属于历史检查点"))?;
        ensure(
            current.members.iter().any(|m| {
                m.account_id == *account
                    && m.device_id == *device
                    && m.signature_key == historical.signature_key
            }),
            code,
            "历史设备与当前可信公钥不同",
        )?;
    }
    Ok(old
        .members
        .iter()
        .map(|m| Device {
            account_id: m.account_id.clone(),
            device_id: m.device_id.clone(),
        })
        .collect())
}
