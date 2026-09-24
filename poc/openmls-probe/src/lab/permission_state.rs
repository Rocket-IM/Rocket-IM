//! 签名权限状态随设备加密快照保存；候选仅保存密码存储，不复制消息队列。

use super::{checked, codec, ensure, groups, state::DeviceState, wire, LabError};
use crate::permission::{Member, PermissionCheckpoint, Proof};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

type ProviderEntries = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Serialize, Deserialize)]
pub(super) struct Pending {
    pub change: Proof,
    pub candidate_entries: ProviderEntries,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct PermissionState {
    pub checkpoint: Option<PermissionCheckpoint>,
    pub pending: Option<Pending>,
    pub applied: BTreeMap<String, Proof>,
    pub used_nonces: BTreeSet<String>,
    #[serde(default)]
    pub recovery: super::recovery_state::RecoveryState,
    #[serde(default)]
    pub history: super::wire_history::History,
    #[serde(default)]
    pub admission: super::permission_admission::AdmissionState,
    #[serde(default)]
    pub consistency: super::consistency_state::ConsistencyState,
    #[serde(default)]
    pub exchange: super::exchange_state::ExchangeState,
}

pub(super) fn entries(provider: &OpenMlsRustCrypto) -> Result<ProviderEntries, LabError> {
    let values = provider
        .storage()
        .values
        .read()
        .map_err(|_| LabError::new("storage_lock", "密码存储锁失效"))?;
    let mut entries: Vec<_> = values
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

pub(super) fn provider_from(entries: &[(Vec<u8>, Vec<u8>)]) -> Result<OpenMlsRustCrypto, LabError> {
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider
            .storage()
            .values
            .write()
            .map_err(|_| LabError::new("storage_lock", "密码存储锁失效"))?;
        for (key, value) in entries {
            ensure(
                values.insert(key.clone(), value.clone()).is_none(),
                "permission_conflict",
                "候选密码存储出现重复键",
            )?;
        }
    }
    Ok(provider)
}

pub(super) fn group_from(
    state: &DeviceState,
    provider: &OpenMlsRustCrypto,
) -> Result<MlsGroup, LabError> {
    let id = state
        .group_id
        .as_ref()
        .ok_or_else(|| LabError::new("no_group", "尚未入群"))?;
    checked(
        "group_storage",
        MlsGroup::load(provider.storage(), &GroupId::from_slice(id)),
    )?
    .ok_or_else(|| LabError::new("missing_group", "缺少群状态"))
}

pub(super) fn actual_members(
    state: &DeviceState,
    group: &MlsGroup,
) -> Result<Vec<Member>, LabError> {
    groups::validate_members(state, group)?;
    decoded_members(state, group)
}

/// 仅解析实际 MLS 叶子；调用者必须与已验证前驱推导的精确后继成员集比较。
pub(super) fn decoded_members(
    state: &DeviceState,
    group: &MlsGroup,
) -> Result<Vec<Member>, LabError> {
    let mut members = group
        .members()
        .map(|member| {
            let identity = codec::credential_context(&member.credential)?;
            ensure(
                identity.service == state.context.service,
                "wrong_service",
                "MLS 叶子属于其他实例",
            )?;
            Ok(Member {
                account_id: identity.account,
                device_id: identity.device,
                signature_key: codec::encode(&member.signature_key),
            })
        })
        .collect::<Result<Vec<_>, LabError>>()?;
    members.sort_by_key(Member::identity);
    Ok(members)
}

pub(super) fn validate_current(
    state: &DeviceState,
    checkpoint: &PermissionCheckpoint,
    group: &MlsGroup,
) -> Result<(), LabError> {
    checkpoint.validate()?;
    ensure(
        checkpoint.service_id == state.context.service
            && checkpoint.crypto_state_ref == wire::state_ref(group)?
            && checkpoint.members == actual_members(state, group)?,
        "permission_context",
        "权限检查点与实际已验证 MLS 状态不同",
    )
}
