//! 核验账本与原密码状态共同保存；旧字段缺失不授予核验。
use super::{checked, codec, ensure, state::DeviceState, LabError};
use crate::{
    consistency_exchange::Verification, identity_trust::DeviceIdentity, permission::Identity,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const RECORD_LIMIT: usize = 128;
pub(super) const RETIRED_LIMIT: usize = 1024;
pub(super) const BYTE_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub version: u32,
    pub records: BTreeMap<String, Record>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Unverified,
    Verified,
    Changed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum History {
    Unknown,
    Gap,
    Reset,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fact {
    pub verification: Verification,
    pub confirmation_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retired {
    pub identity: DeviceIdentity,
    pub verification: Option<Fact>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub identity: DeviceIdentity,
    pub candidate: Option<DeviceIdentity>,
    pub revision: String,
    pub status: Status,
    pub history: History,
    pub verification: Option<Fact>,
    pub retired: Vec<Retired>,
    pub last_reset: Option<String>,
}

pub(super) fn own(state: &DeviceState) -> DeviceIdentity {
    object(
        &state.context.service,
        &state.context.account,
        &state.context.device,
        &codec::encode(&state.own_signature_key),
    )
}
pub(super) fn object(service: &str, account: &str, device: &str, key: &str) -> DeviceIdentity {
    DeviceIdentity {
        protocol_version: "rim-device-identity-1".into(),
        service_id: service.into(),
        account_id: account.into(),
        device_id: device.into(),
        signature_key: key.into(),
    }
}
pub(super) fn key(target: &Identity) -> Result<String, LabError> {
    for value in [&target.account_id, &target.device_id] {
        super::wire_types::id(value)
            .map_err(|_| LabError::new("identity_invalid", "核验目标标识无效"))?;
    }
    checked("identity_invalid", serde_json::to_string(target))
}
pub(super) fn target(identity: &DeviceIdentity) -> Identity {
    Identity {
        account_id: identity.account_id.clone(),
        device_id: identity.device_id.clone(),
    }
}
pub(super) fn next(revision: &str) -> Result<String, LabError> {
    super::wire_types::decimal(revision)?
        .checked_add(1)
        .map(|n| n.to_string())
        .ok_or_else(|| LabError::new("identity_budget", "核验版本耗尽"))
}
pub(super) fn budget(state: &State) -> Result<(), LabError> {
    ensure(
        state.records.len() <= RECORD_LIMIT
            && state
                .records
                .values()
                .map(|r| r.retired.len())
                .sum::<usize>()
                <= RETIRED_LIMIT
            && checked("identity_invalid", serde_json::to_vec(state))?.len() <= BYTE_LIMIT,
        "identity_budget",
        "核验账本达到有界容量，不能丢弃旧绑定",
    )
}
pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    let Some(stored) = &state.identity_trust else {
        return Ok(());
    };
    ensure(
        stored.version == 1,
        "identity_invalid",
        "核验账本版本不支持",
    )?;
    budget(stored)?;
    let mut bindings = std::collections::BTreeSet::from([codec::encode(&state.own_signature_key)]);
    for (index, record) in &stored.records {
        ensure(
            *index == key(&target(&record.identity))?,
            "identity_invalid",
            "核验索引不匹配",
        )?;
        ensure(
            super::wire_types::decimal(&record.revision)? > 0,
            "identity_invalid",
            "核验版本无效",
        )?;
        let identities =
            std::iter::once(&record.identity).chain(record.retired.iter().map(|r| &r.identity));
        let mut seen = std::collections::BTreeSet::new();
        for identity in identities {
            identity.validate()?;
            ensure(
                identity.service_id == state.context.service
                    && target(identity) == target(&record.identity)
                    && !(identity.account_id == state.context.account
                        && identity.device_id == state.context.device)
                    && seen.insert(identity.signature_key.clone())
                    && bindings.insert(identity.signature_key.clone()),
                "identity_invalid",
                "核验绑定范围或历史冲突",
            )?;
        }
        if let Some(candidate) = &record.candidate {
            candidate.validate()?;
            ensure(
                candidate.service_id == state.context.service
                    && target(candidate) == target(&record.identity)
                    && candidate != &record.identity,
                "identity_invalid",
                "冲突候选必须绑定原目标且不能等于原身份",
            )?;
        }
        ensure(
            (record.status == Status::Changed) == record.candidate.is_some()
                && (record.status != Status::Verified || record.verification.is_some())
                && (record.status != Status::Unverified || record.verification.is_none())
                && (record.status != Status::Changed || record.history == History::Gap)
                && (record.retired.is_empty() == record.last_reset.is_none())
                && (record.history != History::Reset || record.last_reset.is_some())
                && (record.history != History::Unknown || record.retired.is_empty()),
            "identity_invalid",
            "核验状态与证据冲突",
        )?;
        for fact in record.verification.iter().chain(
            record
                .retired
                .iter()
                .filter_map(|r| r.verification.as_ref()),
        ) {
            super::wire_types::reference(&fact.confirmation_sha256)?;
        }
        if let Some(hash) = &record.last_reset {
            super::wire_types::reference(hash)?;
        }
    }
    Ok(())
}

/// 冲突候选可以持久展示，但不能成为当前绑定或独立核验事实。
pub(super) fn binding_available(
    state: &DeviceState,
    identity: &DeviceIdentity,
) -> Result<(), LabError> {
    let target = target(identity);
    let key: [u8; 32] = codec::decode(&identity.signature_key)?
        .try_into()
        .map_err(|_| LabError::new("identity_invalid", "签名公钥长度不匹配"))?;
    let roster_target = if target.account_id == state.context.account {
        target.device_id.as_str()
    } else {
        ""
    };
    let collides = identity.signature_key == codec::encode(&state.own_signature_key)
        || state.roster.key_bound_to_other_device(roster_target, &key)
        || state
            .identity_trust
            .iter()
            .flat_map(|s| s.records.values())
            .any(|r| {
                (self::target(&r.identity) != target
                    && r.identity.signature_key == identity.signature_key)
                    || r.retired
                        .iter()
                        .any(|old| old.identity.signature_key == identity.signature_key)
            })
        || state.peer_pins.iter().any(|p| {
            (p.account != target.account_id || p.device != target.device_id)
                && p.signature_key == identity.signature_key
        })
        || state
            .permissions
            .admission
            .seen_members
            .iter()
            .chain(
                state
                    .permissions
                    .checkpoint
                    .iter()
                    .flat_map(|cp| cp.members.iter()),
            )
            .any(|m| m.identity() != target && m.signature_key == identity.signature_key);
    ensure(
        !collides,
        "identity_changed",
        "公钥属于本机、其他设备或已退休绑定，不能授权冲突候选",
    )
}

/// 仅作为已有绑定/缺口的依据，不把原 pin 或群授权提升为独立核验。
pub(super) fn legacy(state: &DeviceState, target: &Identity) -> Option<DeviceIdentity> {
    let key = if target.account_id == state.context.account {
        state
            .roster
            .trusted_signature_key(&target.device_id)
            .map(|key| codec::encode(&key))
    } else {
        None
    }
    .or_else(|| {
        state
            .peer_pins
            .iter()
            .find(|p| p.account == target.account_id && p.device == target.device_id)
            .map(|p| p.signature_key.clone())
    })
    .or_else(|| {
        state
            .permissions
            .admission
            .seen_members
            .iter()
            .find(|m| m.identity() == *target)
            .map(|m| m.signature_key.clone())
    })
    .or_else(|| {
        state
            .permissions
            .checkpoint
            .as_ref()?
            .members
            .iter()
            .find(|m| m.identity() == *target)
            .map(|m| m.signature_key.clone())
    });
    key.map(|key| {
        object(
            &state.context.service,
            &target.account_id,
            &target.device_id,
            &key,
        )
    })
}
