//! Q01 来源账本与原快照/独立锚共同提交；没有自动信任或暂停解除入口。
use super::{ensure, key_package_state, state::DeviceState, LabError, Operation};
use crate::{
    identity_source::{self as protocol, directory, Document, Roots, Snapshot},
    permission::{receipts::SignedRecord, Member},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub(super) account_id: String,
    pub(super) challenge: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Account {
    pub snapshots: Vec<Snapshot>,
    pub conflict: bool,
    pub heads: Vec<SignedRecord>,
}
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    #[default]
    Active,
    EvidenceCapacityExhausted,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    #[serde(default)]
    pub(super) status: Status,
    pub(super) roots: Roots,
    pub(super) requests: BTreeMap<String, Pending>,
    pub(super) accounts: BTreeMap<String, Account>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Command {
    Configure {
        roots: Roots,
    },
    Inspect,
    Request {
        account_id: String,
        request_id: String,
    },
    Respond {
        request_id: String,
        receipt: SignedRecord,
        witness: Option<SignedRecord>,
    },
    Approve {
        approval: protocol::Approval,
    },
    ExportHead {
        account_id: String,
        requester: Member,
        request_id: String,
        challenge: String,
    },
}
pub(super) fn configured(state: &DeviceState) -> Result<&State, LabError> {
    state
        .identity_source
        .as_ref()
        .ok_or_else(|| LabError::new("identity_source_required", "尚未固定信任来源"))
}
pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    if let Some(s) = &state.identity_source {
        s.roots.validate()?;
        ensure(
            s.roots.service_id == state.context.service
                && s.requests.len() <= 64
                && s.accounts.len() <= 16
                && serde_json::to_vec(s)
                    .map_err(|_| LabError::new("identity_source_state", "编码失败"))?
                    .len()
                    <= 3 * 1024 * 1024,
            "identity_source_state",
            "来源账本或预算无效",
        )?;
        for (id, p) in &s.requests {
            crate::permission::types::id(id)?;
            crate::permission::types::id(&p.account_id)?;
            crate::permission::types::hash(&p.challenge)?;
        }
        for (id, a) in &s.accounts {
            directory::verify_chain(&a.snapshots, &s.roots)?;
            ensure(
                a.snapshots[0].account_id == *id && a.heads.len() <= 32,
                "identity_source_state",
                "目录账本归属不符",
            )?;
            for h in &a.heads {
                let Document::Head(head) = protocol::parse(h)? else {
                    return Err(LabError::new("identity_source_state", "对照格式错误"));
                };
                protocol::verify(h, &head.actor.signature_key)?;
                ensure(
                    head.service_id == s.roots.service_id && head.account_id == *id,
                    "identity_source_state",
                    "对照归属不符",
                )?;
            }
        }
    }
    Ok(())
}
pub(super) fn require(state: &DeviceState, member: &Member, new: bool) -> Result<(), LabError> {
    let Some(s) = &state.identity_source else {
        return Ok(());
    };
    ensure(
        s.status == Status::Active,
        "identity_source_capacity_exhausted",
        "来源证据满额暂停",
    )?;
    let Some(a) = s.accounts.get(&member.account_id) else {
        return ensure(
            !new,
            "directory_comparison_required",
            "缺已验证目录及独立对照",
        );
    };
    ensure(!a.conflict, "directory_conflict", "已知目录冲突持续暂停")?;
    let head = a
        .snapshots
        .last()
        .ok_or_else(|| LabError::new("directory_gap", "缺目录"))?;
    ensure(
        head.devices
            .iter()
            .any(|e| e.status == "active" && directory::target(e).ok().as_ref() == Some(member)),
        "identity_source_revoked",
        "目录中无此准确活动身份",
    )?;
    let hash = directory::hash(head)?;
    let mut matched = false;
    for proof in &a.heads {
        if let Document::Head(h) = protocol::parse(proof)? {
            let v = crate::permission::types::decimal(&h.version)?;
            ensure(
                v <= a.snapshots.len() as u64,
                "directory_gap",
                "独立所知水位尚未补齐",
            )?;
            ensure(
                v > 0 && h.snapshot_sha256 == directory::hash(&a.snapshots[(v - 1) as usize])?,
                "directory_conflict",
                "独立对照与已知前缀冲突",
            )?;
            if new {
                super::identity_gate::require(
                    state,
                    &super::identity_state::object(
                        &state.context.service,
                        &h.actor.account_id,
                        &h.actor.device_id,
                        &h.actor.signature_key,
                    ),
                )?;
                ensure(
                    head.devices.iter().any(|e| {
                        e.status == "active" && directory::target(e).ok().as_ref() == Some(&h.actor)
                    }),
                    "identity_source_revoked",
                    "对照端已失效",
                )?;
            }
            if h.version == head.version && h.snapshot_sha256 == hash {
                matched = true;
            }
        }
    }
    if new {
        ensure(
            matched,
            "directory_comparison_required",
            "缺准确head独立对照",
        )?;
    }

    Ok(())
}
pub(super) fn gate(state: &DeviceState, op: &Operation) -> Result<(), LabError> {
    if state.identity_source.is_none() {
        return Ok(());
    }
    if let Operation::KeyPackageGenerate { source_key, .. }
    | Operation::KeyPackageRequest { source_key, .. } = op
    {
        ensure(
            *source_key == configured(state)?.roots.receipt_key,
            "identity_source_root",
            "材料来源与固定根不符",
        )?;
    }
    match op {
        Operation::Create { peers } => {
            let own = key_package_state::own(state);
            ensure(
                configured(state)?.accounts.contains_key(&own.account_id),
                "identity_source_required",
                "本机尚无授权目录",
            )?;
            require(state, &own, false)?;
            for p in peers {
                require(
                    state,
                    &Member {
                        account_id: p.account.clone(),
                        device_id: p.device.clone(),
                        signature_key: p.signature_key.clone(),
                    },
                    true,
                )?;
            }
        }
        Operation::PermissionPrepareAdd { member, .. }
        | Operation::PermissionPrepareDevice { member, .. } => require(state, member, true)?,
        Operation::KeyPackageRequest {
            action: crate::key_package::Action::Claim { target, .. },
            ..
        } => require(state, target, true)?,
        Operation::PermissionPrepare {
            action:
                crate::permission::Action::AddMember { member, .. }
                | crate::permission::Action::AddDevice { member, .. },
            ..
        } => require(state, member, true)?,
        Operation::HistoryExport { .. } => {
            for p in &state.peer_pins {
                require(
                    state,
                    &Member {
                        account_id: p.account.clone(),
                        device_id: p.device.clone(),
                        signature_key: p.signature_key.clone(),
                    },
                    true,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}
