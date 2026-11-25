//! Q01来源命令；候选元数据经原快照/独立锚提交，无暂停解除入口。
use super::identity_source_state::{configured, Pending, Status};
pub(super) use super::identity_source_state::{gate, require, validate, Command, State};
use super::{ensure, key_package_state, state::DeviceState, LabError, Operation};
use crate::identity_source::{self as protocol, directory, Document, Head};
use serde_json::{json, Value};
use std::collections::BTreeMap;
pub(super) fn execute(state: &mut DeviceState, command: Command) -> Result<Value, LabError> {
    let own = key_package_state::own(state);
    match command {
        Command::Configure { roots } => {
            roots.validate()?;
            ensure(
                roots.service_id == state.context.service,
                "identity_source_root",
                "实例不符",
            )?;
            if let Some(s) = &state.identity_source {
                ensure(s.roots == roots, "identity_source_root", "禁止更换固定根")?;
            } else {
                ensure(
                    state.group_id.is_none(),
                    "identity_source_state",
                    "必须在建群前配置",
                )?;
                state.identity_source = Some(State {
                    roots,
                    status: Status::Active,
                    requests: BTreeMap::new(),
                    accounts: BTreeMap::new(),
                });
            }
            Ok(json!({"configured":true}))
        }
        Command::Inspect => Ok(serde_json::to_value(configured(state)?)
            .map_err(|_| LabError::new("identity_source_state", "编码失败"))?),
        Command::Request {
            account_id,
            request_id,
        } => {
            crate::permission::types::id(&account_id)?;
            crate::permission::types::id(&request_id)?;
            let s = state
                .identity_source
                .as_mut()
                .ok_or_else(|| LabError::new("identity_source_required", "尚未配置"))?;
            if let Some(p) = s.requests.get(&request_id) {
                ensure(
                    p.account_id == account_id,
                    "idempotency_conflict",
                    "请求不能改绑",
                )?;
            } else {
                ensure(s.requests.len() < 64, "resource_exhausted", "对照请求满额")?;
                let mut random = [0u8; 32];
                super::checked("random_source", getrandom::getrandom(&mut random))?;
                s.requests.insert(
                    request_id.clone(),
                    Pending {
                        account_id: account_id.clone(),
                        challenge: crate::permission::commit_digest(&random),
                    },
                );
            }
            let p = &s.requests[&request_id];
            Ok(
                json!({"service_id":state.context.service,"requester":own,"account_id":account_id,"request_id":request_id,"challenge":p.challenge}),
            )
        }
        Command::Approve { approval } => {
            ensure(
                approval.actor == own && approval.target.account_id == own.account_id,
                "identity_source_approval",
                "批准者主体不符",
            )?;
            require(state, &own, false)?;
            let s = configured(state)?;
            let a = s
                .accounts
                .get(&own.account_id)
                .ok_or_else(|| LabError::new("directory_gap", "缺账号目录"))?;
            let head = a
                .snapshots
                .last()
                .ok_or_else(|| LabError::new("directory_gap", "空目录"))?;
            ensure(
                !a.conflict
                    && approval.service_id == state.context.service
                    && approval.previous_version == head.version
                    && approval.previous_sha256 == directory::hash(head)?,
                "directory_gap",
                "批准前驱不符",
            )?;
            Ok(json!({"proof":protocol::sign(&Document::Approval(approval),&state.signer()?)?}))
        }
        Command::ExportHead {
            account_id,
            requester,
            request_id,
            challenge,
        } => {
            ensure(
                account_id == own.account_id,
                "identity_source_approval",
                "只导出本人账号实际所见",
            )?;
            require(state, &own, false)?;
            let a = configured(state)?
                .accounts
                .get(&account_id)
                .ok_or_else(|| LabError::new("directory_gap", "无目录"))?;
            ensure(!a.conflict, "directory_conflict", "冲突不导出正常head")?;
            let h = a
                .snapshots
                .last()
                .ok_or_else(|| LabError::new("directory_gap", "空目录"))?;
            let head = Head {
                service_id: state.context.service.clone(),
                actor: own,
                requester,
                account_id,
                request_id,
                challenge,
                version: h.version.clone(),
                snapshot_sha256: directory::hash(h)?,
            };
            Ok(json!({"proof":protocol::sign(&Document::Head(head),&state.signer()?)?}))
        }
        Command::Respond {
            request_id,
            receipt,
            witness,
        } => {
            let s = configured(state)?;
            ensure(
                s.status == Status::Active,
                "identity_source_capacity_exhausted",
                "来源证据满额暂停",
            )?;
            let pending = s
                .requests
                .get(&request_id)
                .ok_or_else(|| LabError::new("identity_source_request", "缺原请求"))?;
            let Document::Directory(r) = protocol::verify(&receipt, &s.roots.receipt_key)? else {
                return Err(LabError::new("identity_source_directory", "响应类型不符"));
            };
            ensure(
                r.service_id == state.context.service
                    && r.requester == own
                    && r.account_id == pending.account_id
                    && r.request_id == request_id
                    && r.challenge == pending.challenge,
                "identity_source_binding",
                "响应请求绑定错误",
            )?;
            directory::verify_chain(&r.snapshots, &s.roots)?;
            ensure(
                r.snapshots[0].account_id == r.account_id,
                "directory_context",
                "目录账号不符",
            )?;
            if let Some(proof) = &witness {
                let Document::Head(h) = protocol::parse(proof)? else {
                    return Err(LabError::new("identity_source_binding", "对照类型错误"));
                };
                protocol::verify(proof, &h.actor.signature_key)?;
                ensure(
                    h.service_id == r.service_id
                        && h.requester == own
                        && h.account_id == r.account_id
                        && h.actor.account_id == r.account_id
                        && h.actor != own
                        && h.request_id == request_id
                        && h.challenge == r.challenge,
                    "identity_source_binding",
                    "对照范围不符",
                )?;
                super::identity_gate::require_verified(
                    state,
                    &super::identity_state::object(
                        &state.context.service,
                        &h.actor.account_id,
                        &h.actor.device_id,
                        &h.actor.signature_key,
                    ),
                )?;
            }
            let s = state
                .identity_source
                .as_mut()
                .ok_or_else(|| LabError::new("identity_source_required", "尚未配置"))?;
            ensure(
                s.accounts.contains_key(&r.account_id) || s.accounts.len() < 16,
                "resource_exhausted",
                "目录账号满额",
            )?;
            let a = s.accounts.entry(r.account_id).or_default();
            if !a.snapshots.is_empty() {
                ensure(
                    r.snapshots.len() >= a.snapshots.len(),
                    "directory_stale",
                    "目录回退",
                )?;
                if a.snapshots.iter().zip(&r.snapshots).any(|(x, y)| x != y) {
                    a.conflict = true;
                    return Ok(json!({"status":"directory_conflict"}));
                }
            }
            if let Some(proof) = witness {
                if !a.heads.contains(&proof) {
                    if a.heads.len() >= 32 {
                        s.status = Status::EvidenceCapacityExhausted;
                        return Ok(json!({"status":"identity_source_capacity_exhausted"}));
                    }
                    a.heads.push(proof);
                }
            }
            a.snapshots = r.snapshots;
            let head = a
                .snapshots
                .last()
                .ok_or_else(|| LabError::new("directory_gap", "空目录"))?;
            let hash = directory::hash(head)?;
            let mut matched = false;
            let mut gap = false;
            for proof in &a.heads {
                if let Document::Head(h) = protocol::parse(proof)? {
                    let v = crate::permission::types::decimal(&h.version)?;
                    if v > 0
                        && v <= a.snapshots.len() as u64
                        && h.snapshot_sha256 != directory::hash(&a.snapshots[(v - 1) as usize])?
                    {
                        a.conflict = true;
                    }
                    if h.version == head.version {
                        if h.snapshot_sha256 != hash {
                            a.conflict = true;
                        } else {
                            matched = true;
                        }
                    } else if crate::permission::types::decimal(&h.version)?
                        > crate::permission::types::decimal(&head.version)?
                    {
                        gap = true;
                    }
                }
            }
            Ok(
                json!({"status":if a.conflict {"directory_conflict"}else if gap{"directory_gap"}else if matched{"known_comparison_satisfied"}else{"freshness_unknown"}}),
            )
        }
    }
}

/// 纯元数据拒绝不消耗独立锚预约；成功仍在预约后重新执行并保存。
pub(super) fn preflight(state: &DeviceState, op: &Operation) -> Result<(), LabError> {
    if let Operation::IdentitySource { command } = op {
        match command {
            Command::Configure { .. } | Command::Respond { .. } => {
                let mut candidate: DeviceState = super::checked(
                    "identity_source_state",
                    serde_json::from_slice(&super::checked(
                        "identity_source_state",
                        serde_json::to_vec(state),
                    )?),
                )?;
                let command = super::checked(
                    "identity_source_state",
                    serde_json::from_slice(&super::checked(
                        "identity_source_state",
                        serde_json::to_vec(command),
                    )?),
                )?;
                apply(&mut candidate, command)?;
            }
            Command::Request {
                account_id,
                request_id,
            } => {
                crate::permission::types::id(account_id)?;
                crate::permission::types::id(request_id)?;
                let s = configured(state)?;
                ensure(
                    s.requests.contains_key(request_id) || s.requests.len() < 64,
                    "resource_exhausted",
                    "请求满额",
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// 仅Respond处理公共元数据；预算不足只提交暂停，保留已有全部证据与真实provider。
pub(super) fn apply(state: &mut DeviceState, command: Command) -> Result<Value, LabError> {
    if matches!(command, Command::Respond { .. }) {
        let raw = super::checked("identity_source_state", serde_json::to_vec(state))?;
        let mut candidate: DeviceState =
            super::checked("identity_source_state", serde_json::from_slice(&raw))?;
        let value = execute(&mut candidate, command)?;
        let source = candidate
            .identity_source
            .as_ref()
            .ok_or_else(|| LabError::new("identity_source_required", "尚未配置"))?;
        if super::checked("identity_source_state", serde_json::to_vec(source))?.len()
            > 3 * 1024 * 1024
        {
            state
                .identity_source
                .as_mut()
                .ok_or_else(|| LabError::new("identity_source_required", "尚未配置"))?
                .status = Status::EvidenceCapacityExhausted;
            return Ok(json!({"status":"identity_source_capacity_exhausted"}));
        }
        validate(&candidate)?;
        state.identity_source = candidate.identity_source;
        Ok(value)
    } else {
        execute(state, command)
    }
}
