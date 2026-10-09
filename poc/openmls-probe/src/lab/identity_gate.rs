//! 所有秘密外发在返回缓存之前核验准确目标；此模块不恢复provider或运行MLS。
use super::{
    codec, ensure, identity_state as stored, state::DeviceState, wire_types::Header, LabError,
    Operation,
};
use crate::{
    identity_trust::DeviceIdentity,
    permission::{self, Action, Identity, Member, PermissionCheckpoint, Statement},
};

pub(super) fn require(state: &DeviceState, identity: &DeviceIdentity) -> Result<(), LabError> {
    identity.validate()?;
    if *identity == stored::own(state) {
        return Ok(());
    }
    let record = state
        .identity_trust
        .as_ref()
        .and_then(|s| {
            stored::key(&stored::target(identity))
                .ok()
                .and_then(|key| s.records.get(&key))
        })
        .ok_or_else(|| LabError::new("identity_unverified", "目标设备尚无独立核验事实"))?;
    ensure(
        record.status != stored::Status::Changed && record.identity == *identity,
        "identity_changed",
        "目标身份与核验绑定变化或冲突",
    )?;
    ensure(
        record.status == stored::Status::Verified && record.verification.is_some(),
        "identity_unverified",
        "目标设备尚未独立核验",
    )
}
fn members(state: &DeviceState, members: &[Member]) -> Result<(), LabError> {
    for member in members {
        require(
            state,
            &stored::object(
                &state.context.service,
                &member.account_id,
                &member.device_id,
                &member.signature_key,
            ),
        )?;
    }
    Ok(())
}
fn checkpoint<'a>(
    state: &'a DeviceState,
    version: &str,
    reference: &str,
) -> Option<&'a PermissionCheckpoint> {
    state
        .permissions
        .checkpoint
        .iter()
        .chain(state.permissions.consistency.checkpoints.values())
        .chain(state.permissions.history.past.values())
        .find(|cp| cp.authorization_version == version && cp.crypto_state_ref == reference)
}
fn header(state: &DeviceState, header: &Header) -> Result<(), LabError> {
    let cp = checkpoint(
        state,
        &header.authorization_version,
        &header.crypto_state_ref,
    );
    for target in &header.recipients {
        let identity = Identity {
            account_id: target.account_id.clone(),
            device_id: target.device_id.clone(),
        };
        let binding = if let Some(cp) = cp {
            cp.members
                .iter()
                .find(|m| m.identity() == identity)
                .map(|m| {
                    stored::object(
                        &state.context.service,
                        &m.account_id,
                        &m.device_id,
                        &m.signature_key,
                    )
                })
        } else if state.permissions.checkpoint.is_none() {
            // 无签名权限的早期实验只使用其从未改绑的原 pin/roster，不采用新候选。
            stored::legacy(state, &identity)
        } else {
            None
        };
        require(
            state,
            &binding.ok_or_else(|| {
                LabError::new("identity_evidence_missing", "缺少原消息目标的完整公钥绑定")
            })?,
        )?;
    }
    Ok(())
}
fn current(state: &DeviceState) -> Result<(), LabError> {
    if let Some(cp) = &state.permissions.checkpoint {
        return members(state, &cp.members);
    }
    original_pins(state)
}
fn original_pins(state: &DeviceState) -> Result<(), LabError> {
    // 旧实验只在首次 create/join 保存 pins，remove 不删除或改绑。
    // 旧 Outbound 没有头部，故保守要求全部原 pins；绝不由当前候选补造原目标。
    for pin in &state.peer_pins {
        require(
            state,
            &stored::object(
                &state.context.service,
                &pin.account,
                &pin.device,
                &pin.signature_key,
            ),
        )?;
    }
    Ok(())
}
fn permission_output(
    state: &DeviceState,
    change_id: &str,
    action: &Action,
) -> Result<(), LabError> {
    let pending = if let Some(pending) = &state.permissions.pending {
        let statement = Statement::parse(&codec::decode(&pending.change.statement_bytes)?)?;
        (statement.change_id == change_id).then_some(&pending.change)
    } else {
        None
    };
    let previous = pending.or_else(|| state.permissions.applied.get(change_id));
    if let Some(proof) = previous {
        let statement = Statement::parse(&codec::decode(&proof.statement_bytes)?)?;
        if let Some(cp) = checkpoint(
            state,
            &statement.previous_authorization_version,
            &statement.from_state_ref,
        ) {
            return members(state, &cp.remaining(&statement.actor, &statement.action)?);
        }
        let successor = checkpoint(
            state,
            &statement.authorization_version,
            &statement.to_state_ref,
        )
        .ok_or_else(|| {
            LabError::new(
                "identity_evidence_missing",
                "缺少原权限候选的准确前驱或后继",
            )
        })?;
        return members(state, &successor.members);
    }
    let cp = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "尚未建立权限检查点"))?;
    members(
        state,
        &cp.remaining(
            &Identity {
                account_id: state.context.account.clone(),
                device_id: state.context.device.clone(),
            },
            action,
        )?,
    )
}

pub(super) fn check(state: &DeviceState, operation: &Operation) -> Result<(), LabError> {
    match operation {
        Operation::Create { peers } => {
            for peer in peers {
                require(
                    state,
                    &stored::object(
                        &state.context.service,
                        &peer.account,
                        &peer.device,
                        &peer.signature_key,
                    ),
                )?;
            }
        }
        Operation::Send { id, .. } => {
            if state.outbox.contains_key(id) {
                original_pins(state)?;
            } else {
                current(state)?;
            }
        }
        Operation::Remove { member, .. } => {
            for pin in state.peer_pins.iter().filter(|p| p.device != *member) {
                require(
                    state,
                    &stored::object(
                        &state.context.service,
                        &pin.account,
                        &pin.device,
                        &pin.signature_key,
                    ),
                )?;
            }
        }
        Operation::WireSend {
            logical_message_id,
            attempt_id,
            ..
        } => {
            let config = super::wire::configuration(state)?;
            let sender = super::wire_types::Device {
                account_id: state.context.account.clone(),
                device_id: state.context.device.clone(),
            };
            let logical = super::wire_types::logical_key(
                &state.context.service,
                &config.conversation_id,
                &sender,
                logical_message_id,
            )?;
            // 紧凑终态不输出密文；精确请求校验仍由原入口负责。
            if super::wire_reclaimed::message(state, &logical).is_some() {
                return Ok(());
            }
            if let Some(record) = state
                .wire
                .outbox
                .values()
                .find(|r| r.logical_key == logical && r.attempt_id == *attempt_id)
            {
                header(
                    state,
                    &Header::parse(&codec::decode(&record.envelope.header_bytes)?)?,
                )?;
            } else {
                current(state)?;
            }
        }
        Operation::PermissionPrepare {
            change_id, action, ..
        } => {
            super::permissions::validate_prepare_action(action)?;
            permission_output(state, change_id, action)?;
        }
        Operation::PermissionPrepareAdd {
            change_id,
            member,
            key_package,
            history_policy,
            ..
        }
        | Operation::PermissionPrepareDevice {
            change_id,
            member,
            key_package,
            history_policy,
            ..
        } => {
            let action = if matches!(operation, Operation::PermissionPrepareAdd { .. }) {
                Action::AddMember {
                    member: member.clone(),
                    key_package_sha256: permission::commit_digest(&codec::decode(key_package)?),
                    welcome_sha256: "0".repeat(64),
                    history_policy: history_policy.clone(),
                }
            } else {
                Action::AddDevice {
                    member: member.clone(),
                    key_package_sha256: permission::commit_digest(&codec::decode(key_package)?),
                    welcome_sha256: "0".repeat(64),
                    history_policy: history_policy.clone(),
                }
            };
            permission_output(state, change_id, &action)?;
        }
        Operation::HistoryExport { request } => {
            let cp = state
                .permissions
                .checkpoint
                .as_ref()
                .ok_or_else(|| LabError::new("trust_required", "缺少历史迁移检查点"))?;
            let statement = crate::history_transfer::verify_request(cp, request)?;
            let target = cp
                .members
                .iter()
                .find(|m| m.identity() == statement.target)
                .ok_or_else(|| {
                    LabError::new("identity_evidence_missing", "迁移目标不在准确检查点中")
                })?;
            members(state, std::slice::from_ref(target))?;
        }
        _ => {}
    }
    Ok(())
}
