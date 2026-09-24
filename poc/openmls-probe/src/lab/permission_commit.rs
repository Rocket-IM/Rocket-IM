//! 用实际 MLS 身份、提案及后继状态核对签名权限声明。
use super::{checked, codec, ensure, permission_state, state::DeviceState, LabError};
use crate::permission::{self, Action, PermissionCheckpoint, Proof, Statement};
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;

pub(super) fn apply(
    state: &DeviceState,
    provider: &OpenMlsRustCrypto,
    change: &Proof,
    statement: &Statement,
    next: &PermissionCheckpoint,
) -> Result<bool, LabError> {
    let mut group = permission_state::group_from(state, provider)?;
    let mut expected = Vec::new();
    for member in group.members() {
        let identity = codec::credential_context(&member.credential)?;
        if !next
            .members
            .iter()
            .any(|entry| entry.account_id == identity.account && entry.device_id == identity.device)
        {
            expected.push(member.index);
        }
    }
    let processed = checked(
        "permission_commit",
        group.process_message(
            provider,
            codec::protocol(&codec::decode(&change.commit_bytes)?)?,
        ),
    )?;
    let actor = codec::credential_context(processed.credential())?;
    ensure(
        actor.service == statement.service_id
            && actor.account == statement.actor.account_id
            && actor.device == statement.actor.device_id,
        "permission_commit",
        "实际 MLS Commit 发送者与签名发起设备不同",
    )?;
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        _ => {
            return Err(LabError::new(
                "permission_commit",
                "权限证明必须携带成员变更 Commit",
            ))
        }
    };
    let removed: Vec<_> = staged
        .remove_proposals()
        .map(|proposal| proposal.remove_proposal().removed())
        .collect();
    if let Action::AddMember {
        key_package_sha256, ..
    }
    | Action::AddDevice {
        key_package_sha256, ..
    } = &statement.action
    {
        let adds: Vec<_> = staged.add_proposals().collect();
        ensure(
            adds.len() == 1 && removed.is_empty() && staged.queued_proposals().count() == 1,
            "permission_commit",
            "Add Commit 必须只包含签名声明的一项新增",
        )?;
        let raw = checked(
            "permission_commit",
            adds[0]
                .add_proposal()
                .key_package()
                .tls_serialize_detached(),
        )?;
        ensure(
            permission::commit_digest(&raw) == *key_package_sha256,
            "permission_commit",
            "实际 Add KeyPackage 与签名摘要不同",
        )?;
    } else {
        ensure(
            removed.len() == expected.len()
                && removed.iter().all(|index| expected.contains(index))
                && staged.queued_proposals().count() == removed.len(),
            "permission_commit",
            "Commit 必须仅精确移除签名声明的目标",
        )?;
    }
    let self_removed = staged.self_removed();
    checked(
        "permission_commit",
        group.merge_staged_commit(provider, *staged),
    )?;
    Ok(self_removed)
}
