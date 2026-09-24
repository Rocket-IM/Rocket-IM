//! 候选准备保留已消耗的握手发送状态，权限与公开群状态仅在验证接受后推进。

use super::{
    checked, codec, ensure, permission_state as stored, state::DeviceState, wire, wire_types,
    LabError, Operation, MAX_RECORDS,
};
use crate::permission::{
    self, Action, Identity, PermissionCheckpoint, Proof, Statement, SIGNING_DOMAIN,
};
use openmls_traits::{signatures::Signer, OpenMlsProvider};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn guard(state: &DeviceState, operation: &Operation) -> Result<(), LabError> {
    // 一致性观察不授予权限；候选/移除门禁不应阻止取证或清理独立的 Q02 暂停。
    if matches!(
        operation,
        Operation::ConsistencyChallenge
            | Operation::ConsistencyExchangeInspect
            | Operation::ConsistencyExchangeCancel
            | Operation::ConsistencyInspect
            | Operation::ConsistencyObserveHead { .. }
            | Operation::ConsistencyObserveFork { .. }
            | Operation::ConsistencyResume { .. }
    ) {
        return Ok(());
    }
    if state.permissions.admission.anchor.is_some() && state.group_id.is_none() {
        ensure(
            matches!(
                operation,
                Operation::Init
                    | Operation::Inspect
                    | Operation::WireReadPending
                    | Operation::WireReadInspect
                    | Operation::PermissionInspect
                    | Operation::PermissionPinMember { .. }
                    | Operation::PermissionJoinAnchor { .. }
                    | Operation::PermissionDeviceJoinAnchor { .. }
                    | Operation::PermissionJoinAdvance { .. }
                    | Operation::PermissionJoin { .. }
            ),
            "join_required",
            "已固定入群锚，必须验证签名链和 Welcome 后才能使用密码状态",
        )?;
    }
    if state.permissions.checkpoint.is_none() {
        return Ok(());
    }
    ensure(
        !matches!(
            operation,
            Operation::Remove { .. }
                | Operation::ApplyCommit { .. }
                | Operation::WireConfigure { .. }
                | Operation::WireApplyDependency { .. }
                | Operation::Authorize { .. }
                | Operation::Create { .. }
                | Operation::Join { .. }
                | Operation::Send { .. }
                | Operation::Receive { .. }
        ),
        "signed_permission_required",
        "签名权限模式禁止旧控制或消息路径绕过",
    )?;
    if state.permissions.pending.is_some()
        || state.permissions.recovery.intent.is_some()
        || state.permissions.recovery.access_removed
    {
        ensure(
            matches!(
                operation,
                Operation::Inspect
                    | Operation::HistoryInspect
                    | Operation::HistoryCancel { .. }
                    | Operation::WireInspect
                    | Operation::WireReadPending
                    | Operation::WireReadInspect
                    | Operation::WireSlotInspect { .. }
                    | Operation::WireAccept { .. }
                    | Operation::WireCloseRequest { .. }
                    | Operation::WireClose { .. }
                    | Operation::WireReject { .. }
                    | Operation::PermissionInspect
                    | Operation::PermissionPrepare { .. }
                    | Operation::PermissionPrepareAdd { .. }
                    | Operation::PermissionPrepareDevice { .. }
                    | Operation::PermissionPinMember { .. }
                    | Operation::PermissionApply { .. }
                    | Operation::PermissionCloseRequest
                    | Operation::PermissionRecover { .. }
                    | Operation::WireDownload { .. }
                    | Operation::WireDownloadSigned { .. }
            ),
            if state.permissions.recovery.access_removed {
                "access_removed"
            } else {
                "permission_pending"
            },
            "权限意图待完成或访问已移除，暂停密码状态推进和发送",
        )?;
    }
    Ok(())
}

pub(super) fn inspect(state: &DeviceState) -> Value {
    json!({"checkpoint":state.permissions.checkpoint,"pending_change":state.permissions.pending.as_ref().map(|p| &p.change),
        "applied_count":state.permissions.applied.len(), "epoch_prepare_count":state.permissions.recovery.prepare_count, "epoch_prepare_limit":64,
        "needs_reprepare":state.permissions.recovery.intent, "access_removed":state.permissions.recovery.access_removed,
        "service_target":state.permissions.recovery.service_target,
        "recovery_status":if state.permissions.recovery.access_removed {"access_removed"} else if state.permissions.pending.is_some() {"pending"} else if state.permissions.recovery.intent.is_some() {"needs_reprepare"} else {"ready"},
        "admission":super::permission_admission::summary(state)})
}

pub(super) fn bootstrap(
    state: &mut DeviceState,
    checkpoint: PermissionCheckpoint,
    relay_receipt_key: Option<String>,
) -> Result<Value, LabError> {
    ensure(
        state.permissions.checkpoint.is_none(),
        "permission_conflict",
        "初始权限信任只能建立一次",
    )?;
    let mut group = state.group()?;
    stored::validate_current(state, &checkpoint, &group)?;
    let config = state
        .wire
        .configuration
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "先配置初始会话"))?;
    ensure(
        config.conversation_id == checkpoint.conversation_id
            && config.authorization_version == checkpoint.authorization_version
            && config.crypto_state_ref == checkpoint.crypto_state_ref
            && group.is_active(),
        "permission_context",
        "初始权限检查点与 wire 配置不一致",
    )?;
    if let Some(key) = &relay_receipt_key {
        permission::receipts::validate_key(key)?;
        super::wire_history::enable(&state.provider, &mut group)?;
    }
    state.permissions.recovery.relay_receipt_key = relay_receipt_key;
    state.permissions.recovery.verified_refs.insert(
        checkpoint.authorization_version.clone(),
        checkpoint.crypto_state_ref.clone(),
    );
    super::permission_admission::remember(state, &checkpoint);
    state.permissions.admission.device_history_complete = true;
    state.permissions.checkpoint = Some(checkpoint);
    Ok(inspect(state))
}

pub(super) fn prepare(
    state: &mut DeviceState,
    change_id: String,
    action: Action,
    validity_secs: Option<u16>,
) -> Result<Value, LabError> {
    ensure(
        !matches!(action, Action::AddMember { .. } | Action::AddDevice { .. }),
        "invalid_permission",
        "Add 必须使用专用准备入口",
    )?;
    prepare_change(state, change_id, action, validity_secs, None)
}

pub(super) fn prepare_change(
    state: &mut DeviceState,
    change_id: String,
    mut action: Action,
    validity_secs: Option<u16>,
    key_package: Option<String>,
) -> Result<Value, LabError> {
    wire_types::id(&change_id)?;
    ensure(
        !state.permissions.recovery.access_removed,
        "access_removed",
        "本机已被移除",
    )?;
    ensure(
        validity_secs.is_none_or(|value| (1..=300).contains(&value)),
        "invalid_permission",
        "有效期必须为1到300秒",
    )?;
    super::permission_recovery::check_prepare(state, &change_id, &action)?;
    if let Some(pending) = &state.permissions.pending {
        let statement = Statement::parse(&codec::decode(&pending.change.statement_bytes)?)?;
        ensure(
            statement.change_id == change_id
                && statement.action.same_intent(&action)
                && validity_secs.is_none_or(|seconds| {
                    statement
                        .expires_at_unix_secs
                        .parse::<u64>()
                        .ok()
                        .zip(statement.issued_at_unix_secs.parse::<u64>().ok())
                        .is_some_and(|(end, start)| end - start == u64::from(seconds))
                }),
            "pending_conflict",
            "已有不同的待确认权限变更",
        )?;
        return super::permission_admission::prepared(state, &pending.change, true);
    }
    if let Some(change) = state.permissions.applied.get(&change_id) {
        let statement = Statement::parse(&codec::decode(&change.statement_bytes)?)?;
        ensure(
            statement.action.same_intent(&action),
            "permission_conflict",
            "相同变更 ID 对应不同意图",
        )?;
        return super::permission_admission::prepared(state, change, true);
    }
    ensure(
        state.permissions.applied.len() < MAX_RECORDS,
        "resource_exhausted",
        "权限记录已满",
    )?;
    ensure(
        state.permissions.recovery.prepare_count < 64,
        "permission_epoch_budget",
        "同一已验证epoch最多准备64个候选，需验证下一epoch才能继续",
    )?;
    let checkpoint = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "尚未建立权限检查点"))?;
    let actor = Identity {
        account_id: state.context.account.clone(),
        device_id: state.context.device.clone(),
    };
    let remaining = checkpoint.remaining(&actor, &action)?;
    super::permission_admission::check_new_member(state, &action)?;
    stored::validate_current(state, checkpoint, &state.group()?)?;
    let version = wire_types::decimal(&checkpoint.authorization_version)?
        .checked_add(1)
        .ok_or_else(|| LabError::new("permission_version", "权限版本溢出"))?;
    let provider = stored::provider_from(&stored::entries(&state.provider)?)?;
    let mut candidate = stored::group_from(state, &provider)?;
    if state.permissions.recovery.relay_receipt_key.is_some() {
        super::wire_history::enable(&provider, &mut candidate)?;
    }
    ensure(
        candidate.pending_proposals().next().is_none(),
        "permission_conflict",
        "存在未决 MLS 提案",
    )?;
    let mut targets = Vec::new();
    for member in candidate.members() {
        let context = codec::credential_context(&member.credential)?;
        if !remaining
            .iter()
            .any(|entry| entry.account_id == context.account && entry.device_id == context.device)
        {
            targets.push(member.index);
        }
    }
    let signer = state.signer()?;
    let (commit, join) = if let Action::AddMember {
        member,
        welcome_sha256,
        ..
    }
    | Action::AddDevice {
        member,
        welcome_sha256,
        ..
    } = &mut action
    {
        let key_package =
            key_package.ok_or_else(|| LabError::new("invalid_join_material", "缺少 KeyPackage"))?;
        let package =
            permission::admission::validate_package(&key_package, &state.context.service, member)?;
        let (commit, welcome, _) = checked(
            "permission_commit",
            candidate.add_members(&provider, &signer, &[package]),
        )?;
        let welcome = checked("permission_commit", welcome.to_bytes())?;
        *welcome_sha256 = permission::commit_digest(&welcome);
        (
            commit,
            Some(permission::admission::JoinMaterial {
                key_package,
                welcome: codec::encode(&welcome),
            }),
        )
    } else {
        let (commit, _, _) = checked(
            "permission_commit",
            candidate.remove_members(&provider, &signer, &targets),
        )?;
        (commit, None)
    };
    let commit = checked("permission_commit", commit.to_bytes())?;
    // 保留加密 Commit 已消耗的旧 epoch 握手 ratchet；清除 pending 只作用于继续使用的 base。
    let base_provider = stored::provider_from(&stored::entries(&provider)?)?;
    let mut base_group = stored::group_from(state, &base_provider)?;
    checked(
        "permission_commit",
        base_group.clear_pending_commit(base_provider.storage()),
    )?;
    checked(
        "permission_commit",
        candidate.merge_pending_commit(&provider),
    )?;
    ensure(
        stored::decoded_members(state, &candidate)? == remaining,
        "permission_commit",
        "候选成员与精确变更目标不符",
    )?;
    let issued = checked("clock", SystemTime::now().duration_since(UNIX_EPOCH))?.as_secs();
    let expires = issued
        .checked_add(u64::from(validity_secs.unwrap_or(300)))
        .ok_or_else(|| LabError::new("clock", "有效期溢出"))?;
    let mut nonce = [0u8; 32];
    checked("random_source", getrandom::getrandom(&mut nonce))?;
    let statement = Statement {
        protocol_version: "rim-permission-1".into(),
        change_id,
        service_id: checkpoint.service_id.clone(),
        conversation_id: checkpoint.conversation_id.clone(),
        actor,
        previous_authorization_version: checkpoint.authorization_version.clone(),
        authorization_version: version.to_string(),
        from_state_ref: checkpoint.crypto_state_ref.clone(),
        to_state_ref: wire::state_ref(&candidate)?,
        action,
        commit_sha256: permission::commit_digest(&commit),
        nonce: codec::digest_hex(&nonce),
        issued_at_unix_secs: issued.to_string(),
        expires_at_unix_secs: expires.to_string(),
    };
    let raw = checked("permission_encoding", serde_json::to_vec(&statement))?;
    let mut signed = SIGNING_DOMAIN.to_vec();
    signed.extend(&raw);
    let change = Proof {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(
            &signer
                .sign(&signed)
                .map_err(|_| LabError::new("permission_signature", "权限签名失败"))?,
        ),
        commit_bytes: codec::encode(&commit),
    };
    permission::verify(checkpoint, &change)?;
    if let Some(join) = join {
        permission::admission::verify_material(&statement, &join)?;
        state
            .permissions
            .admission
            .materials
            .insert(statement.change_id.clone(), join);
    }
    let result = super::permission_admission::prepared(state, &change, false)?;
    state.provider = base_provider;
    state.permissions.recovery.prepare_count += 1;
    state.permissions.pending = Some(stored::Pending {
        change,
        candidate_entries: stored::entries(&provider)?,
    });
    Ok(result)
}

pub(super) fn apply(state: &mut DeviceState, change: Proof) -> Result<Value, LabError> {
    ensure(
        state.permissions.recovery.relay_receipt_key.is_none(),
        "receipt_required",
        "固定回执钥后必须通过签名回执恢复",
    )?;
    super::permission_apply::commit(state, change, false)
}
