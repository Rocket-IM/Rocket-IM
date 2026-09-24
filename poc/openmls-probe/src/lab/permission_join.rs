//! 新设备只从独立公共锚验证入群链；Welcome 成功前不创建群，也不归档前驱历史。
use super::{
    checked, codec, ensure,
    permission_admission::{self, JoinAnchor, JoinMode},
    permission_state, permissions,
    state::DeviceState,
    wire, wire_types, LabError, MAX_RECORDS,
};
use crate::permission::{
    self,
    admission::JoinMaterial,
    receipts::{self, Outcome, RecoveryRecord},
    Action, PermissionCheckpoint, Statement,
};
use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    *,
};
use serde_json::{json, Value};

pub(super) fn anchor(
    state: &mut DeviceState,
    checkpoint: PermissionCheckpoint,
    relay_receipt_key: String,
    mode: JoinMode,
) -> Result<Value, LabError> {
    ensure(
        state.group_id.is_none()
            && state.permissions.checkpoint.is_none()
            && state.permissions.admission.anchor.is_none(),
        "permission_conflict",
        "入群公共锚只能在全新无群设备固定一次",
    )?;
    checkpoint.validate()?;
    receipts::validate_key(&relay_receipt_key)?;
    let account_present = checkpoint
        .members
        .iter()
        .any(|m| m.account_id == state.context.account);
    ensure(
        checkpoint.service_id == state.context.service
            && !checkpoint.members.iter().any(|m| {
                (m.account_id == state.context.account && m.device_id == state.context.device)
                    || m.signature_key == codec::encode(&state.own_signature_key)
            })
            && match mode {
                JoinMode::Member => !account_present,
                JoinMode::Device => account_present,
            },
        "join_identity",
        "入群锚模式、账号或全新设备身份不匹配",
    )?;
    // 同账号旧设备只成为本群公共锚，不覆盖本机独立账号 roster。
    for member in &checkpoint.members {
        if member.account_id != state.context.account {
            permission_admission::pin(state, member.clone())?;
        }
    }
    permission_admission::remember(state, &checkpoint);
    state.permissions.admission.device_history_complete = true;
    state.permissions.admission.anchor = Some(JoinAnchor {
        checkpoint,
        relay_receipt_key,
        mode,
    });
    Ok(permissions::inspect(state))
}

fn verify_next(
    state: &DeviceState,
    record: &RecoveryRecord,
) -> Result<(PermissionCheckpoint, Statement), LabError> {
    ensure(
        state.group_id.is_none(),
        "already_grouped",
        "已加入后不能回退至公共入群链",
    )?;
    let anchor = state
        .permissions
        .admission
        .anchor
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "尚未独立固定入群公共锚"))?;
    let (receipt, _) = receipts::verify_receipt(&anchor.relay_receipt_key, record)?;
    ensure(
        receipt.outcome == Outcome::Accepted,
        "join_not_accepted",
        "入群链只能使用已接受权限变更",
    )?;
    let (next, statement) = permission::verify(&anchor.checkpoint, &record.change)?;
    ensure(
        !matches!(statement.action, Action::AddDevice { .. })
            || state.permissions.admission.device_history_complete,
        "device_history_unavailable",
        "旧入群锚缺少完整设备身份历史",
    )?;
    ensure(
        !state.permissions.used_nonces.contains(&statement.nonce),
        "permission_replay",
        "权限挑战已经使用",
    )?;
    ensure(
        state.permissions.admission.public_records.len() < MAX_RECORDS,
        "resource_exhausted",
        "入群公共链已满",
    )?;
    if let Action::AddMember { member, .. } | Action::AddDevice { member, .. } = &statement.action {
        let own_identity =
            member.account_id == state.context.account && member.device_id == state.context.device;
        if own_identity
            || (anchor.mode == JoinMode::Member && member.account_id == state.context.account)
        {
            ensure(
                own_identity && member.signature_key == codec::encode(&state.own_signature_key),
                "join_identity",
                "本机入群声明与固定身份不同",
            )?;
            ensure(
                anchor.mode.accepts(&statement.action),
                "join_mode_mismatch",
                "入群动作与初始固定模式不同",
            )?;
        } else {
            permission_admission::check_new_member(state, &statement.action)?;
        }
    }
    Ok((next, statement))
}

pub(super) fn advance(state: &mut DeviceState, record: RecoveryRecord) -> Result<Value, LabError> {
    ensure(
        state.group_id.is_none(),
        "already_grouped",
        "已加入后不能回退至公共入群链",
    )?;
    let parsed = Statement::parse(&codec::decode(&record.change.statement_bytes)?)?;
    if let Some(previous) = state
        .permissions
        .admission
        .public_records
        .get(&parsed.change_id)
    {
        ensure(
            previous == &record,
            "receipt_conflict",
            "公共链同 ID 对应不同证明",
        )?;
        let mut result = permissions::inspect(state);
        result["duplicate"] = json!(true);
        return Ok(result);
    }
    let (next, statement) = verify_next(state, &record)?;
    ensure(
        !next
            .members
            .iter()
            .any(|m| m.account_id == state.context.account && m.device_id == state.context.device),
        "join_required",
        "到达本机 Add 时必须实际验证 Welcome，不能越过或只推进公共水位",
    )?;
    permission_admission::remember(state, &next);
    state
        .permissions
        .admission
        .anchor
        .as_mut()
        .ok_or_else(|| LabError::new("trust_required", "缺少入群锚"))?
        .checkpoint = next;
    state.permissions.used_nonces.insert(statement.nonce);
    state
        .permissions
        .admission
        .public_records
        .insert(statement.change_id, record);
    let mut result = permissions::inspect(state);
    result["duplicate"] = json!(false);
    Ok(result)
}

pub(super) fn join(
    state: &mut DeviceState,
    record: RecoveryRecord,
    join: JoinMaterial,
) -> Result<Value, LabError> {
    let parsed = Statement::parse(&codec::decode(&record.change.statement_bytes)?)?;
    if let Some(previous) = &state.permissions.admission.joined_record {
        ensure(
            previous == &record
                && state.permissions.admission.materials.get(&parsed.change_id) == Some(&join),
            "join_conflict",
            "已加入设备只允许精确重试原入群记录和材料",
        )?;
        let mut result = permissions::inspect(state);
        result["duplicate"] = json!(true);
        return Ok(result);
    }
    let (next, statement) = verify_next(state, &record)?;
    let (Action::AddMember { member, .. } | Action::AddDevice { member, .. }) = &statement.action
    else {
        return Err(LabError::new("invalid_permission", "加入必须使用 Add 记录"));
    };
    ensure(
        member.account_id == state.context.account && member.device_id == state.context.device,
        "join_identity",
        "入群材料不是发给本机的",
    )?;
    permission::admission::verify_material(&statement, &join)?;
    ensure(
        codec::decode(&join.key_package)? == state.key_package,
        "join_identity",
        "入群 KeyPackage 与本机原始一次性材料不同",
    )?;
    let provider = permission_state::provider_from(&permission_state::entries(&state.provider)?)?;
    let message = checked(
        "welcome_validation",
        MlsMessageIn::tls_deserialize_exact(codec::decode(&join.welcome)?),
    )?;
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err(LabError::new("invalid_join_material", "预期 Welcome")),
    };
    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    // OpenMLS 此步消耗 KeyPackage；只在临时 provider 操作，后续失败不会消费有效快照。
    let processed = checked(
        "welcome_validation",
        ProcessedWelcome::new_from_welcome(&provider, &config, welcome),
    )?;
    let actual_package = processed
        .own_key_package()
        .ok_or_else(|| LabError::new("join_identity", "Welcome 未使用本机 KeyPackage"))?;
    ensure(
        checked(
            "welcome_validation",
            actual_package.tls_serialize_detached(),
        )? == state.key_package,
        "join_identity",
        "Welcome 使用的 KeyPackage 不符",
    )?;
    let staged = checked(
        "welcome_validation",
        processed.into_staged_welcome(&provider, None),
    )?;
    let sender = checked("welcome_validation", staged.welcome_sender())?;
    let context = codec::credential_context(sender.credential())?;
    let actor = next
        .members
        .iter()
        .find(|m| m.identity() == statement.actor)
        .ok_or_else(|| LabError::new("join_identity", "后继缺少入群发起设备"))?;
    ensure(
        context.service == statement.service_id
            && context.account == actor.account_id
            && context.device == actor.device_id
            && sender.signature_key().as_slice() == codec::decode(&actor.signature_key)?,
        "welcome_actor",
        "Welcome 的真实签发者与权限发起设备不同",
    )?;
    let mut group = checked("welcome_validation", staged.into_group(&provider))?;
    if let Some(plan) = &state.rebuild {
        ensure(
            group.group_id().as_slice() != codec::decode(&plan.old_group_id)?,
            "rebuild_group",
            "新通信范围不能复用旧实际MLS群",
        )?;
    }
    ensure(
        wire::state_ref(&group)? == next.crypto_state_ref
            && permission_state::decoded_members(state, &group)? == next.members,
        "welcome_context",
        "Welcome 的实际群状态或完整身份集与签名后继不同",
    )?;
    super::wire_history::enable(&provider, &mut group)?;
    let key = state
        .permissions
        .admission
        .anchor
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "缺少入群锚"))?
        .relay_receipt_key
        .clone();
    state.group_id = Some(group.group_id().as_slice().to_vec());
    state.permissions.admission.joined_epoch = Some(group.epoch().as_u64().to_string());
    state.provider = provider;
    state.wire.configuration = Some(wire_types::Configuration {
        conversation_id: next.conversation_id.clone(),
        authorization_version: next.authorization_version.clone(),
        crypto_state_ref: next.crypto_state_ref.clone(),
        members: next
            .members
            .iter()
            .map(|m| wire_types::Device {
                account_id: m.account_id.clone(),
                device_id: m.device_id.clone(),
            })
            .collect(),
    });
    permission_admission::remember(state, &next);
    state.permissions.history.past.clear();
    state.permissions.recovery.relay_receipt_key = Some(key);
    state.permissions.recovery.verified_refs.insert(
        next.authorization_version.clone(),
        next.crypto_state_ref.clone(),
    );
    state.permissions.used_nonces.insert(statement.nonce);
    state
        .permissions
        .applied
        .insert(statement.change_id.clone(), record.change.clone());
    state
        .permissions
        .recovery
        .records
        .insert(statement.change_id.clone(), record.clone());
    state
        .permissions
        .admission
        .materials
        .insert(statement.change_id, join);
    state.permissions.admission.joined_record = Some(record);
    state.permissions.checkpoint = Some(next);
    let mut result = permissions::inspect(state);
    result["duplicate"] = json!(false);
    Ok(result)
}
