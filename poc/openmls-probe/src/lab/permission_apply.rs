//! 只在权限证明和实际MLS核对后提交候选；外层负责回执与未完成意图。
use super::{
    codec, ensure, permission_state as stored, state::DeviceState, wire, wire_types, LabError,
    MAX_RECORDS,
};
use crate::permission::{self, Proof, Statement};
use serde_json::{json, Value};
pub(super) fn commit(
    state: &mut DeviceState,
    change: Proof,
    allow_replacement: bool,
) -> Result<Value, LabError> {
    let statement = Statement::parse(&codec::decode(&change.statement_bytes)?)?;
    if let Some(old) = state.permissions.applied.get(&statement.change_id) {
        ensure(
            *old == change,
            "permission_conflict",
            "相同变更 ID 对应不同原始证明",
        )?;
        return Ok(
            json!({"checkpoint":state.permissions.checkpoint,"statement":statement,"duplicate":true}),
        );
    }
    if let Some(pending) = &state.permissions.pending {
        ensure(
            pending.change == change || allow_replacement,
            "pending_conflict",
            "不同变更与待确认候选冲突，需独立协调",
        )?;
    }
    ensure(
        state.permissions.applied.len() < MAX_RECORDS,
        "resource_exhausted",
        "权限记录已满",
    )?;
    ensure(
        !state.permissions.used_nonces.contains(&statement.nonce),
        "permission_replay",
        "权限挑战已经消耗",
    )?;
    let checkpoint = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "尚未建立权限检查点"))?;
    let (next, statement) = permission::verify(checkpoint, &change)?;
    ensure(
        !matches!(
            statement.action,
            permission::Action::AddMember { .. } | permission::Action::AddDevice { .. }
        ) || state.permissions.recovery.relay_receipt_key.is_some(),
        "receipt_pin_required",
        "Add 不支持无固定 Service 回执钥的旧模式",
    )?;
    super::permission_admission::check_new_member(state, &statement.action)?;
    stored::validate_current(state, checkpoint, &state.group()?)?;
    let old_checkpoint = checkpoint.clone();
    let old_epoch = state.group()?.epoch().as_u64();
    let mut self_removed = false;
    let provider = if let Some(pending) = state
        .permissions
        .pending
        .as_ref()
        .filter(|pending| pending.change == change)
    {
        stored::provider_from(&pending.candidate_entries)?
    } else {
        let provider = stored::provider_from(&stored::entries(&state.provider)?)?;
        let mut current = stored::group_from(state, &provider)?;
        if state.permissions.recovery.relay_receipt_key.is_some() {
            super::wire_history::enable(&provider, &mut current)?;
        }
        self_removed =
            super::permission_commit::apply(state, &provider, &change, &statement, &next)?;
        provider
    };
    if self_removed {
        ensure(
            allow_replacement,
            "permission_commit",
            "旧模式不能将本机移除记录为完整后继",
        )?;
        // OpenMLS 对被移除者仅验证发送者和移除提案，无法验证新epoch确认/完整上下文。
        state.provider = provider;
        state.permissions.recovery.access_removed = true;
        state.permissions.recovery.service_target = Some(next);
        state
            .permissions
            .used_nonces
            .insert(statement.nonce.clone());
        state
            .permissions
            .applied
            .insert(statement.change_id.clone(), change);
        state.permissions.pending = None;
        return Ok(json!({"access_removed":true,"duplicate":false}));
    }
    let mut group = stored::group_from(state, &provider)?;
    ensure(
        wire::state_ref(&group)? == next.crypto_state_ref
            && stored::decoded_members(state, &group)? == next.members,
        "permission_commit",
        "实际 MLS 后继状态与签名权限结果不符",
    )?;
    super::wire_history::archive(state, old_epoch, old_checkpoint, &mut group, &provider)?;
    super::permission_admission::remember(state, &next);
    state.provider = provider;
    state.wire.configuration = Some(wire_types::Configuration {
        conversation_id: next.conversation_id.clone(),
        authorization_version: next.authorization_version.clone(),
        crypto_state_ref: next.crypto_state_ref.clone(),
        members: next
            .members
            .iter()
            .map(|member| wire_types::Device {
                account_id: member.account_id.clone(),
                device_id: member.device_id.clone(),
            })
            .collect(),
    });
    state
        .permissions
        .used_nonces
        .insert(statement.nonce.clone());
    state
        .permissions
        .applied
        .insert(statement.change_id.clone(), change);
    state.permissions.pending = None;
    state.permissions.checkpoint = Some(next.clone());
    state.permissions.recovery.prepare_count = 0;
    Ok(json!({"checkpoint":next,"statement":statement,"duplicate":false}))
}
