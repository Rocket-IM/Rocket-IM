//! 准备候选前的公开元数据检查；锚预约前和真实执行共用，不恢复密码 provider。
use super::{codec, ensure, state::DeviceState, wire_types, LabError, MAX_RECORDS};
use crate::permission::{Action, Identity, Proof, Statement};

pub(super) fn check<'a>(
    state: &'a DeviceState,
    change_id: &str,
    action: &Action,
    validity_secs: Option<u16>,
) -> Result<Option<&'a Proof>, LabError> {
    wire_types::id(change_id)?;
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
    super::permission_recovery::check_prepare(state, change_id, action)?;
    if let Some(pending) = &state.permissions.pending {
        let statement = Statement::parse(&codec::decode(&pending.change.statement_bytes)?)?;
        ensure(
            statement.change_id == change_id
                && statement.action.same_intent(action)
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
        super::permission_admission::prepared(state, &pending.change, true)?;
        return Ok(Some(&pending.change));
    }
    if let Some(change) = state.permissions.applied.get(change_id) {
        let statement = Statement::parse(&codec::decode(&change.statement_bytes)?)?;
        ensure(
            statement.action.same_intent(action),
            "permission_conflict",
            "相同变更 ID 对应不同意图",
        )?;
        super::permission_admission::prepared(state, change, true)?;
        return Ok(Some(change));
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
    checkpoint.remaining(&actor, action)?;
    super::permission_admission::check_new_member(state, action)?;
    wire_types::decimal(&checkpoint.authorization_version)?
        .checked_add(1)
        .ok_or_else(|| LabError::new("permission_version", "权限版本溢出"))?;
    ensure(state.group_id.is_some(), "no_group", "尚未入群")?;
    Ok(None)
}
