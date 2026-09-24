//! 只接受固定Service钥承诺的终态；赢家仍必须从原始有效MLS状态验证。
use super::{
    checked, codec, ensure, permission_apply, permission_state::PermissionState, permissions,
    recovery_state::Intent, state::DeviceState, wire_types, LabError, MAX_RECORDS,
};
use crate::permission::{
    receipts::{self, CloseStatement, Outcome, RecoveryRecord, SignedRecord, CLOSE_DOMAIN},
    Action, Statement,
};
use openmls_traits::signatures::Signer;
use serde_json::{json, Value};

pub(super) fn check_prepare(
    state: &DeviceState,
    id: &str,
    action: &Action,
) -> Result<(), LabError> {
    ensure(
        !state.permissions.recovery.retired.contains_key(id),
        "permission_retired",
        "旧候选已经退役",
    )?;
    if let Some(intent) = &state.permissions.recovery.intent {
        ensure(
            action.same_intent(&intent.action),
            "intent_mismatch",
            "新候选必须保留原权限变更意图",
        )?;
        if state.permissions.pending.is_none() {
            ensure(
                id != intent.origin_change_id && !state.permissions.applied.contains_key(id),
                "permission_retired",
                "重准备必须使用新变更ID",
            )?;
            let cp = state
                .permissions
                .checkpoint
                .as_ref()
                .ok_or_else(|| LabError::new("trust_required", "缺少权限检查点"))?;
            ensure(
                wire_types::decimal(&cp.authorization_version)?
                    >= wire_types::decimal(&intent.minimum_version)?
                    && state
                        .permissions
                        .recovery
                        .verified_refs
                        .get(&intent.minimum_version)
                        == Some(&intent.minimum_state_ref),
                "permission_sync_required",
                "重准备前必须验证封口水位对应权限链",
            )?;
        }
    }
    Ok(())
}

pub(super) fn close_request(state: &mut DeviceState) -> Result<Value, LabError> {
    ensure(
        state.permissions.recovery.relay_receipt_key.is_some(),
        "receipt_pin_required",
        "未固定Service回执钥",
    )?;
    let pending = state
        .permissions
        .pending
        .as_ref()
        .ok_or_else(|| LabError::new("no_pending_permission", "没有待确认候选"))?;
    let original = Statement::parse(&codec::decode(&pending.change.statement_bytes)?)?;
    if let Some(close) = state.permissions.recovery.closes.get(&original.change_id) {
        return Ok(json!({"change":pending.change,"close":close}));
    }
    ensure(
        state.permissions.recovery.closes.len() < MAX_RECORDS,
        "resource_exhausted",
        "封口记录已满",
    )?;
    let statement = CloseStatement {
        protocol_version: "rim-permission-close-1".into(),
        service_id: original.service_id,
        conversation_id: original.conversation_id,
        actor: original.actor,
        change_id: original.change_id.clone(),
        proof_sha256: receipts::proof_digest(&pending.change)?,
    };
    let raw = checked("permission_encoding", serde_json::to_vec(&statement))?;
    let mut signed = CLOSE_DOMAIN.to_vec();
    signed.extend(&raw);
    let close = SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(
            &state
                .signer()?
                .sign(&signed)
                .map_err(|_| LabError::new("permission_signature", "封口签名失败"))?,
        ),
    };
    let result = json!({"change":pending.change,"close":close});
    state
        .permissions
        .recovery
        .closes
        .insert(original.change_id, close);
    Ok(result)
}

fn unfinished(state: &PermissionState) -> Result<Option<Intent>, LabError> {
    if let Some(intent) = &state.recovery.intent {
        return Ok(Some(intent.clone()));
    }
    state
        .pending
        .as_ref()
        .map(|pending| {
            let statement = Statement::parse(&codec::decode(&pending.change.statement_bytes)?)?;
            Ok(Intent {
                origin_change_id: statement.change_id,
                action: statement.action,
                minimum_version: statement.previous_authorization_version,
                minimum_state_ref: statement.from_state_ref,
                satisfied: false,
            })
        })
        .transpose()
}

fn raise_floor(intent: &mut Intent, version: &str, reference: &str) -> Result<(), LabError> {
    if version == intent.minimum_version {
        ensure(
            reference == intent.minimum_state_ref,
            "receipt_conflict",
            "同版本恢复水位冲突",
        )?;
    }
    if wire_types::decimal(version)? > wire_types::decimal(&intent.minimum_version)? {
        intent.minimum_version = version.into();
        intent.minimum_state_ref = reference.into();
    }
    Ok(())
}

pub(super) fn recover(state: &mut DeviceState, record: RecoveryRecord) -> Result<Value, LabError> {
    let key = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_ref()
        .ok_or_else(|| LabError::new("receipt_pin_required", "未固定Service回执钥"))?;
    let (receipt, statement) = receipts::verify_receipt(key, &record)?;
    if let Some(previous) = state.permissions.recovery.records.get(&statement.change_id) {
        ensure(
            *previous == record,
            "receipt_conflict",
            "相同变更出现不同Service终态",
        )?;
        let mut result = permissions::inspect(state);
        result["duplicate"] = json!(true);
        return Ok(result);
    }
    ensure(
        !state.permissions.recovery.access_removed,
        "access_removed",
        "本机已被移除，不能恢复发送",
    )?;
    ensure(
        !state
            .permissions
            .recovery
            .retired
            .contains_key(&statement.change_id),
        "permission_retired",
        "已退役候选不能复活",
    )?;
    ensure(
        state.permissions.recovery.records.len() < MAX_RECORDS
            && state.permissions.recovery.retired.len() < MAX_RECORDS
            && state.permissions.recovery.verified_refs.len() < MAX_RECORDS,
        "resource_exhausted",
        "恢复记录达到上限",
    )?;
    let cp = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "缺少可信检查点"))?;
    receipts::authenticate(cp, &record.change)?;
    let mut intent = unfinished(&state.permissions)?;
    let pending = state.permissions.pending.as_ref().map(|p| p.change.clone());
    match receipt.outcome {
        Outcome::Closed => {
            ensure(
                pending.as_ref() == Some(&record.change),
                "pending_conflict",
                "封口回执不属于当前精确候选",
            )?;
            if wire_types::decimal(&receipt.authorization_version)?
                <= wire_types::decimal(&cp.authorization_version)?
            {
                ensure(
                    state
                        .permissions
                        .recovery
                        .verified_refs
                        .get(&receipt.authorization_version)
                        == Some(&receipt.crypto_state_ref),
                    "receipt_conflict",
                    "封口水位与已验证链冲突",
                )?;
            }
            let next_intent = intent
                .as_mut()
                .ok_or_else(|| LabError::new("pending_conflict", "缺少待完成意图"))?;
            raise_floor(
                next_intent,
                &receipt.authorization_version,
                &receipt.crypto_state_ref,
            )?;
            state.permissions.pending = None;
        }
        Outcome::Accepted => {
            permission_apply::commit(state, record.change.clone(), true)?;
            if !state.permissions.recovery.access_removed {
                let next = state
                    .permissions
                    .checkpoint
                    .as_ref()
                    .ok_or_else(|| LabError::new("trust_required", "缺少已应用检查点"))?;
                state.permissions.recovery.verified_refs.insert(
                    next.authorization_version.clone(),
                    next.crypto_state_ref.clone(),
                );
                if let Some(original) = &mut intent {
                    let satisfied = match &original.action {
                        Action::RemoveMember { account_id } => {
                            !next.members.iter().any(|m| m.account_id == *account_id)
                        }
                        Action::RevokeDevice { .. } => statement.action == original.action,
                        Action::AddMember { member, .. } | Action::AddDevice { member, .. } => {
                            original.action.same_intent(&statement.action)
                                && next.members.contains(member)
                        }
                    };
                    original.satisfied |= satisfied;
                    raise_floor(
                        original,
                        &next.authorization_version,
                        &next.crypto_state_ref,
                    )?;
                    if original.satisfied
                        && state
                            .permissions
                            .recovery
                            .verified_refs
                            .get(&original.minimum_version)
                            == Some(&original.minimum_state_ref)
                    {
                        intent = None;
                    }
                }
            }
        }
    }
    if let Some(old) = pending {
        let id = Statement::parse(&codec::decode(&old.statement_bytes)?)?.change_id;
        if old != record.change || receipt.outcome == Outcome::Closed {
            state
                .permissions
                .recovery
                .retired
                .insert(id, receipts::proof_digest(&old)?);
        }
    }
    state.permissions.recovery.intent = intent;
    state
        .permissions
        .recovery
        .records
        .insert(statement.change_id, record);
    let mut result = permissions::inspect(state);
    result["duplicate"] = json!(false);
    Ok(result)
}
