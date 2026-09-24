//! 全新候选只可进入明确批准的新群；不提供旧群或历史恢复入口。
use super::{
    checked, codec, ensure, permission_state, state::DeviceState, store::LockedDevice, Context,
    LabError, Operation, Request,
};
use crate::rollback_anchor::{self as anchor, rebuild::Plan, Signed};
use openmls_traits::signatures::Signer;
use serde_json::{json, Value};

pub(super) fn healthy(state: &DeviceState) -> Result<(), LabError> {
    ensure(
        !state.permissions.consistency.paused(),
        "rebuild_consistency",
        "已有一致性检查或暂停，不能通过重建绕过",
    )?;
    ensure(
        state.permissions.pending.is_none()
            && state.permissions.recovery.intent.is_none()
            && state.permissions.recovery.service_target.is_none()
            && !state.permissions.recovery.access_removed,
        "rebuild_permission",
        "已有权限候选、恢复目标或访问移除，不能重建",
    )?;
    let cp = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("rebuild_permission", "重建需要已验证签名权限范围"))?;
    cp.validate()?;
    ensure(
        state.permissions.admission.device_history_complete
            && cp.members.iter().any(|m| {
                m.account_id == state.context.account
                    && m.device_id == state.context.device
                    && m.signature_key == codec::encode(&state.own_signature_key)
            }),
        "rebuild_permission",
        "本机身份不在完整已验证成员范围",
    )
}

pub(super) fn candidate(
    locked: &LockedDevice,
    request: Request,
    context: Context,
) -> Result<Value, LabError> {
    match request.operation {
        Operation::RebuildInit { mut template } => {
            ensure(
                !request.directory.join("state.enc").exists(),
                "rebuild_exists",
                "候选只能在无快照目录初始化；已有结果须读取原提案",
            )?;
            ensure(
                template.successor_scope.service == context.service
                    && template.successor_scope.account == context.account
                    && template.successor_scope.device == context.device,
                "rebuild_scope",
                "候选上下文与计划不同",
            )?;
            template
                .validate()
                .map_err(|e| LabError::new("rebuild_plan", e.to_string()))?;
            let mut state = DeviceState::new(context)?;
            template.successor_scope.identity_key = anchor::encode_hex(&state.own_signature_key);
            template.key_package_sha256 = anchor::hash_bytes(&state.key_package);
            // 初始文件摘要不能递归写入自身；持久模板固定占位值，offer从同次核验读取产生完整计划。
            template.successor_head = "0".repeat(64);
            template
                .validate()
                .map_err(|e| LabError::new("rebuild_plan", e.to_string()))?;
            state.rebuild = Some(template.clone());
            locked.save(&mut state, request.failpoint)?;
            template.successor_head = anchor::encode_hex(
                &locked
                    .saved_commitment
                    .get()
                    .ok_or_else(|| LabError::new("rebuild_save", "缺少已保存候选承诺"))?,
            );
            Ok(
                json!({"ok":true,"result":{"identity":state.public_identity(),"plan":template,"status":"quarantined"}}),
            )
        }
        Operation::RebuildOffer => {
            let head = super::rollback_io::state_hash(&request.directory)?;
            let state = locked
                .metadata_committed(
                    &context,
                    &checked("rebuild_head", anchor::decode_hex(&head))?,
                )?
                .ok_or_else(|| LabError::new("rebuild_missing", "缺少完整候选"))?;
            let plan = initial_plan(&state, &head)?;
            Ok(
                json!({"ok":true,"result":{"identity":state.public_identity(),"plan":plan,"status":"quarantined"}}),
            )
        }
        _ => Err(LabError::new("rebuild_operation", "不是候选初始化操作")),
    }
}

pub(super) fn initial_plan(state: &DeviceState, head: &str) -> Result<Plan, LabError> {
    let mut plan = state
        .rebuild
        .clone()
        .ok_or_else(|| LabError::new("rebuild_candidate", "只能使用新生成的隔离候选"))?;
    ensure(
        state.group_id.is_none()
            && state.permissions.checkpoint.is_none()
            && state.permissions.admission.anchor.is_none()
            && state.outbox.is_empty()
            && state.inbox.is_empty()
            && state.control_outbox.is_empty()
            && state.wire.outbox.is_empty()
            && state.wire.inbox.is_empty()
            && state.wire_sync.stream_id.is_none()
            && state.wire_sync.download_cursor == 0
            && state.wire_sync.processed_cursor == 0,
        "rebuild_candidate",
        "候选已经使用，不能重新登记为初始快照",
    )?;
    ensure(
        plan.successor_scope.identity_key == anchor::encode_hex(&state.own_signature_key)
            && plan.successor_scope.service == state.context.service
            && plan.successor_scope.account == state.context.account
            && plan.successor_scope.device == state.context.device
            && plan.key_package_sha256 == anchor::hash_bytes(&state.key_package),
        "rebuild_candidate",
        "候选身份或一次性材料与计划不同",
    )?;
    plan.successor_head = head.into();
    checked("rebuild_plan", plan.validate())?;
    Ok(plan)
}

pub(super) fn guard(state: &DeviceState, operation: &Operation) -> Result<(), LabError> {
    if let Operation::RebuildApprove { plan } = operation {
        approval_source(state, plan)?;
    }
    let Some(plan) = &state.rebuild else {
        return Ok(());
    };
    ensure(
        std::env::var_os("RIM_ROLLBACK_ANCHOR_CONFIG").is_some(),
        "rebuild_anchor_required",
        "隔离候选及其后继必须由可信锚启动",
    )?;
    ensure(
        !matches!(
            operation,
            Operation::WireDownload { .. } | Operation::WireDownloadSigned { .. }
        ),
        "rebuild_sync_unavailable",
        "重建设备必须使用独立授权的签名分页，不能导入普通流或游标",
    )?;
    if matches!(operation, Operation::WireProcess) {
        ensure(
            state.rebuild_stream.binding.is_some(),
            "rebuild_sync_unavailable",
            "重建设备尚未绑定独立新消息流",
        )?;
        healthy(state)?;
    }
    ensure(
        !matches!(
            operation,
            Operation::HistoryRequest { .. }
                | Operation::HistoryExport { .. }
                | Operation::HistoryImport { .. }
                | Operation::RebuildApprove { .. }
        ),
        "rebuild_history_disabled",
        "本项后继不提供历史迁移或后继再重建授权",
    )?;
    if state.group_id.is_some() {
        ensure(
            state
                .permissions
                .checkpoint
                .as_ref()
                .is_some_and(|cp| cp.conversation_id == plan.trust.checkpoint.conversation_id)
                && state.group_id.as_ref() != Some(&codec::decode(&plan.old_group_id)?),
            "rebuild_group",
            "重建后继必须保持新通信范围",
        )?;
        return Ok(());
    }
    match operation {
        Operation::PermissionDeviceJoinAnchor {
            checkpoint,
            relay_receipt_key,
        } => ensure(
            checkpoint == &plan.trust.checkpoint
                && relay_receipt_key == &plan.trust.relay_receipt_key,
            "rebuild_trust",
            "入群锚必须精确匹配独立批准范围",
        ),
        Operation::PermissionJoin { record, join } => {
            let statement = crate::permission::Statement::parse(&codec::decode(
                &record.change.statement_bytes,
            )?)?;
            ensure(
                statement.actor == plan.trust.authorizer.identity()
                    && statement.previous_authorization_version
                        == plan.trust.checkpoint.authorization_version
                    && statement.from_state_ref == plan.trust.checkpoint.crypto_state_ref
                    && statement.conversation_id == plan.trust.checkpoint.conversation_id
                    && anchor::hash_bytes(&codec::decode(&join.key_package)?)
                        == plan.key_package_sha256,
                "rebuild_join",
                "仅允许批准设备在精确前序上的本次加入",
            )?;
            ensure(
                matches!(&statement.action, crate::permission::Action::AddDevice { member, history_policy, .. }
                if member.account_id == state.context.account && member.device_id == state.context.device
                && member.signature_key == codec::encode(&state.own_signature_key) && history_policy == "from_join"),
                "rebuild_join",
                "重建仅允许无旧历史的同账号新设备",
            )
        }
        Operation::Inspect
        | Operation::PermissionInspect
        | Operation::WireReadPending
        | Operation::WireReadInspect => Ok(()),
        _ => Err(LabError::new(
            "rebuild_quarantined",
            "尚未验证新范围的实际Welcome，不能使用密码状态",
        )),
    }
}

fn approval_source(state: &DeviceState, plan: &Plan) -> Result<(), LabError> {
    ensure(
        std::env::var_os("RIM_ROLLBACK_ANCHOR_CONFIG").is_some(),
        "rebuild_anchor_required",
        "独立批准设备也必须使用可信锚启动，不能回滚旧状态后再批准",
    )?;
    checked("rebuild_plan", plan.validate())?;
    healthy(state)?;
    ensure(
        state.rebuild.is_none()
            && state.permissions.checkpoint.as_ref() == Some(&plan.trust.checkpoint)
            && state.permissions.recovery.relay_receipt_key.as_ref()
                == Some(&plan.trust.relay_receipt_key)
            && plan.trust.authorizer.account_id == state.context.account
            && plan.trust.authorizer.device_id == state.context.device
            && plan.trust.authorizer.signature_key == codec::encode(&state.own_signature_key),
        "rebuild_authorizer",
        "本机不是计划固定的健康独立批准设备",
    )?;
    let group = state.group()?;
    ensure(
        group.is_active() && codec::encode(group.group_id().as_slice()) != plan.old_group_id,
        "rebuild_group",
        "批准者须位于另一个有效实际MLS群",
    )?;
    permission_state::validate_current(state, &plan.trust.checkpoint, &group)?;
    ensure(
        !state.permissions.admission.seen_members.iter().any(|m| {
            (m.account_id == plan.successor_scope.account
                && m.device_id == plan.successor_scope.device)
                || codec::decode(&m.signature_key)
                    .is_ok_and(|key| anchor::encode_hex(&key) == plan.successor_scope.identity_key)
        }),
        "rebuild_reentry",
        "不批准旧设备或旧公钥重新加入",
    )
}

pub(super) fn approve(state: &DeviceState, plan: Plan) -> Result<Value, LabError> {
    approval_source(state, &plan)?;
    let raw = checked("rebuild_encoding", serde_json::to_vec(&plan))?;
    let signature = state
        .signer()?
        .sign(&checked(
            "rebuild_encoding",
            anchor::rebuild::approval_signing_bytes(&plan),
        )?)
        .map_err(|_| LabError::new("rebuild_signature", "独立批准签名失败"))?;
    let approval = Signed {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(&signature),
    };
    checked(
        "rebuild_signature",
        anchor::rebuild::verify_approval(&plan, &approval),
    )?;
    Ok(
        json!({"approval":approval,"plan_sha256":checked("rebuild_plan",plan.digest())?,"assurance":"synthetic_local"}),
    )
}
