//! 旧范围只读校验及一次性关联；正常后继操作继续走原独立锚事务。
use super::{
    checked, ensure, rebuild_state,
    rollback_io::{self, Config},
    store::LockedDevice,
    Context, LabError,
};
use crate::rollback_anchor::{
    self as anchor,
    rebuild::{self, Action, Plan, Response, Status},
    Signed,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;

fn rpc(
    config: &Config,
    plan: &Plan,
    approval: &Signed,
    action: Action,
) -> Result<(Response, Signed, Signed), LabError> {
    let challenge = rollback_io::random_hex()?;
    let request = checked(
        "rebuild_request",
        rebuild::sign_rebuild_request(
            plan,
            &challenge,
            action,
            &checked("anchor_key", anchor::decode_hex(&config.client_seed))?,
        ),
    )?;
    let op = match action {
        Action::Link => "rebuild",
        Action::Cancel => "cancel_rebuild",
        Action::Inspect => "inspect_rebuild",
    };
    let input = checked(
        "rebuild_encoding",
        serde_json::to_vec(&json!({"op":op,
        "directory":config.anchor_directory,"plan":plan,"approval":approval,
        "client_proof":request,"challenge":challenge})),
    )?;
    let output = rollback_io::invoke(&config.helper_path, &input)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        ok: bool,
        response: Signed,
    }
    let reply: Reply = checked("rebuild_response", serde_json::from_slice(&output))?;
    ensure(reply.ok, "rebuild_response", "锚未返回可验证重建事实")?;
    let response = checked(
        "rebuild_response",
        rebuild::verify_rebuild_response(
            &reply.response,
            &config.anchor_public_key,
            plan,
            &request,
        ),
    )?;
    Ok((response, request, reply.response))
}

pub(super) fn execute(
    config: &Config,
    locked: &LockedDevice,
    directory: &Path,
    context: &Context,
    plan: Plan,
    approval: Signed,
    successor_directory: Option<&Path>,
) -> Result<Value, LabError> {
    checked("rebuild_plan", plan.validate())?;
    ensure(
        config.scope == plan.old_scope
            && config.anchor_public_key == plan.anchor_public_key
            && config.rebuild_trust.as_ref() == Some(&plan.trust),
        "rebuild_trust",
        "重建计划不匹配预先独立固定的旧范围与授权来源",
    )?;
    checked(
        "rebuild_approval",
        rebuild::verify_approval(&plan, &approval),
    )?;
    // 即使完整旧目录被恢复，也只能读独立锚承诺的精确前序，不加载密码provider。
    let mut old = locked
        .metadata_committed(
            context,
            &checked("rebuild_head", anchor::decode_hex(&plan.old_head))?,
        )?
        .ok_or_else(|| LabError::new("rebuild_state", "旧范围缺少完整已承诺状态"))?;
    super::consistency_state::preflight(&mut old)?;
    rebuild_state::healthy(&old)?;
    ensure(
        anchor::encode_hex(&old.own_signature_key) == plan.old_scope.identity_key
            && old
                .permissions
                .checkpoint
                .as_ref()
                .is_some_and(|cp| cp.conversation_id == plan.old_conversation_id)
            && old
                .group_id
                .as_ref()
                .is_some_and(|id| super::codec::encode(id) == plan.old_group_id),
        "rebuild_state",
        "旧身份、群或范围不匹配",
    )?;
    let (response, anchor_request, anchor_response) =
        if let Some(successor_directory) = successor_directory {
            let observed = rpc(config, &plan, &approval, Action::Inspect)?;
            if observed.0.status == Status::Unlinked {
                ensure(
                    !directory
                        .join("anchor-journal.enc")
                        .try_exists()
                        .map_err(|e| LabError::new("rebuild_journal", e.to_string()))?,
                    "rebuild_recoverable",
                    "存在结果journal；先核验原事务，不能改走本项最小重建",
                )?;
                let local = checked("rebuild_directory", std::fs::canonicalize(directory))?;
                let target = checked(
                    "rebuild_directory",
                    std::fs::canonicalize(successor_directory),
                )?;
                ensure(
                    !local.starts_with(&target)
                        && !target.starts_with(&local)
                        && !target.starts_with(&config.anchor_directory)
                        && !config.anchor_directory.starts_with(&target),
                    "rebuild_directory",
                    "旧设备、新候选与独立锚必须分开",
                )?;
                let candidate = LockedDevice::open(&target)?;
                let new_context = Context {
                    service: plan.successor_scope.service.clone(),
                    account: plan.successor_scope.account.clone(),
                    device: plan.successor_scope.device.clone(),
                };
                let new_state = candidate
                    .metadata_committed(
                        &new_context,
                        &checked("rebuild_head", anchor::decode_hex(&plan.successor_head))?,
                    )?
                    .ok_or_else(|| LabError::new("rebuild_candidate", "新候选未完整落盘"))?;
                ensure(
                    rebuild_state::initial_plan(&new_state, &plan.successor_head)? == plan,
                    "rebuild_candidate",
                    "初始候选与独立批准计划不符",
                )?;
                // 同一候选锁持有至关联响应，客户端既不能推进候选也不能在另一目录授权第二后继。
                rpc(config, &plan, &approval, Action::Link)?
            } else {
                observed
            }
        } else {
            rpc(config, &plan, &approval, Action::Cancel)?
        };
    Ok(
        json!({"ok":true,"result":{"status":response.status,"cancelled":response.cancelled,
        "plan_sha256":response.plan_sha256,"scope":plan.successor_scope,
        "old_scope":plan.old_scope,"old_active_txn":plan.old_txn,
        "successor_head":response.successor_head,"successor_revision":response.successor_revision,
        "anchor_request":anchor_request,"anchor_response":anchor_response,
        "freshness":"unknown","assurance":"synthetic_local"}}),
    )
}
