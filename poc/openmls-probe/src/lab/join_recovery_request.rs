//! 恢复意图及控制原件先保存后外发；没有有效关闭不能重做未知候选。
use super::{ensure, join_recovery_state as stored, state::DeviceState, LabError};
use crate::{join_recovery as p, permission::receipts::SignedRecord};
use serde_json::{json, Value};

pub(super) fn trusted_members(state: &DeviceState) -> Result<(), LabError> {
    for member in &stored::checkpoint(state)?.members {
        super::identity_gate::require(
            state,
            &super::identity_state::object(
                &state.context.service,
                &member.account_id,
                &member.device_id,
                &member.signature_key,
            ),
        )?;
    }
    Ok(())
}
pub(super) fn intent(state: &DeviceState, i: &p::Intent) -> Result<(), LabError> {
    p::Request::Intent(Box::new(i.clone())).validate()?;
    super::join_recovery_witness_config::intent(state, i)?;
    let s = stored::get(state)?;
    let root = s
        .roots
        .get(&i.root_admission.change_id)
        .ok_or_else(|| LabError::new("recovery_chain_missing", "缺少原接受入口"))?;
    let (reference, target, device, _) = p::root(&root.record, stored::key(state)?)?;
    ensure(
        reference == i.root_admission
            && target == i.signer
            && root.current == i.current_admission
            && p::commit_group(&root.record.change.commit_bytes)? == i.scope.group_id,
        "recovery_superseded",
        "恢复入口不匹配",
    )?;
    let cp = stored::checkpoint(state)?;
    p::authorize(cp, i, device)?;
    ensure(
        p::Floor::from(cp) == i.predecessor,
        "recovery_predecessor_changed",
        "前驱不匹配",
    )?;
    if let Some(known) = &state.permissions.consistency.highest_observed {
        ensure(
            super::consistency_state::version(known)? <= super::consistency_state::version(cp)?
                && super::join_recovery_consistency::covers(state, known)?,
            "consistency_paused",
            "已知水位尚未补齐",
        )?;
    }
    for member in [&i.signer, &i.actor] {
        super::key_packages::target_ready(state, member)?;
    }
    for reference in &i.directory_refs {
        let head = state
            .key_packages
            .as_ref()
            .and_then(|s| s.directories.get(&reference.account_id))
            .and_then(|d| d.snapshots.last())
            .ok_or_else(|| LabError::new("directory_required", "缺少准确目录"))?;
        ensure(
            crate::key_package::directory::parse(head)?.version == reference.version
                && crate::key_package::directory::hash(head)? == reference.sha256,
            "directory_stale",
            "目录引用不符",
        )?;
    }
    let now = super::join_recovery::now()?;
    ensure(
        i.issued_at_unix_secs.parse::<u64>().is_ok_and(|v| v <= now)
            && i.expires_at_unix_secs.parse::<u64>().is_ok_and(|v| now < v),
        "recovery_expired",
        "首次恢复意图不在当前有效区间",
    )?;
    trusted_members(state)
}
pub(super) fn check(
    state: &DeviceState,
    request: &p::Request,
    intent_proof: Option<&SignedRecord>,
) -> Result<(), LabError> {
    request.validate()?;
    ensure(
        *request.signer() == super::key_package_state::own(state)
            && request.scope().service_id == state.context.service,
        "permission_denied",
        "只能签署本机准确身份",
    )?;
    let s = stored::get(state)?;
    if let Some(previous) = s.requests.get(request.id()) {
        ensure(
            p::parse_request(previous)? == *request,
            "idempotency_conflict",
            "请求 ID 不可改字节",
        )?;
        return Ok(());
    }
    ensure(
        !s.requests
            .values()
            .any(|proof| p::parse_request(proof).is_ok_and(|r| r.nonce() == request.nonce())),
        "idempotency_conflict",
        "nonce 已使用",
    )?;
    ensure(
        s.requests.len() < 320,
        "resource_exhausted",
        "恢复请求账本已满",
    )?;
    if !matches!(request,p::Request::Control(c) if c.kind==p::ControlKind::Close) {
        ensure(
            s.records.len() + s.public_advances.len() + s.closed.len() < 64
                && serde_json::to_vec(s)
                    .map_err(|e| LabError::new("recovery_encoding", e.to_string()))?
                    .len()
                    + 1536 * 1024
                    <= 8 * 1024 * 1024,
            "resource_exhausted",
            "新恢复须预留终态空间",
        )?;
    }
    match request {
        p::Request::Intent(i) => {
            intent(state, i)?;
            ensure(
                state.group_id.is_none() && state.permissions.admission.joined_record.is_none(),
                "already_grouped",
                "恢复不得覆盖健康群",
            )?;
            let pool = state
                .key_packages
                .as_ref()
                .ok_or_else(|| LabError::new("key_package_missing", "缺少本机材料"))?;
            let root = &s.roots[&i.root_admission.change_id];
            let old = pool
                .packages
                .get(&root.package_sha256)
                .ok_or_else(|| LabError::new("key_package_missing", "当前入口缺少本机 bundle"))?;
            ensure(
                !old.consumed
                    && super::join_recovery::now()?
                        >= old
                            .material
                            .not_after
                            .parse::<u64>()
                            .map_err(|_| LabError::new("recovery_state", "期限损坏"))?,
                "recovery_not_expired",
                "当前入口尚未过期或已消费",
            )?;
            let new = pool
                .packages
                .get(&i.key_package_sha256)
                .ok_or_else(|| LabError::new("key_package_missing", "缺少新私有 bundle"))?;
            ensure(
                !new.consumed
                    && new.material.init_key != old.material.init_key
                    && new.material.leaf_key != old.material.leaf_key,
                "key_package_reuse",
                "必须使用新秘密",
            )?;
            crate::key_package::material::current(&new.material, super::join_recovery::now()?)?;
            ensure(pool.requests.values().any(|r|r.receipt.as_ref().is_some_and(|receipt|crate::key_package::verify_receipt(stored::key(state).unwrap_or(""),receipt)
                .is_ok_and(|r|matches!(r.result,crate::key_package::ResultBody::Published{hashes,..} if hashes.contains(&i.key_package_sha256))))),"key_package_unavailable","新包尚无发布成功原件")?;
        }
        p::Request::Control(c) => {
            let proof = intent_proof
                .ok_or_else(|| LabError::new("recovery_invalid", "控制请求需要目标意图"))?;
            let i = p::parse_intent(proof)?;
            ensure(
                c.scope == i.scope
                    && c.recovery_id == i.request_id
                    && c.change_id == i.change_id
                    && c.intent_sha256 == p::signed_digest(proof)?
                    && (c.signer == i.actor
                        || (c.kind == p::ControlKind::Close && c.signer == i.signer)),
                "recovery_invalid",
                "控制原件绑定无效",
            )?;
            if c.kind == p::ControlKind::Claim {
                intent(state, &i)?;
                ensure(
                    state.group_id.is_some(),
                    "recovery_r1_required",
                    "批准者必须拥有真实前驱群",
                )?;
            } else {
                ensure(
                    stored::checkpoint(state)?.members.contains(&c.signer),
                    "permission_denied",
                    "关闭需当前访问权",
                )?;
            }
        }
    }
    if !matches!(request,p::Request::Control(c) if c.kind==p::ControlKind::Close) {
        for old in s.requests.values() {
            let old = p::parse_request(old)?;
            let rid = match &old {
                p::Request::Intent(i) => &i.request_id,
                p::Request::Control(c) if c.kind == p::ControlKind::Claim => &c.recovery_id,
                _ => continue,
            };
            ensure(
                s.closed.contains_key(rid)
                    || s.records.values().any(|a| {
                        p::parse_intent(&a.record.public().bundle.intent)
                            .is_ok_and(|i| i.request_id == *rid)
                    }),
                "recovery_pending",
                "已有请求尚无确定终态",
            )?;
        }
    }
    Ok(())
}
pub(super) fn sign(
    state: &mut DeviceState,
    request: p::Request,
    intent: Option<SignedRecord>,
) -> Result<Value, LabError> {
    check(state, &request, intent.as_ref())?;
    if let Some(proof) = stored::get(state)?.requests.get(request.id()) {
        return Ok(json!({"proof":proof,"duplicate":true}));
    }
    let proof = p::sign(&request, request.domain()?, &state.signer()?)?;
    match &request {
        p::Request::Intent(i) => super::join_recovery_witness_config::pin(state, i)?,
        p::Request::Control(_) => {
            if let Some(proof) = &intent {
                super::join_recovery_witness_config::pin(state, &p::parse_intent(proof)?)?;
            }
        }
    }
    stored::get_mut(state)?
        .requests
        .insert(request.id().into(), proof.clone());
    stored::budget(stored::get(state)?)?;
    Ok(json!({"proof":proof,"duplicate":false}))
}
pub(super) fn resolve(
    state: &mut DeviceState,
    intent: SignedRecord,
    receipt: SignedRecord,
) -> Result<Value, LabError> {
    let i = p::parse_intent(&intent)?;
    let r = p::verify_receipt(stored::key(state)?, &receipt)?;
    p::receipt_context(&r, &i, &intent)?;
    let p::ResultBody::Closed {
        allocation_sha256,
        checkpoint,
        ..
    } = &r.result
    else {
        return Err(LabError::new(
            "recovery_accepted",
            "已接受须读取原候选并完成真实 R1",
        ));
    };
    let s = stored::get(state)?;
    let root = s
        .roots
        .get(&i.root_admission.change_id)
        .ok_or_else(|| LabError::new("recovery_chain_missing", "关闭缺少原接受入口"))?;
    let (reference, target, _, _) = p::root(&root.record, stored::key(state)?)?;
    let own = super::key_package_state::own(state);
    ensure(
        reference == i.root_admission
            && target == i.signer
            && (own == i.signer || own == i.actor)
            && p::commit_group(&root.record.change.commit_bytes)? == i.scope.group_id
            && i.scope.service_id == state.context.service
            && i.scope.conversation_id == stored::checkpoint(state)?.conversation_id,
        "permission_denied",
        "关闭不属于当前恢复范围",
    )?;
    ensure(
        s.requests.values().any(|proof| {
            p::parse_request(proof).is_ok_and(|request| match request {
                p::Request::Intent(old) => *old == i,
                p::Request::Control(c) => {
                    c.recovery_id == i.request_id
                        && p::signed_digest(&intent).is_ok_and(|hash| c.intent_sha256 == hash)
                }
            })
        }),
        "recovery_request_missing",
        "关闭缺少本机原请求",
    )?;
    if s.closed.get(&i.request_id) == Some(&receipt) {
        // 原件重试不能把后来已经补齐的设备重新判为回退。
        return Ok(json!({"duplicate":true}));
    }
    if let Some(pending) = &s.pending {
        ensure(
            pending.bundle.intent == intent
                && *allocation_sha256 == Some(p::signed_digest(&pending.bundle.allocation)?),
            "receipt_conflict",
            "关闭未绑定原候选",
        )?;
    }
    super::join_recovery_consistency::observe(
        state,
        super::join_recovery_evidence::Observation::Closed {
            intent,
            receipt: receipt.clone(),
        },
    )?;
    super::join_recovery_consistency::close_floor(state, checkpoint)?;
    if super::join_recovery_consistency::forked(state) {
        return Ok(super::join_recovery_consistency::paused(state));
    }
    let s = stored::get_mut(state)?;
    s.pending = None;
    s.closed.insert(i.request_id, receipt);
    Ok(json!({"duplicate":false,"state":"closed"}))
}
