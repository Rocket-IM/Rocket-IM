//! 领取凭证只授权一个原候选；实际 MLS/权限验证继续走已有入口。
use super::{
    codec, ensure, key_packages, permission_admission::JoinMode, state::DeviceState, LabError,
};
use crate::{
    key_package::{self as protocol, Action, ResultBody},
    permission::{
        admission::{Allocation, JoinMaterial},
        Member, Statement,
    },
};
use serde_json::Value;
pub(super) fn allocation(
    state: &DeviceState,
    id: &str,
) -> Result<(protocol::Request, Allocation, String), LabError> {
    let intent = state
        .key_packages
        .as_ref()
        .and_then(|s| s.requests.get(id))
        .ok_or_else(|| LabError::new("key_package_pending", "缺少原领取意图"))?;
    let request = protocol::parse(&intent.proof)?;
    let Action::Claim { target, .. } = &request.action else {
        return Err(LabError::new("key_package_context", "预期领取"));
    };
    key_packages::target_ready(state, target)?;
    let receipt = intent
        .receipt
        .as_ref()
        .ok_or_else(|| LabError::new("key_package_pending", "领取结果不明，重试原请求"))?;
    let result = protocol::verify_receipt(&intent.source_key, receipt)?;
    let ResultBody::Allocated { key_package, .. } = result.result else {
        return Err(LabError::new(
            "key_package_unavailable",
            "材料不足，补充后使用新请求",
        ));
    };
    ensure(
        state.permissions.recovery.relay_receipt_key.as_ref() == Some(&intent.source_key),
        "key_package_source",
        "目录来源与本群固定Service钥不一致",
    )?;
    Ok((
        request,
        Allocation {
            request: intent.proof.clone(),
            receipt: receipt.clone(),
        },
        key_package,
    ))
}
pub(super) fn for_change(state: &DeviceState, id: &str) -> Result<Option<Allocation>, LabError> {
    if let Some(pool) = &state.key_packages {
        for (request_id, intent) in &pool.requests {
            if matches!(protocol::parse(&intent.proof)?.action,Action::Claim {change_id,..} if change_id==id)
            {
                return allocation(state, request_id).map(|(_, a, _)| Some(a));
            }
        }
    }
    Ok(None)
}
pub(super) fn check_prepare(
    state: &DeviceState,
    request_id: &str,
    validity_secs: Option<u16>,
) -> Result<super::Operation, LabError> {
    let (request, _, key_package) = allocation(state, request_id)?;
    let Action::Claim {
        target,
        conversation_id,
        join_kind,
        change_id,
        authorization_version,
        crypto_state_ref,
        ..
    } = request.action
    else {
        return Err(LabError::new("key_package_context", "预期领取"));
    };
    let cp = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "缺少群权限前驱"))?;
    if !state.permissions.applied.contains_key(&change_id) {
        ensure(
            cp.conversation_id == conversation_id
                && cp.authorization_version == authorization_version
                && cp.crypto_state_ref == crypto_state_ref,
            "key_package_predecessor",
            "领取绑定旧群前驱，须先确定封口",
        )?;
    }
    let mode = if join_kind == "add_member" {
        JoinMode::Member
    } else {
        JoinMode::Device
    };
    let operation = if mode == JoinMode::Member {
        super::Operation::PermissionPrepareAdd {
            change_id: change_id.clone(),
            member: target.clone(),
            key_package: key_package.clone(),
            history_policy: "from_join".into(),
            validity_secs,
        }
    } else {
        super::Operation::PermissionPrepareDevice {
            change_id: change_id.clone(),
            member: target.clone(),
            key_package: key_package.clone(),
            history_policy: "from_join".into(),
            validity_secs,
        }
    };
    super::identity_gate::check(state, &operation)?;
    let action = super::permission_admission::intent(
        state,
        &change_id,
        target.clone(),
        &key_package,
        "from_join".into(),
        mode,
    )?;
    if super::permission_prepare::check(state, &change_id, &action, validity_secs)?.is_none() {
        // 只验证公开 KeyPackage；精确重试必须复用已保存候选，不重新检查其寿命。
        crate::permission::admission::validate_package(
            &key_package,
            &state.context.service,
            &target,
        )?;
    }
    Ok(operation)
}

pub(super) fn prepare(
    state: &mut DeviceState,
    request_id: String,
    validity_secs: Option<u16>,
) -> Result<Value, LabError> {
    let operation = check_prepare(state, &request_id, validity_secs)?;
    let mode = if matches!(operation, super::Operation::PermissionPrepareAdd { .. }) {
        JoinMode::Member
    } else {
        JoinMode::Device
    };
    match operation {
        super::Operation::PermissionPrepareAdd {
            change_id,
            member,
            key_package,
            history_policy,
            validity_secs,
        }
        | super::Operation::PermissionPrepareDevice {
            change_id,
            member,
            key_package,
            history_policy,
            validity_secs,
        } => super::permission_admission::prepare(
            state,
            change_id,
            member,
            key_package,
            history_policy,
            validity_secs,
            mode,
        ),
        _ => Err(LabError::new("key_package_context", "预期入群候选")),
    }
}

pub(super) fn first_join(
    state: &DeviceState,
    statement: &Statement,
    join: &JoinMaterial,
    owner: &Member,
) -> Result<bool, LabError> {
    let hash = crate::permission::commit_digest(&codec::decode(&join.key_package)?);
    let package = state
        .key_packages
        .as_ref()
        .and_then(|s| s.packages.get(&hash));
    if statement.allocation_sha256.is_none() {
        ensure(
            package.is_none(),
            "key_package_allocation_required",
            "池内材料不能绕过领取",
        )?;
        return Ok(false);
    }
    let package =
        package.ok_or_else(|| LabError::new("key_package_missing", "本机没有此领取材料bundle"))?;
    ensure(!package.consumed, "key_package_consumed", "材料已消费")?;
    protocol::material::current(
        &package.material,
        super::checked(
            "clock",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH),
        )?
        .as_secs(),
    )?;
    let allocation = join
        .allocation
        .as_ref()
        .ok_or_else(|| LabError::new("key_package_allocation_required", "缺少分配凭证"))?;
    let key = &state
        .permissions
        .admission
        .anchor
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "缺少入群锚"))?
        .relay_receipt_key;
    let receipt = protocol::verify_receipt(key, &allocation.receipt)?;
    let request = protocol::parse(&allocation.request)?;
    ensure(
        receipt.service_id == state.context.service
            && receipt.request_sha256 == protocol::digest(&allocation.request)?,
        "key_package_context",
        "领取来源或请求不符",
    )?;
    let Action::Claim { target, .. } = request.action else {
        return Err(LabError::new("key_package_context", "预期领取"));
    };
    ensure(target == *owner, "key_package_context", "领取目标不符")?;
    Ok(true)
}

// 只有已证明退役的本协议候选可换新材料；旧v1的same_intent语义不改变。
pub(super) fn renewed_intent(
    state: &DeviceState,
    old_id: &str,
    new_id: &str,
    old: &crate::permission::Action,
    new: &crate::permission::Action,
) -> Result<bool, LabError> {
    use crate::permission::Action as A;
    if old_id == new_id
        || !state.permissions.recovery.retired.contains_key(old_id)
        || for_change(state, old_id)?.is_none()
        || for_change(state, new_id)?.is_none()
    {
        return Ok(false);
    }
    Ok(match (old, new) {
        (
            A::AddMember {
                member: a,
                key_package_sha256: ak,
                history_policy: ah,
                ..
            },
            A::AddMember {
                member: b,
                key_package_sha256: bk,
                history_policy: bh,
                ..
            },
        )
        | (
            A::AddDevice {
                member: a,
                key_package_sha256: ak,
                history_policy: ah,
                ..
            },
            A::AddDevice {
                member: b,
                key_package_sha256: bk,
                history_policy: bh,
                ..
            },
        ) => a == b && ah == bh && ak != bk,
        _ => false,
    })
}
