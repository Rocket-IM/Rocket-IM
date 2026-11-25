//! 可确定的输入/信任/配额拒绝在独立锚预约之前完成，不恢复或推进MLS。
use super::{
    ensure, key_package_state as stored, key_packages, state::DeviceState, LabError, Operation,
};
use crate::key_package::{self as protocol, Action, Request};

fn source(state: &DeviceState, key: &str) -> Result<(), LabError> {
    crate::permission::receipts::validate_key(key)?;
    for fixed in [
        state.permissions.recovery.relay_receipt_key.as_ref(),
        state
            .permissions
            .admission
            .anchor
            .as_ref()
            .map(|a| &a.relay_receipt_key),
        state
            .key_packages
            .as_ref()
            .and_then(|p| p.source_key.as_ref()),
    ]
    .into_iter()
    .flatten()
    {
        ensure(fixed == key, "key_package_source", "Service来源已经固定")?;
    }
    Ok(())
}
pub(super) fn check(state: &DeviceState, operation: &Operation) -> Result<(), LabError> {
    match operation {
        Operation::KeyPackageGenerate {
            request_id,
            count,
            not_before,
            not_after,
            source_key,
        } => {
            source(state, source_key)?;
            super::wire_types::id(request_id)?;
            let start = super::wire_types::decimal(not_before)?;
            let end = super::wire_types::decimal(not_after)?;
            ensure(
                (1..=4).contains(count)
                    && end
                        .checked_sub(start)
                        .is_some_and(|n| (1..=86400).contains(&n)),
                "key_package_lifetime",
                "批次或有效期不合法",
            )?;
            if let Some(pool) = &state.key_packages {
                if let Some(intent) = pool.requests.get(request_id) {
                    let Action::Publish { packages } = protocol::parse(&intent.proof)?.action
                    else {
                        return Err(LabError::new("idempotency_conflict", "原请求不是发布"));
                    };
                    ensure(
                        packages.len() == usize::from(*count)
                            && packages.iter().all(|e| {
                                pool.packages.values().any(|p| {
                                    p.encoded == *e
                                        && p.material.not_before == *not_before
                                        && p.material.not_after == *not_after
                                })
                            }),
                        "idempotency_conflict",
                        "重试改变生成参数",
                    )?;
                } else {
                    ensure(
                        pool.packages.len() + usize::from(*count) <= 32 && pool.requests.len() < 64,
                        "resource_exhausted",
                        "生命周期账本已满",
                    )?;
                }
            }
        }
        Operation::KeyPackageRequest {
            request_id,
            action,
            source_key,
        } => {
            source(state, source_key)?;
            let request = Request {
                protocol_version: "rim-key-package-request-1".into(),
                service_id: state.context.service.clone(),
                request_id: request_id.clone(),
                actor: stored::own(state),
                action: action.clone(),
            };
            request.validate()?;
            if let Action::Claim { target, .. } = action {
                key_packages::target_ready(state, target)?;
            }
            if let Some(intent) = state
                .key_packages
                .as_ref()
                .and_then(|p| p.requests.get(request_id))
            {
                ensure(
                    protocol::parse(&intent.proof)? == request,
                    "idempotency_conflict",
                    "请求标识不可改变内容",
                )?;
                return Ok(());
            }
            ensure(
                state
                    .key_packages
                    .as_ref()
                    .is_none_or(|p| p.requests.len() < 64),
                "resource_exhausted",
                "请求账本已满",
            )?;
            match action {
                Action::Claim {
                    target,
                    directory_version,
                    directory_sha256,
                    ..
                } => {
                    let head = state
                        .key_packages
                        .as_ref()
                        .and_then(|p| p.directories.get(&target.account_id))
                        .and_then(|d| d.snapshots.last())
                        .ok_or_else(|| LabError::new("directory_required", "缺少候选目录"))?;
                    ensure(
                        protocol::directory::parse(head)?.version == *directory_version
                            && protocol::directory::hash(head)? == *directory_sha256,
                        "directory_stale",
                        "领取未绑定当前目录",
                    )?;
                }
                Action::Publish { packages } => {
                    for encoded in packages {
                        ensure(
                            state.key_packages.as_ref().is_some_and(|s| {
                                s.packages
                                    .values()
                                    .any(|p| p.encoded == *encoded && !p.consumed)
                            }),
                            "key_package_missing",
                            "缺少原私有bundle",
                        )?;
                    }
                }
                _ => {}
            }
        }
        Operation::PermissionPrepareClaim {
            request_id,
            validity_secs,
        } => {
            super::key_package_join::check_prepare(state, request_id, *validity_secs)?;
        }
        _ => {}
    }
    Ok(())
}
