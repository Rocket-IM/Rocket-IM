//! 先保存私有bundle和准确发布/领取意图，再通过原快照提交边界返回公开字节。
use super::{checked, codec, ensure, key_package_state as stored, state::DeviceState, LabError};
use crate::{
    key_package::{self as protocol, Action, Request, ResultBody},
    permission::{receipts::SignedRecord, Member},
};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use serde_json::{json, Value};

pub(super) fn inspect(state: &DeviceState) -> Value {
    let Some(pool) = &state.key_packages else {
        return json!({"enabled":false,"packages":{},"requests":{},"directories":{},"freshness":"unknown"});
    };
    json!({"enabled":true,"packages":pool.packages,"requests":pool.requests,"directories":pool.directories,"freshness":"unknown"})
}
pub(super) fn generate(
    state: &mut DeviceState,
    request_id: String,
    count: u8,
    not_before: String,
    not_after: String,
    source_key: String,
) -> Result<Value, LabError> {
    super::wire_types::id(&request_id)?;
    crate::permission::receipts::validate_key(&source_key)?;
    let start = super::wire_types::decimal(&not_before)?;
    let end = super::wire_types::decimal(&not_after)?;
    ensure(
        (1..=4).contains(&count)
            && end
                .checked_sub(start)
                .is_some_and(|n| (1..=86400).contains(&n)),
        "key_package_lifetime",
        "批次或有效期不合法",
    )?;
    if let Some(intent) = state
        .key_packages
        .as_ref()
        .and_then(|s| s.requests.get(&request_id))
    {
        let request = protocol::parse(&intent.proof)?;
        let Action::Publish { packages } = &request.action else {
            return Err(LabError::new("idempotency_conflict", "原请求不是发布"));
        };
        let pool = state
            .key_packages
            .as_ref()
            .ok_or_else(|| LabError::new("key_package_state", "缺少账本"))?;
        ensure(
            intent.source_key == source_key
                && packages.len() == usize::from(count)
                && packages.iter().all(|encoded| {
                    pool.packages.values().any(|p| {
                        p.encoded == *encoded
                            && p.material.not_before == not_before
                            && p.material.not_after == not_after
                    })
                }),
            "idempotency_conflict",
            "重试改变生成参数",
        )?;
        return Ok(json!({"proof":intent.proof,"duplicate":true}));
    }
    let pool = state.key_packages.get_or_insert_with(Default::default);
    ensure(
        pool.packages.len() + usize::from(count) <= 32 && pool.requests.len() < 64,
        "resource_exhausted",
        "材料或请求账本已满",
    )?;
    let signer = state.signer()?;
    let mut packages = Vec::new();
    for _ in 0..count {
        let bundle = checked(
            "key_package_generation",
            KeyPackage::builder()
                .key_package_lifetime(Lifetime::init(start, end))
                .build(
                    codec::CIPHERSUITE,
                    &state.provider,
                    &signer,
                    state.own_credential()?,
                ),
        )?;
        let encoded = codec::encode(&checked(
            "key_package_encoding",
            bundle.key_package().tls_serialize_detached(),
        )?);
        let material = protocol::material::metadata(bundle.key_package())?;
        state
            .key_packages
            .as_mut()
            .ok_or_else(|| LabError::new("key_package_state", "缺少账本"))?
            .packages
            .insert(
                material.key_package_sha256.clone(),
                stored::Package {
                    encoded: encoded.clone(),
                    material,
                    consumed: false,
                },
            );
        packages.push(encoded);
    }
    request(state, request_id, Action::Publish { packages }, source_key)
}
pub(super) fn target_ready(state: &DeviceState, target: &Member) -> Result<(), LabError> {
    super::identity_source::require(state, target, true)?;
    super::identity_gate::require(
        state,
        &super::identity_state::object(
            &state.context.service,
            &target.account_id,
            &target.device_id,
            &target.signature_key,
        ),
    )?;
    let directory = state
        .key_packages
        .as_ref()
        .and_then(|s| s.directories.get(&target.account_id))
        .ok_or_else(|| LabError::new("directory_required", "尚无已验证来源的候选目录"))?;
    ensure(
        !directory.conflict,
        "directory_conflict",
        "目录已暂停，不能用新响应清除冲突",
    )?;
    let current = protocol::directory::parse(
        directory
            .snapshots
            .last()
            .ok_or_else(|| LabError::new("directory_required", "缺少目录头"))?,
    )?;
    for entry in &current.devices {
        let registered = crate::device_registration::verify_proof(&entry.registration)?;
        if registered.device_id == target.device_id {
            return ensure(
                entry.status == "active" && registered.signature_key == target.signature_key,
                "identity_changed",
                "目录目标已撤销或身份冲突",
            );
        }
    }
    Err(LabError::new("directory_required", "完整目录不含准确目标"))
}
pub(super) fn request(
    state: &mut DeviceState,
    request_id: String,
    action: Action,
    source_key: String,
) -> Result<Value, LabError> {
    crate::permission::receipts::validate_key(&source_key)?;
    let request = Request {
        protocol_version: "rim-key-package-request-1".into(),
        service_id: state.context.service.clone(),
        request_id: request_id.clone(),
        actor: stored::own(state),
        action,
    };
    request.validate()?;
    if let Some(intent) = state
        .key_packages
        .as_ref()
        .and_then(|s| s.requests.get(&request_id))
    {
        ensure(
            protocol::parse(&intent.proof)? == request && intent.source_key == source_key,
            "idempotency_conflict",
            "请求标识不可改绑",
        )?;
        return Ok(json!({"proof":intent.proof,"duplicate":true}));
    }
    if let Action::Claim {
        target,
        directory_version,
        directory_sha256,
        ..
    } = &request.action
    {
        target_ready(state, target)?;
        let head = state
            .key_packages
            .as_ref()
            .and_then(|s| s.directories.get(&target.account_id))
            .and_then(|d| d.snapshots.last())
            .ok_or_else(|| LabError::new("directory_required", "缺少目录"))?;
        ensure(
            protocol::directory::hash(head)? == *directory_sha256
                && protocol::directory::parse(head)?.version == *directory_version,
            "directory_stale",
            "领取必须绑定当前本机目录",
        )?;
    }
    if let Action::Publish { packages } = &request.action {
        for encoded in packages {
            ensure(
                state.key_packages.as_ref().is_some_and(|s| {
                    s.packages
                        .values()
                        .any(|p| p.encoded == *encoded && !p.consumed)
                }),
                "key_package_missing",
                "不能发布没有私有bundle的材料",
            )?;
        }
    }
    let proof = protocol::sign(&request, &state.signer()?)?;
    let pinned = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_ref()
        .or_else(|| {
            state
                .permissions
                .admission
                .anchor
                .as_ref()
                .map(|a| &a.relay_receipt_key)
        });
    ensure(
        pinned.is_none_or(|key| key == &source_key),
        "key_package_source",
        "Service来源与群锚不符",
    )?;
    let pool = state.key_packages.get_or_insert_with(Default::default);
    ensure(
        pool.source_key
            .as_ref()
            .is_none_or(|key| key == &source_key),
        "key_package_source",
        "Service来源已经固定",
    )?;
    pool.source_key = Some(source_key.clone());
    ensure(
        pool.requests.len() < 64,
        "resource_exhausted",
        "请求账本已满",
    )?;
    pool.requests.insert(
        request_id,
        stored::Intent {
            proof: proof.clone(),
            source_key,
            receipt: None,
        },
    );
    stored::budget(pool)?;
    Ok(json!({"proof":proof,"duplicate":false}))
}
pub(super) fn response(
    state: &mut DeviceState,
    request_id: String,
    receipt: SignedRecord,
) -> Result<Value, LabError> {
    let intent = state
        .key_packages
        .as_ref()
        .and_then(|s| s.requests.get(&request_id))
        .ok_or_else(|| LabError::new("key_package_pending", "未保存原请求"))?
        .clone();
    let request = protocol::parse(&intent.proof)?;
    let statement = protocol::verify_receipt(&intent.source_key, &receipt)?;
    ensure(
        statement.service_id == state.context.service
            && statement.request_sha256 == protocol::digest(&intent.proof)?,
        "key_package_context",
        "回执未绑定原请求",
    )?;
    if let Some(previous) = &intent.receipt {
        ensure(
            *previous == receipt,
            "idempotency_conflict",
            "原结果不能改变",
        )?;
        return Ok(json!({"result":statement.result,"duplicate":true}));
    }
    let mut directory_status = None;
    match (&request.action, &statement.result) {
        (
            Action::Directory {
                account_id,
                challenge,
            },
            ResultBody::Directory {
                challenge: actual,
                snapshots,
            },
        ) => {
            ensure(actual == challenge, "directory_context", "目录挑战不符")?;
            directory_status = Some(super::key_package_directory::accept(
                state, account_id, snapshots,
            )?);
        }
        (Action::Publish { packages }, ResultBody::Published { hashes, .. }) => {
            let expected: Result<Vec<_>, LabError> = packages
                .iter()
                .map(|p| Ok(crate::permission::commit_digest(&codec::decode(p)?)))
                .collect();
            ensure(*hashes == expected?, "key_package_context", "发布结果不符")?;
        }
        (Action::Claim { .. }, ResultBody::Allocated { .. }) => {} // 保存历史分配事实；实际准备仍重验当前材料与身份。
        (Action::Claim { .. }, ResultBody::Unavailable { .. }) => {}
        (
            Action::Retire { key_package_sha256 },
            ResultBody::Retired {
                key_package_sha256: actual,
                ..
            },
        ) => {
            ensure(
                key_package_sha256 == actual,
                "key_package_context",
                "退役材料不符",
            )?;
        }
        _ => return Err(LabError::new("key_package_context", "回执动作不符")),
    }
    state
        .key_packages
        .as_mut()
        .and_then(|s| s.requests.get_mut(&request_id))
        .ok_or_else(|| LabError::new("key_package_pending", "缺少原意图"))?
        .receipt = Some(receipt);
    if let Some(pool) = &state.key_packages {
        stored::budget(pool)?;
    }
    Ok(json!({"result":statement.result,"directory_status":directory_status,"duplicate":false}))
}
