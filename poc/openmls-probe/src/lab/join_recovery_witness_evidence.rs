//! 公开附件先独立观察，再允许安装。摘要不能取代 Service 原件验证。
use super::{checked, codec, ensure, state::DeviceState, LabError};
use crate::{
    join_recovery::{self as p, witness as w},
    permission,
};
use serde_json::{json, Value};

pub(super) fn export(
    state: &DeviceState,
    exclude: &[w::PublicEvidenceAttachment],
) -> Result<Vec<w::PublicEvidenceAttachment>, LabError> {
    let mut records = Vec::new();
    if let Some(s) = &state.join_recovery {
        for record in s
            .records
            .values()
            .map(|r| r.record.public())
            .chain(s.public_advances.values().map(|a| a.record.clone()))
        {
            let raw = checked("w1_binding_mismatch", serde_json::to_vec(&record))?;
            let i = p::parse_intent(&record.bundle.intent)?;
            records.push(w::PublicEvidenceAttachment {
                reference: w::SourceRef {
                    source_id: i.change_id,
                    source_sha256: permission::commit_digest(&raw),
                },
                evidence_bytes: codec::encode(&raw),
            });
        }
    }
    for (id, record) in &state.permissions.recovery.records {
        let s = permission::Statement::parse(&codec::decode(&record.change.statement_bytes)?)?;
        if !state.permissions.checkpoint.as_ref().is_some_and(|cp| {
            cp.authorization_version == s.authorization_version
                && cp.crypto_state_ref == s.to_state_ref
        }) {
            continue;
        }
        let raw = checked("w1_binding_mismatch", serde_json::to_vec(record))?;
        records.push(w::PublicEvidenceAttachment {
            reference: w::SourceRef {
                source_id: id.clone(),
                source_sha256: permission::commit_digest(&raw),
            },
            evidence_bytes: codec::encode(&raw),
        });
    }
    records.retain(|e| !exclude.iter().any(|old| old.reference == e.reference));
    let mut unique = std::collections::BTreeSet::new();
    records.retain(|e| {
        unique.insert((
            e.reference.source_id.clone(),
            e.reference.source_sha256.clone(),
        ))
    });
    ensure(
        records.len() <= 64,
        "w1_resource_exhausted",
        "公开证据数量超限",
    )?;
    Ok(records)
}
pub(super) fn fact(
    state: &DeviceState,
    attachment: &w::PublicEvidenceAttachment,
) -> Result<w::CompleteCheckpoint, LabError> {
    let raw = codec::decode(&attachment.evidence_bytes)?;
    ensure(
        raw.len() <= 900 * 1024
            && permission::commit_digest(&raw) == attachment.reference.source_sha256,
        "w1_binding_mismatch",
        "公开附件摘要或长度不符",
    )?;
    if let Ok(record) = serde_json::from_slice::<p::PublicRecord>(&raw) {
        let fact =
            super::join_recovery_evidence::accepted(state, &p::Evidence::Public(record.clone()))?;
        let s: p::Statement = p::raw(&record.bundle.change.statement_bytes)?;
        ensure(
            s.change_id == attachment.reference.source_id,
            "w1_binding_mismatch",
            "公开恢复证据 ID 不符",
        )?;
        return Ok(w::CompleteCheckpoint {
            group_id: s.scope.group_id,
            epoch: crate::permission::types::decimal(&s.action.previous_epoch)?
                .checked_add(1)
                .ok_or_else(|| LabError::new("w1_binding_mismatch", "epoch 溢出"))?
                .to_string(),
            checkpoint: fact.checkpoint,
        });
    }
    let record: permission::receipts::RecoveryRecord =
        checked("w1_binding_mismatch", serde_json::from_slice(&raw))?;
    let (receipt, s) =
        permission::receipts::verify_receipt(super::join_recovery_state::key(state)?, &record)?;
    ensure(
        receipt.outcome == permission::receipts::Outcome::Accepted
            && s.change_id == attachment.reference.source_id,
        "w1_binding_mismatch",
        "公开附件不是准确已接受权限原件",
    )?;
    // Epoch 不由普通权限声明单独证明；只允许本机已实际保存的准确记录与 checkpoint。
    let local = state
        .permissions
        .recovery
        .records
        .get(&s.change_id)
        .or_else(|| state.permissions.admission.public_records.get(&s.change_id));
    ensure(
        local == Some(&record),
        "w1_predecessor_unavailable",
        "先通过原权限同步核验附件",
    )?;
    let cp = state
        .permissions
        .consistency
        .checkpoints
        .values()
        .find(|cp| {
            cp.authorization_version == s.authorization_version
                && cp.crypto_state_ref == s.to_state_ref
        })
        .ok_or_else(|| LabError::new("w1_predecessor_unavailable", "附件缺少已验证检查点"))?;
    // 本 POC 普通权限事件保留MLS epoch在回执中没有字段，不能推断；导出只用本机当前群。
    let group = state.group()?;
    ensure(
        super::wire::state_ref(&group)? == cp.crypto_state_ref,
        "w1_predecessor_unavailable",
        "附件 epoch 未得到实际群验证",
    )?;
    Ok(w::CompleteCheckpoint {
        group_id: codec::encode(group.group_id().as_slice()),
        epoch: group.epoch().as_u64().to_string(),
        checkpoint: cp.clone(),
    })
}
pub(super) fn highest(
    state: &DeviceState,
    initial: &w::CompleteCheckpoint,
    evidence: &[w::PublicEvidenceAttachment],
) -> Result<w::CompleteCheckpoint, LabError> {
    let mut highest = initial.clone();
    for attachment in evidence {
        let cp = fact(state, attachment)?;
        if crate::permission::types::decimal(&cp.checkpoint.authorization_version)?
            > crate::permission::types::decimal(&highest.checkpoint.authorization_version)?
        {
            highest = cp;
        }
    }
    if let Some(known) = &state.permissions.consistency.highest_observed {
        ensure(
            crate::permission::types::decimal(&known.authorization_version)?
                <= crate::permission::types::decimal(&highest.checkpoint.authorization_version)?,
            "w1_predecessor_unavailable",
            "已知更高水位缺少可附带的完整原件",
        )?;
    }
    Ok(highest)
}
pub(super) fn observe(
    state: &mut DeviceState,
    delivery: w::WitnessDelivery,
) -> Result<Value, LabError> {
    w::validate_delivery(&delivery)?;
    let response = w::parse_witness_response(&delivery.response)?;
    let mut changed = false;
    for attachment in delivery
        .known_evidence
        .iter()
        .chain(&delivery.supplemental_evidence)
    {
        let raw = codec::decode(&attachment.evidence_bytes)?;
        ensure(
            permission::commit_digest(&raw) == attachment.reference.source_sha256,
            "w1_binding_mismatch",
            "附件摘要不符",
        )?;
        if let Ok(record) = serde_json::from_slice::<p::PublicRecord>(&raw) {
            let s: p::Statement = p::raw(&record.bundle.change.statement_bytes)?;
            ensure(
                s.change_id == attachment.reference.source_id,
                "w1_binding_mismatch",
                "附件 ID 不符",
            )?;
            let out = super::join_recovery::observe(state, p::Evidence::Public(record))?;
            changed |= out["duplicate"] != true;
        } else {
            fact(state, attachment)?;
        }
    }
    ensure(
        response.known_evidence_refs
            == delivery
                .known_evidence
                .iter()
                .map(|e| e.reference.clone())
                .collect::<Vec<_>>(),
        "w1_binding_mismatch",
        "缺少或改变签名证据顺序",
    )?;
    super::join_recovery_witness_state::budget(state, 0)?;
    Ok(json!({"duplicate":!changed}))
}
pub(super) fn check(
    state: &DeviceState,
    delivery: &w::WitnessDelivery,
    response: &w::WitnessResponse,
) -> Result<(), LabError> {
    w::validate_delivery(delivery)?;
    ensure(
        delivery.known_evidence.len() <= 64
            && delivery.supplemental_evidence.len() <= 64
            && response.known_evidence_refs
                == delivery
                    .known_evidence
                    .iter()
                    .map(|e| e.reference.clone())
                    .collect::<Vec<_>>(),
        "w1_binding_mismatch",
        "公开证据引用不完整",
    )?;
    let mut highest = response.next.clone();
    for attachment in delivery
        .known_evidence
        .iter()
        .chain(&delivery.supplemental_evidence)
    {
        let raw = codec::decode(&attachment.evidence_bytes)?;
        // 已知 root 原件可直接精确匹配；不需要用当前群伪造其 epoch。
        if super::join_recovery_state::get(state)?
            .roots
            .iter()
            .any(|(id, r)| {
                *id == attachment.reference.source_id
                    && serde_json::to_vec(&r.record).is_ok_and(|v| v == raw)
            })
        {
            ensure(
                permission::commit_digest(&raw) == attachment.reference.source_sha256,
                "w1_binding_mismatch",
                "root 摘要错误",
            )?;
            continue;
        }
        let cp = fact(state, attachment)?;
        ensure(
            cp.checkpoint.members.contains(&response.witness),
            "w1_permission_denied",
            "后获公开原件显示 W 已撤销",
        )?;
        let v = crate::permission::types::decimal(&cp.checkpoint.authorization_version)?;
        let expected =
            crate::permission::types::decimal(&response.next.checkpoint.authorization_version)?;
        ensure(v <= expected, "w1_superseded", "应先处理已知更高水位")?;
        ensure(
            v != expected || cp == response.next,
            "w1_binding_mismatch",
            "同水位冲突",
        )?;
        if v > crate::permission::types::decimal(&highest.checkpoint.authorization_version)? {
            highest = cp;
        }
    }
    ensure(
        response.highest_known == highest,
        "w1_binding_mismatch",
        "highest_known 没有完整可核验原件",
    )?;
    Ok(())
}
