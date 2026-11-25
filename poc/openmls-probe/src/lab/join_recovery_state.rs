//! 与原加密快照及独立锚共同提交；公开接受和实际 R1 分开记录。
use super::{checked, ensure, state::DeviceState, LabError};
use crate::{
    join_recovery as protocol,
    permission::{
        admission::JoinMaterial,
        receipts::{RecoveryRecord, SignedRecord},
        PermissionCheckpoint,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Command {
    WitnessActivate,
    WitnessRequest {
        record: protocol::Record,
        request_id: String,
        ttl: String,
    },
    WitnessRespond {
        record: protocol::PublicRecord,
        request: SignedRecord,
    },
    WitnessApply {
        record: protocol::Record,
        request: SignedRecord,
        delivery: protocol::witness::WitnessDelivery,
    },
    WitnessObserve {
        delivery: protocol::witness::WitnessDelivery,
    },
    WitnessCancel {
        request_id: String,
    },
    WitnessInspect,
    Root {
        record: RecoveryRecord,
        join: JoinMaterial,
    },
    Advance {
        record: RecoveryRecord,
    },
    AdvancePublic {
        record: protocol::PublicRecord,
    },
    Sign {
        request: protocol::Request,
        intent: Option<SignedRecord>,
    },
    Prepare {
        intent: SignedRecord,
        claim: SignedRecord,
        allocation: SignedRecord,
        key_package: String,
    },
    Observe {
        record: protocol::Evidence,
    },
    Apply {
        record: protocol::Evidence,
    },
    Resolve {
        intent: SignedRecord,
        receipt: SignedRecord,
    },
    Inspect,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Root {
    pub record: RecoveryRecord,
    pub join: JoinMaterial,
    pub current: protocol::AdmissionRef,
    pub package_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub bundle: protocol::Bundle,
    pub candidate_entries: Vec<(Vec<u8>, Vec<u8>)>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Accepted {
    pub predecessor: PermissionCheckpoint,
    pub record: protocol::Evidence,
    pub installed: bool,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub roots: BTreeMap<String, Root>,
    pub requests: BTreeMap<String, SignedRecord>,
    pub records: BTreeMap<String, Accepted>,
    pub closed: BTreeMap<String, SignedRecord>,
    pub pending: Option<Pending>,
    pub public_head: Option<PermissionCheckpoint>,
    // 空值不写出，既有 State 2 原件保持兼容；旧程序的 deny_unknown_fields 拒绝新链。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub public_advances: BTreeMap<String, super::join_recovery_public::Advance>,
    // 新证据一旦落盘，旧程序必须拒读，不能忽略其发送门禁。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<super::join_recovery_evidence::Observation>,
}
pub(super) fn get(state: &DeviceState) -> Result<&State, LabError> {
    state
        .join_recovery
        .as_ref()
        .ok_or_else(|| LabError::new("recovery_required", "尚未验证原入群入口"))
}
pub(super) fn get_mut(state: &mut DeviceState) -> Result<&mut State, LabError> {
    state
        .join_recovery
        .as_mut()
        .ok_or_else(|| LabError::new("recovery_required", "尚未验证原入群入口"))
}
pub(super) fn key(state: &DeviceState) -> Result<&str, LabError> {
    state
        .permissions
        .recovery
        .relay_receipt_key
        .as_deref()
        .or_else(|| {
            state
                .permissions
                .admission
                .anchor
                .as_ref()
                .map(|a| a.relay_receipt_key.as_str())
        })
        .ok_or_else(|| LabError::new("trust_required", "缺少独立固定的 Service 来源"))
}
pub(super) fn checkpoint(state: &DeviceState) -> Result<&PermissionCheckpoint, LabError> {
    state
        .permissions
        .checkpoint
        .as_ref()
        .or_else(|| {
            state
                .join_recovery
                .as_ref()
                .and_then(|s| s.public_head.as_ref())
        })
        .or_else(|| {
            state
                .permissions
                .admission
                .anchor
                .as_ref()
                .map(|a| &a.checkpoint)
        })
        .ok_or_else(|| LabError::new("trust_required", "缺少已验证的前驱"))
}
pub(super) fn budget(value: &State) -> Result<(), LabError> {
    // 未决请求的后续 accepted/closed 需要在原候选之外留出空间，不能到收结果时才满额。
    let mut unresolved = std::collections::BTreeSet::new();
    for proof in value.requests.values() {
        let id = match protocol::parse_request(proof)? {
            protocol::Request::Intent(i) => i.request_id,
            protocol::Request::Control(c) if c.kind == protocol::ControlKind::Claim => {
                c.recovery_id
            }
            _ => continue,
        };
        if !value.closed.contains_key(&id)
            && !value.records.values().any(|a| {
                protocol::parse_intent(&a.record.public().bundle.intent)
                    .is_ok_and(|i| i.request_id == id)
            })
        {
            unresolved.insert(id);
        }
    }
    ensure(
        value.roots.len() <= 32
            && value.observations.len() <= super::consistency_state::MAX_EVIDENCE
            && value.requests.len() <= 320
            && value.records.len()
                + value.public_advances.len()
                + value.closed.len()
                + unresolved.len()
                <= 64
            && checked("recovery_encoding", serde_json::to_vec(value))?.len()
                + unresolved.len() * 1536 * 1024
                <= 8 * 1024 * 1024,
        "resource_exhausted",
        "恢复快照及预留终态预算不足",
    )
}

pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    let Some(s) = &state.join_recovery else {
        return Ok(());
    };
    budget(s)?;
    super::join_recovery_evidence::facts(state)?;
    super::join_recovery_public::validate(state, s)?;
    let source = key(state)?;
    for (id, root) in &s.roots {
        let (reference, _, _, hash) = protocol::root(&root.record, source)?;
        ensure(
            *id == reference.change_id
                && hash
                    == crate::permission::commit_digest(&super::codec::decode(
                        &root.join.key_package,
                    )?),
            "recovery_state",
            "原入口不一致",
        )?;
        if root.current != reference {
            let current = s
                .records
                .get(&root.current.change_id)
                .ok_or_else(|| LabError::new("recovery_state", "当前端点缺少记录"))?;
            ensure(
                protocol::admission_ref(
                    &root.current.change_id,
                    &current.record.public().bundle.change,
                    &current.record.public().receipt,
                )? == root.current
                    && protocol::raw::<protocol::Statement>(
                        &current.record.public().bundle.change.statement_bytes,
                    )?
                    .action
                    .key_package_sha256
                        == root.package_sha256,
                "recovery_state",
                "当前端点不一致",
            )?;
        } else {
            ensure(
                root.package_sha256 == hash,
                "recovery_state",
                "原端点材料不一致",
            )?;
        }
    }
    let mut nonces = std::collections::BTreeSet::new();
    for (id, proof) in &s.requests {
        let request = protocol::parse_request(proof)?;
        ensure(
            request.id() == id
                && *request.signer() == super::key_package_state::own(state)
                && nonces.insert(request.nonce().to_owned()),
            "recovery_state",
            "请求归属不一致",
        )?;
    }
    for (id, a) in &s.records {
        let intent = protocol::parse_intent(&a.record.public().bundle.intent)?;
        let root = s
            .roots
            .get(&intent.root_admission.change_id)
            .ok_or_else(|| LabError::new("recovery_state", "恢复根缺失"))?;
        let (_, statement, _) =
            protocol::accepted_evidence(&a.predecessor, &root.record, source, &a.record)?;
        ensure(*id == statement.change_id, "recovery_state", "记录 ID 不符")?;
    }
    for (id, receipt) in &s.closed {
        let r = protocol::verify_receipt(source, receipt)?;
        ensure(
            r.recovery_id == *id
                && matches!(r.result, protocol::ResultBody::Closed { .. })
                && r.scope.service_id == state.context.service
                && r.scope.conversation_id == checkpoint(state)?.conversation_id
                && (r.target == super::key_package_state::own(state)
                    || r.actor == super::key_package_state::own(state))
                && !s.records.contains_key(&r.change_id),
            "recovery_state",
            "关闭归属或终态冲突",
        )?;
        let root = s
            .roots
            .get(&r.root_admission.change_id)
            .ok_or_else(|| LabError::new("recovery_state", "关闭根缺失"))?;
        ensure(
            protocol::root(&root.record, source)?.0 == r.root_admission
                && protocol::commit_group(&root.record.change.commit_bytes)? == r.scope.group_id,
            "recovery_state",
            "关闭根不符",
        )?;
        ensure(
            s.requests.values().any(|proof| {
                protocol::parse_request(proof).is_ok_and(|q| match q {
                    protocol::Request::Intent(i) => {
                        i.request_id == *id
                            && protocol::signed_digest(proof).is_ok_and(|h| h == r.intent_sha256)
                    }
                    protocol::Request::Control(c) => {
                        c.recovery_id == *id && c.intent_sha256 == r.intent_sha256
                    }
                })
            }),
            "recovery_state",
            "关闭缺少原请求",
        )?;
    }
    for root in s.roots.values() {
        let reference = protocol::root(&root.record, source)?.0;
        let mut current = reference.clone();
        let mut visited = std::collections::BTreeSet::new();
        loop {
            ensure(
                visited.insert(current.change_id.clone()),
                "recovery_state",
                "后继链成环",
            )?;
            let mut next = None;
            for a in s.records.values() {
                let public = a.record.public();
                let intent = protocol::parse_intent(&public.bundle.intent)?;
                if intent.root_admission == reference && intent.current_admission == current {
                    ensure(next.is_none(), "recovery_state", "后继不唯一")?;
                    next = Some(protocol::admission_ref(
                        &intent.change_id,
                        &public.bundle.change,
                        &public.receipt,
                    )?);
                }
            }
            match next {
                Some(value) => current = value,
                None => break,
            }
        }
        let count = s
            .records
            .values()
            .filter(|a| {
                protocol::parse_intent(&a.record.public().bundle.intent)
                    .is_ok_and(|i| i.root_admission == reference)
            })
            .count();
        ensure(
            current == root.current && visited.len() == count + 1,
            "recovery_state",
            "后继链不完整",
        )?;
    }
    if let Some(p) = &s.pending {
        let i = protocol::parse_intent(&p.bundle.intent)?;
        let root = s
            .roots
            .get(&i.root_admission.change_id)
            .ok_or_else(|| LabError::new("recovery_state", "恢复根缺失"))?;
        protocol::candidate(checkpoint(state)?, &root.record, source, &p.bundle, false)?;
    }
    Ok(())
}
