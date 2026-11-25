//! Service 原件只形成观察事实；其中的完整检查点不能写入实际 MLS 索引。
use super::{ensure, join_recovery_state as stored, state::DeviceState, LabError};
use crate::{
    join_recovery as p,
    permission::{
        receipts::{RecoveryRecord, SignedRecord},
        PermissionCheckpoint,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Observation {
    Accepted {
        record: p::PublicRecord,
    },
    Closed {
        intent: SignedRecord,
        receipt: SignedRecord,
    },
}

pub(super) struct Fact {
    pub receipt: SignedRecord,
    pub statement: p::Receipt,
    pub checkpoint: PermissionCheckpoint,
    pub predecessor: Option<PermissionCheckpoint>,
}

pub(super) fn root<'a>(
    state: &'a DeviceState,
    i: &p::Intent,
) -> Result<&'a RecoveryRecord, LabError> {
    state
        .join_recovery
        .as_ref()
        .and_then(|s| s.roots.get(&i.root_admission.change_id))
        .map(|r| &r.record)
        .or_else(|| {
            state
                .permissions
                .admission
                .public_records
                .get(&i.root_admission.change_id)
        })
        .ok_or_else(|| LabError::new("recovery_chain_missing", "尚未验证恢复根 Add"))
}

fn receipt(state: &DeviceState, proof: &SignedRecord) -> Result<Fact, LabError> {
    let statement = p::verify_receipt(stored::key(state)?, proof)?;
    ensure(
        statement.scope.service_id == state.context.service
            && statement.scope.conversation_id == stored::checkpoint(state)?.conversation_id,
        "recovery_context",
        "恢复观察不属于当前实例和会话",
    )?;
    let checkpoint = match &statement.result {
        p::ResultBody::Accepted { checkpoint, .. } | p::ResultBody::Closed { checkpoint, .. } => {
            checkpoint.clone()
        }
        _ => return Err(LabError::new("recovery_invalid", "观察需要终态回执")),
    };
    Ok(Fact {
        receipt: proof.clone(),
        statement,
        checkpoint,
        predecessor: None,
    })
}

pub(super) fn accepted(state: &DeviceState, record: &p::Evidence) -> Result<Fact, LabError> {
    let public = record.public();
    let intent = p::parse_intent(&public.bundle.intent)?;
    let mut fact = receipt(state, &public.receipt)?;
    ensure(
        matches!(fact.statement.result, p::ResultBody::Accepted { .. }),
        "recovery_invalid",
        "恢复观察需要 accepted 原件",
    )?;
    // 恢复不改变成员集合。由签名回执反推的前驱仍是 Service 的声明，
    // 这里只验证各方签名、授权及原件绑定；可信链与实际 MLS 在另一层对照。
    let mut predecessor = fact.checkpoint.clone();
    predecessor.authorization_version = intent.predecessor.authorization_version.clone();
    predecessor.crypto_state_ref = intent.predecessor.crypto_state_ref.clone();
    p::accepted_evidence(
        &predecessor,
        root(state, &intent)?,
        stored::key(state)?,
        record,
    )?;
    fact.predecessor = Some(predecessor);
    Ok(fact)
}

pub(super) fn verify(state: &DeviceState, evidence: &Observation) -> Result<Fact, LabError> {
    match evidence {
        Observation::Accepted { record } => accepted(state, &p::Evidence::Public(record.clone())),
        Observation::Closed {
            intent,
            receipt: proof,
        } => {
            let i = p::parse_intent(intent)?;
            let fact = receipt(state, proof)?;
            p::receipt_context(&fact.statement, &i, intent)?;
            let root = root(state, &i)?;
            let (reference, target, _, _) = p::root(root, stored::key(state)?)?;
            ensure(
                matches!(fact.statement.result, p::ResultBody::Closed { .. })
                    && reference == i.root_admission
                    && target == i.signer
                    && p::commit_group(&root.change.commit_bytes)? == i.scope.group_id,
                "recovery_invalid",
                "关闭观察缺少准确根入口",
            )?;
            Ok(fact)
        }
    }
}

pub(super) fn facts(state: &DeviceState) -> Result<Vec<Fact>, LabError> {
    let Some(s) = &state.join_recovery else {
        return Ok(Vec::new());
    };
    let mut facts = Vec::new();
    for observation in &s.observations {
        facts.push(verify(state, observation)?);
    }
    // 旧快照没有 observations，仍须纳入已保存的原件；精确重复不增加约束。
    for a in s.records.values() {
        facts.push(accepted(state, &a.record)?);
    }
    for a in s.public_advances.values() {
        facts.push(accepted(state, &p::Evidence::Public(a.record.clone()))?);
    }
    for proof in s.closed.values() {
        facts.push(receipt(state, proof)?);
    }
    Ok(facts)
}
