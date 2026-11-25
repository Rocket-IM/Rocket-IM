//! 尚未到达自身 Add 的设备仅验证公开恢复链；不建立恢复根、不读取 Welcome 或安装 MLS。
use super::{ensure, join_recovery_state as stored, state::DeviceState, LabError};
use crate::{join_recovery as protocol, permission::PermissionCheckpoint};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Advance {
    pub predecessor: PermissionCheckpoint,
    pub record: protocol::PublicRecord,
}

fn before_own_join(state: &DeviceState, cp: &PermissionCheckpoint) -> Result<(), LabError> {
    let own = super::key_package_state::own(state);
    ensure(
        !cp.members
            .iter()
            .any(|m| m.identity() == own.identity() || m.signature_key == own.signature_key),
        "join_required",
        "已到达本机 Add，必须使用专属 Welcome 或恢复入口",
    )
}

// 按签名 AdmissionRef 找唯一后继，不能根据到达顺序或较高版本猜测当前入口。
fn endpoint(
    records: &BTreeMap<String, Advance>,
    root: &protocol::AdmissionRef,
) -> Result<protocol::AdmissionRef, LabError> {
    let mut current = root.clone();
    let mut visited = BTreeSet::new();
    loop {
        ensure(
            visited.insert(current.change_id.clone()),
            "recovery_state",
            "公开后继链成环",
        )?;
        let mut next = None;
        for record in records.values().map(|a| &a.record) {
            let intent = protocol::parse_intent(&record.bundle.intent)?;
            if intent.root_admission == *root && intent.current_admission == current {
                ensure(next.is_none(), "recovery_state", "公开后继不唯一")?;
                next = Some(protocol::admission_ref(
                    &intent.change_id,
                    &record.bundle.change,
                    &record.receipt,
                )?);
            }
        }
        match next {
            Some(value) => current = value,
            None => break,
        }
    }
    let count = records
        .values()
        .filter(|a| {
            protocol::parse_intent(&a.record.bundle.intent).is_ok_and(|i| i.root_admission == *root)
        })
        .count();
    ensure(
        visited.len() == count + 1,
        "recovery_state",
        "公开后继链不完整",
    )?;
    Ok(current)
}

pub(super) fn advance(
    state: &mut DeviceState,
    record: protocol::PublicRecord,
) -> Result<Value, LabError> {
    ensure(
        state.group_id.is_none(),
        "already_grouped",
        "已入群设备必须验证真实 Commit",
    )?;
    let anchor = state
        .permissions
        .admission
        .anchor
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "缺少独立公共入群锚"))?;
    let cp = anchor.checkpoint.clone();
    before_own_join(state, &cp)?;
    let intent = protocol::parse_intent(&record.bundle.intent)?;
    let fact = super::join_recovery_evidence::accepted(
        state,
        &protocol::Evidence::Public(record.clone()),
    )?;
    super::join_recovery_consistency::observe(
        state,
        super::join_recovery_evidence::Observation::Accepted {
            record: record.clone(),
        },
    )?;
    if super::join_recovery_consistency::forked(state) {
        return Ok(super::join_recovery_consistency::paused(state));
    }
    if let Some(old) = state
        .join_recovery
        .as_ref()
        .and_then(|s| s.public_advances.get(&intent.change_id))
    {
        ensure(
            old.record == record,
            "receipt_conflict",
            "公开恢复同 ID 对应不同原件",
        )?;
        return Ok(json!({"duplicate":true,"installed":false}));
    }
    let root = state
        .permissions
        .admission
        .public_records
        .get(&intent.root_admission.change_id)
        .ok_or_else(|| LabError::new("recovery_chain_missing", "必须先从独立锚验证原 Add"))?;
    let source = stored::key(state)?;
    let reference = protocol::root(root, source)?.0;
    let current = match &state.join_recovery {
        Some(s) => endpoint(&s.public_advances, &reference)?,
        None => reference,
    };
    if current != intent.current_admission || fact.predecessor.as_ref() != Some(&cp) {
        return Ok(super::join_recovery_consistency::missing(state));
    }
    let (next, statement, _) = protocol::accepted_public(&cp, root, source, &record)?;
    ensure(
        !state.permissions.used_nonces.contains(&statement.nonce),
        "permission_replay",
        "权限挑战已经使用",
    )?;
    ensure(
        !state
            .permissions
            .admission
            .public_records
            .contains_key(&statement.change_id)
            && state
                .join_recovery
                .as_ref()
                .is_none_or(|s| !s.records.contains_key(&statement.change_id)),
        "receipt_conflict",
        "变更 ID 已被其他原件占用",
    )?;
    let s = state
        .join_recovery
        .get_or_insert_with(stored::State::default);
    s.public_advances.insert(
        statement.change_id,
        Advance {
            predecessor: cp,
            record,
        },
    );
    s.public_head = Some(next.clone());
    stored::budget(s)?;
    if state.witness_state.is_none() {
        state.version = 2;
    }
    state.permissions.used_nonces.insert(statement.nonce);
    super::permission_admission::remember(state, &next);
    state
        .permissions
        .admission
        .anchor
        .as_mut()
        .ok_or_else(|| LabError::new("trust_required", "缺少入群锚"))?
        .checkpoint = next;
    Ok(json!({"duplicate":false,"installed":false}))
}

pub(super) fn validate(state: &DeviceState, s: &stored::State) -> Result<(), LabError> {
    let source = stored::key(state)?;
    let mut nonces = BTreeSet::new();
    let mut roots = BTreeMap::new();
    for (id, advance) in &s.public_advances {
        let intent = protocol::parse_intent(&advance.record.bundle.intent)?;
        let root = state
            .permissions
            .admission
            .public_records
            .get(&intent.root_admission.change_id)
            .ok_or_else(|| LabError::new("recovery_state", "公开恢复缺少原 Add"))?;
        before_own_join(state, &advance.predecessor)?;
        let (_, statement, _) =
            protocol::accepted_public(&advance.predecessor, root, source, &advance.record)?;
        ensure(
            *id == statement.change_id
                && nonces.insert(statement.nonce.clone())
                && state.permissions.used_nonces.contains(&statement.nonce)
                && !state.permissions.admission.public_records.contains_key(id)
                && !s.records.contains_key(id),
            "recovery_state",
            "公开恢复 ID 或挑战不一致",
        )?;
        roots.insert(
            intent.root_admission.change_id.clone(),
            intent.root_admission,
        );
    }
    for root in roots.values() {
        endpoint(&s.public_advances, root)?;
    }
    Ok(())
}
