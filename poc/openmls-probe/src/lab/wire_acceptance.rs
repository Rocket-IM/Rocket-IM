//! 本机原生消息的接受ID只能归属一个精确原件；独立历史archive不占用此索引。
use super::{ensure, state::DeviceState, LabError};
use crate::message_acceptance;
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Owner<'a> {
    Inbox(&'a str),
    Outbox(&'a str),
    Reclaimed(&'a str),
}

fn owners(state: &DeviceState) -> Result<BTreeMap<String, Owner<'_>>, LabError> {
    let mut owners = BTreeMap::new();
    let mut claim = |id: String, owner| {
        ensure(
            owners.insert(id, owner).is_none(),
            "acceptance_conflict",
            "已保存的接受ID属于多个本机消息原件",
        )
    };
    for (key, record) in &state.wire.inbox {
        // 旧快照可以没有接受ID或回执；不补造接受事实，也不改成强制签名模式。
        if let Some(id) = &record.acceptance_id {
            claim(id.clone(), Owner::Inbox(key))?;
        }
    }
    for (key, record) in &state.wire.outbox {
        if let Some(receipt) = &record.acceptance_receipt {
            let pin = state
                .permissions
                .recovery
                .relay_receipt_key
                .as_deref()
                .ok_or_else(|| LabError::new("receipt_pin_required", "缺少固定Service回执钥"))?;
            claim(
                message_acceptance::verify(pin, receipt)?.acceptance_id,
                Owner::Outbox(key),
            )?;
        }
    }
    if let Some(compacted) = &state.wire_reclamation {
        for (key, record) in &compacted.messages {
            claim(record.acceptance_id.clone(), Owner::Reclaimed(key))?;
        }
    }
    Ok(owners)
}

/// exact_owner只能由调用方核对精确原件后提供；补绑定不能借用其他消息的ID。
pub(super) fn available(
    state: &DeviceState,
    id: &str,
    exact_owner: Option<Owner<'_>>,
) -> Result<(), LabError> {
    ensure(
        owners(state)?
            .get(id)
            .is_none_or(|saved| Some(*saved) == exact_owner),
        "acceptance_conflict",
        "接受ID已属于其他本机消息原件",
    )
}

/// 在恢复provider前拒绝旧冲突快照；不能任选一个原件或静默修复历史。
pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    owners(state).map(|_| ())
}
