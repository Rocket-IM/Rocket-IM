//! 固定控制原件；当前轮和已结清前轮永久保留，不按失联或时间释放。
use super::workset_types::*;
use super::{
    super::{
        data::{Data, Saved},
        types::*,
        PersistentDevice,
    },
    ledger,
    types::NetworkData,
};

pub(super) fn originals(data: &Data, n: &NetworkData, first: u64, last: u64) -> Result<String> {
    let bad = || Error::paused("workset_original_mismatch");
    let events = n
        .events
        .get((first - 1) as usize..last as usize)
        .ok_or_else(bad)?;
    let mut fields = Vec::with_capacity(events.len());
    for e in events {
        if e.envelope.is_some() || !matches!(e.kind.as_str(), "delivered" | "unavailable") {
            return Err(bad());
        }
        ledger::validate_ack(data, &e.acceptance)?;
        let r = data
            .requests
            .get(&e.acceptance.request_id)
            .ok_or_else(bad)?;
        let RequestState::Complete { outcome } = &r.result else {
            return Err(bad());
        };
        let Value::Sent { envelope } = &outcome.value else {
            return Err(bad());
        };
        fields.push([
            e.sequence.as_str(),
            e.kind.as_str(),
            e.acceptance.request_id.as_str(),
            e.acceptance.message_id.as_str(),
            e.acceptance.sequence.as_str(),
            e.acceptance.envelope_hash.as_str(),
            envelope.context.as_str(),
        ]);
    }
    Ok(hash(&encode(&("rocket-im/control-originals/1", fields))?))
}

pub(super) fn validate(data: &Data, n: &NetworkData) -> Result<()> {
    super::workset_chain::validate(n)?;
    for state in n.workset_history.iter().chain(n.workset.iter()) {
        validate_state(data, n, state)?;
    }
    Ok(())
}

fn validate_state(data: &Data, n: &NetworkData, state: &CapacityWorksetState) -> Result<()> {
    let w = &state.workset;
    w.validate()?;
    let b = n
        .binding
        .as_ref()
        .ok_or_else(|| Error::paused("workset_invalid"))?;
    let first = number(&w.first)?;
    let last = number(&w.last)?;
    if data.state.identity.as_ref() != Some(&w.owner)
        || b.conversation != w.conversation
        || number(&n.reported)? + 1 < first
        || originals(data, n, first, last)? != w.originals_hash
        || (w.context != data.state.context && !super::queue::retired_context(data, &w.context))
        || (state.phase == WorksetPhase::Settled && number(&n.reported)? < last)
    {
        return Err(Error::paused("workset_original_mismatch"));
    }
    Ok(())
}

#[cfg(any(feature = "protected-storage", test))]
pub(super) fn select(s: &Saved, instance: &str) -> Result<CapacityWorksetState> {
    let n = s
        .data
        .network
        .as_ref()
        .ok_or_else(|| Error::new("network_binding_required"))?;
    if let Some(w) = &n.workset {
        return Ok(w.clone());
    }
    select_originals(s, instance)
}

#[cfg(any(feature = "protected-storage", test))]
pub(super) fn select_originals(s: &Saved, instance: &str) -> Result<CapacityWorksetState> {
    let n = s
        .data
        .network
        .as_ref()
        .ok_or_else(|| Error::new("network_binding_required"))?;
    if s.meta.reserve_version.is_none() {
        return Err(Error::new("capacity_reserve_required"));
    }
    if s.meta.journal.is_some()
        || s.meta.blocks_operations()
        || s.data.state.pending_request.is_some()
    {
        return Err(Error::paused("workset_source_unavailable"));
    }
    let first = number(&n.reported)? + 1;
    let mut last = first - 1;
    for e in n.events.iter().skip((first - 1) as usize) {
        if e.envelope.is_some() || !matches!(e.kind.as_str(), "delivered" | "unavailable") {
            break;
        }
        last = number(&e.sequence)?;
    }
    if last < first {
        return Err(Error::new("workset_empty"));
    }
    let mut w = CapacityWorkset {
        version: WORKSET_VERSION.into(),
        id: String::new(),
        owner: s
            .data
            .state
            .identity
            .clone()
            .ok_or_else(|| Error::new("initialize_required"))?,
        sdk_instance: instance.into(),
        conversation: n
            .binding
            .as_ref()
            .ok_or_else(|| Error::new("network_binding_required"))?
            .conversation
            .clone(),
        context: s.data.state.context.clone(),
        first: first.to_string(),
        last: last.to_string(),
        originals_hash: originals(&s.data, n, first, last)?,
        previous: None,
    };
    w.id = w.digest()?;
    w.validate()?;
    Ok(CapacityWorksetState {
        workset: w,
        phase: WorksetPhase::Prepared,
    })
}

impl PersistentDevice {
    /// 原数据库线程显式读事务；返回本机持久阶段，None表示未准备，不推测远端状态。
    pub fn capacity_workset(&self) -> Result<Option<CapacityWorksetState>> {
        self.database
            .call(|db| db.read(|s| Ok(s.data.network.and_then(|n| n.workset))))
    }

    /// 固定已下载连续控制原件，启用原系统进度保护并升级v7。返回Prepared只承诺本地。
    /// 不等待网络；取消/失联/关闭均不撤销。重复调用只返回同一记录，包括Settled。
    #[cfg(feature = "protected-storage")]
    pub fn prepare_capacity_workset(&self) -> Result<CapacityWorksetState> {
        self.database.call(|db| {
            if let Some(old) = db.read(|s| Ok(s.data.network.and_then(|n| n.workset)))? {
                return Ok(old);
            }
            // 无原件/未知候选在系统预约之前失败；最终仍在写事务里从当前原件重算。
            db.read(|s| select(&s, &"0".repeat(64)))?;
            db.enable_backup()?;
            let result = db
                .update(true, |s| {
                    let instance = s
                        .meta
                        .backup_guard
                        .as_deref()
                        .ok_or_else(|| Error::paused("backup_progress_missing"))?;
                    let state = select(s, instance)?;
                    s.data
                        .network
                        .as_mut()
                        .ok_or_else(|| Error::new("network_binding_required"))?
                        .workset = Some(state.clone());
                    Ok(state)
                })
                .map_err(commit_error)?;
            super::super::checkpoint("workset_after_prepared");
            Ok(result)
        })
    }
}

pub(super) fn commit_error(error: Error) -> Error {
    if error.code == "storage_failure" {
        Error::paused("workset_commit_unknown")
    } else {
        error
    }
}

/// 纳入原Data及所有含Data的完整候选计量；阶段名confirmed是非终态的最大表示。
pub(in crate::persistent) fn project_phase(s: &mut Saved) {
    if let Some(w) = s.data.network.as_mut().and_then(|n| n.workset.as_mut()) {
        if w.phase != WorksetPhase::Settled {
            w.phase = WorksetPhase::Confirmed
        }
    }
}

pub(super) fn check_phase(
    before: Option<&CapacityWorksetState>,
    after: Option<&CapacityWorksetState>,
) -> Result<()> {
    let valid = match (before, after) {
        (None, None) => true,
        (None, Some(a)) => a.phase == WorksetPhase::Prepared,
        (Some(b), Some(a)) if b.workset == a.workset => {
            b.phase == a.phase
                || matches!(
                    (b.phase, a.phase),
                    (WorksetPhase::Prepared, WorksetPhase::Confirmed)
                        | (WorksetPhase::Confirmed, WorksetPhase::Active)
                        | (WorksetPhase::Active, WorksetPhase::Settled)
                )
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::paused("workset_conflict"))
    }
}
