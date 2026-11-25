//! 每轮消耗不重叠的非空原控制区间，512事件给出最多512轮的上界。
#[cfg(any(feature = "protected-storage", test))]
use super::super::data::Saved;
use super::{
    super::{types::*, PersistentDevice},
    types::NetworkData,
    workset,
    workset_types::*,
};

pub(super) fn validate(n: &NetworkData) -> Result<()> {
    let bad = || Error::paused("workset_conflict");
    if n.workset_history.len() >= 512 || (!n.workset_history.is_empty() && n.workset.is_none()) {
        return Err(bad());
    }
    let mut previous: Option<&CapacityWorkset> = None;
    for state in n.workset_history.iter().chain(n.workset.iter()) {
        state.workset.validate()?;
        if let Some(old) = previous {
            if !state.workset.follows(old)? {
                return Err(bad());
            }
        } else if state.workset.version != WORKSET_VERSION {
            return Err(bad());
        }
        previous = Some(&state.workset);
    }
    if n.workset_history
        .iter()
        .any(|w| w.phase != WorksetPhase::Settled)
    {
        return Err(bad());
    }
    Ok(())
}

/// 唯一Store调用：历史只能原样追加已结清当前轮，不能覆盖、删减或重排。
pub(in crate::persistent) fn check_transition(
    before: Option<&CapacityWorksetState>,
    history_before: &[CapacityWorksetState],
    after: Option<&CapacityWorksetState>,
    history_after: &[CapacityWorksetState],
) -> Result<()> {
    if history_before == history_after {
        return workset::check_phase(before, after);
    }
    if let (Some(old), Some(next)) = (before, after) {
        if old.phase == WorksetPhase::Settled
            && next.phase == WorksetPhase::Prepared
            && next.workset.follows(&old.workset)?
            && history_after.len() == history_before.len() + 1
            && history_after.starts_with(history_before)
            && history_after.last() == Some(old)
        {
            return Ok(());
        }
    }
    Err(Error::paused("workset_conflict"))
}

#[cfg(any(feature = "protected-storage", test))]
fn successor(s: &Saved, previous: &str) -> Option<CapacityWorksetState> {
    let n = s.data.network.as_ref()?;
    n.workset_history
        .iter()
        .chain(n.workset.iter())
        .find(|w| w.workset.previous.as_deref() == Some(previous))
        .cloned()
}

#[cfg(any(feature = "protected-storage", test))]
pub(super) fn prepare_next(s: &mut Saved, previous: &str) -> Result<CapacityWorksetState> {
    if unhex(previous, 32)?.len() != 32 {
        return Err(Error::new("workset_invalid"));
    }
    let n = s
        .data
        .network
        .as_ref()
        .ok_or_else(|| Error::new("network_binding_required"))?;
    // 已生成的唯一后继可精确重试，即使它已结清或成为历史，也不新开第三轮。
    if let Some(existing) = successor(s, previous) {
        return Ok(existing);
    }
    let old = n
        .workset
        .as_ref()
        .ok_or_else(|| Error::new("workset_not_prepared"))?;
    if old.workset.id != previous {
        return Err(Error::paused("workset_conflict"));
    }
    if old.phase != WorksetPhase::Settled {
        return Err(Error::new("workset_not_settled"));
    }
    let mut next = workset::select_originals(s, &old.workset.sdk_instance)?;
    next.workset.version = WORKSET_CHAIN_VERSION.into();
    next.workset.previous = Some(previous.into());
    next.workset.id = next.workset.digest()?;
    next.workset.validate()?;
    if !next.workset.follows(&old.workset)? {
        return Err(Error::paused("workset_conflict"));
    }
    let old = old.clone();
    let n = s
        .data
        .network
        .as_mut()
        .ok_or_else(|| Error::new("network_binding_required"))?;
    n.workset_history.push(old);
    n.workset = Some(next.clone());
    Ok(next)
}

impl PersistentDevice {
    /// previous须为本库前轮ID；只有已保存Service终态的轮可接续。
    /// 同一previous始终返回同一后继。原件由Rust选定，旧轮永久保留；首次成功升级v8。
    /// 取消/失联/关闭不解除承诺，storage_failure保守映射为workset_commit_unknown。
    #[cfg(feature = "protected-storage")]
    pub fn prepare_next_capacity_workset(&self, previous: String) -> Result<CapacityWorksetState> {
        self.database.call(move |db| {
            if let Some(existing) = db.read(|s| Ok(successor(&s, &previous)))? {
                return Ok(existing);
            }
            let result = db
                .update(true, |s| prepare_next(s, &previous))
                .map_err(workset::commit_error)?;
            super::super::checkpoint("workset_after_next_prepared");
            Ok(result)
        })
    }
}
