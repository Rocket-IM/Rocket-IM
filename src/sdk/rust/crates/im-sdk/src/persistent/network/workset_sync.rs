//! 网络不是跨库事务；每个回复必须匹配固定原件并先持久保存再交付成功。
use super::{
    super::{data::Saved, types::*, PersistentDevice},
    session::NetworkSession,
    workset_types::*,
};

impl NetworkSession {
    pub(super) fn workset_step(
        &mut self,
        device: &PersistentDevice,
        saved: &Saved,
    ) -> Result<bool> {
        let Some(n) = &saved.data.network else {
            return Ok(false);
        };
        let Some(local) = &n.workset else {
            return Ok(false);
        };
        let (operation, next, expected) = match local.phase {
            WorksetPhase::Prepared => (
                "capacity_workset_prepare",
                WorksetPhase::Confirmed,
                WorksetPhase::Prepared,
            ),
            WorksetPhase::Confirmed => (
                "capacity_workset_confirm",
                WorksetPhase::Active,
                WorksetPhase::Confirmed,
            ),
            WorksetPhase::Active if number(&n.reported)? >= number(&local.workset.last)? => (
                "capacity_workset_settle",
                WorksetPhase::Settled,
                WorksetPhase::Settled,
            ),
            _ => return Ok(false),
        };
        let reply: CapacityWorksetState = self.rpc(operation, &local.workset)?;
        // 对旧阶段的精确重试可以看到远端更晚阶段，但从不倒退本地或直接跳过确认。
        let allowed = reply.phase == expected
            || match expected {
                WorksetPhase::Prepared => {
                    matches!(reply.phase, WorksetPhase::Confirmed | WorksetPhase::Settled)
                }
                WorksetPhase::Confirmed => reply.phase == WorksetPhase::Settled,
                _ => false,
            };
        if !allowed || reply.workset != local.workset {
            return Err(Error::paused("workset_reply_invalid"));
        }
        super::super::checkpoint(match next {
            WorksetPhase::Confirmed => "workset_after_prepare_reply",
            WorksetPhase::Active => "workset_after_confirm_reply",
            _ => "workset_after_settle_reply",
        });
        let original = local.clone();
        device
            .database
            .call(move |db| {
                db.update(true, |s| {
                    let n = s
                        .data
                        .network
                        .as_mut()
                        .ok_or_else(|| Error::paused("workset_invalid"))?;
                    if n.workset.as_ref() != Some(&original) {
                        return Err(Error::paused("workset_conflict"));
                    }
                    if next == WorksetPhase::Settled
                        && number(&n.reported)? < number(&original.workset.last)?
                    {
                        return Err(Error::paused("workset_not_complete"));
                    }
                    n.workset = Some(CapacityWorksetState {
                        workset: original.workset,
                        phase: next,
                    });
                    Ok(())
                })
            })
            .map_err(super::workset::commit_error)?;
        super::super::checkpoint(match next {
            WorksetPhase::Confirmed => "workset_after_confirmed",
            WorksetPhase::Active => "workset_after_active",
            _ => "workset_after_settled",
        });
        Ok(true)
    }
}
