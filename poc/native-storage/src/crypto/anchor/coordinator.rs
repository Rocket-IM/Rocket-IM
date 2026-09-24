//! 网络/独立进程等待在数据库事务之外；完整日志可恢复，未决计算绝不重做。
use super::{
    contract::{AnchorFault, Gate, Journal, StoredResult},
    error,
    protocol::{self, Action, Status},
    AnchoredClient,
};
use crate::{
    crypto::{Metrics, Reply},
    model::{revision, Result},
};
use serde_json::Value;

impl AnchoredClient {
    pub(super) fn run(
        &mut self,
        input: Value,
        kind: &str,
        fault: AnchorFault,
        operation: impl FnOnce(&mut crate::crypto::Client) -> Reply,
    ) -> Reply {
        let gate = self.reserve(input, fault, false);
        let gate = match gate {
            Ok(gate) => gate,
            Err(error) => return self.inner.reply(Err(error), Metrics::default(), vec![]),
        };
        let mut reply = operation(&mut self.inner);
        if !reply.ok {
            if let Some(error) = &mut reply.error {
                error.paused = true;
            }
            return reply;
        }
        let result = (|| {
            pause(
                fault,
                AnchorFault::PauseAfterCandidateCommit,
                "after_candidate_commit",
                &reply.metrics,
            )?;
            let local = self.inner.database.call(|store| store.anchor_local())?;
            let journal = local
                .journal
                .ok_or_else(|| error("anchor_journal_missing"))?;
            if journal.gate != gate
                || journal.target != local.head
                || journal.result
                    != (StoredResult {
                        kind: kind.into(),
                        value: reply
                            .result
                            .clone()
                            .ok_or_else(|| error("anchor_journal_invalid"))?,
                    })
            {
                return Err(error("anchor_state_changed"));
            }
            self.finish(&journal)?;
            pause(
                fault,
                AnchorFault::PauseAfterAnchorFinish,
                "after_anchor_finish",
                &reply.metrics,
            )?;
            let target = journal.target;
            let metrics = reply.metrics.clone();
            self.inner.database.call(move |store| {
                store.anchor_clear(&gate, &target)?;
                // 仅测试故障：清理事务已结束，在作业后置保护检查前等待系统锁定。
                pause(
                    fault,
                    AnchorFault::PauseAfterAnchorClear,
                    "after_anchor_clear",
                    &metrics,
                )
            })
        })();
        reply
            .trace
            .extend(std::mem::take(&mut self.inner.database.trace));
        if let Err(error) = result {
            reply.ok = false;
            reply.result = None;
            reply.events.clear();
            reply.error = Some(error);
        }
        reply
    }
    pub(super) fn reserve(
        &mut self,
        input: Value,
        fault: AnchorFault,
        rebuilding: bool,
    ) -> Result<Gate> {
        let input = crate::crypto::model::hash(
            &serde_json::to_vec(&input).map_err(|_| error("encoding_failed"))?,
        );
        let txn = protocol::random_hex()?;
        let gate = self.inner.database.call(move |store| {
            if rebuilding {
                store.anchor_begin_rebuild(&txn, &input)
            } else {
                store.anchor_begin(&txn, &input)
            }
        })?;
        pause(
            fault,
            AnchorFault::PauseAfterLocalGate,
            "after_local_gate",
            &Metrics::default(),
        )?;
        let observed = self
            .remote
            .rpc(Action::Inspect, &gate.txn, &gate.base, "absent", "0")?;
        if observed.status != Status::Inspected {
            return Err(error("anchor_response"));
        }
        if observed.head != gate.base {
            return Err(error("anchor_head_mismatch"));
        }
        if observed.active_txn.is_some() {
            return Err(error("anchor_unresolved"));
        }
        let reserved = self.remote.rpc(
            Action::Reserve,
            &gate.txn,
            &gate.base,
            "absent",
            &observed.revision,
        )?;
        if reserved.status != Status::Reserved
            || reserved.head != gate.base
            || reserved.active_txn.as_ref() != Some(&gate.txn)
            || reserved.revision != bump(&observed.revision)?
        {
            return Err(error("anchor_conflict"));
        }
        let owned = gate.clone();
        let gate = self
            .inner
            .database
            .call(move |store| store.anchor_reserved(&owned, &reserved.revision))?;
        pause(
            fault,
            AnchorFault::PauseAfterAnchorReserve,
            "after_anchor_reserve",
            &Metrics::default(),
        )?;
        let owned = gate.clone();
        self.inner
            .database
            .call(move |store| store.anchor_activate(&owned))?;
        Ok(gate)
    }
    pub(super) fn finish(&self, journal: &Journal) -> Result<()> {
        let gate = &journal.gate;
        let reserved = gate
            .reserved_revision
            .as_deref()
            .ok_or_else(|| error("anchor_journal_invalid"))?;
        let response = self.remote.rpc(
            Action::Finish,
            &gate.txn,
            &gate.base,
            &journal.target,
            reserved,
        )?;
        if !matches!(
            response.status,
            Status::Finished | Status::FinishedDuplicate
        ) || response.head != journal.target
            || response.active_txn.is_some()
            || response.revision != bump(reserved)?
        {
            return Err(error("anchor_conflict"));
        }
        Ok(())
    }
    /// 显式恢复只使用同一业务事务保存的日志；不恢复 provider 或重新计算密码结果。
    pub fn recover(&mut self) -> Reply {
        let result = (|| {
            let local = self.inner.database.call(|store| store.anchor_local())?;
            let journal = local.journal.ok_or_else(|| error("anchor_unresolved"))?;
            if local.head != journal.target || local.gate.as_ref() != Some(&journal.gate) {
                return Err(error("anchor_state_changed"));
            }
            self.finish(&journal)?;
            let result = journal.result;
            self.inner
                .database
                .call(move |store| store.anchor_clear(&journal.gate, &journal.target))?;
            serde_json::to_value(result).map_err(|_| error("encoding_failed"))
        })();
        self.inner.reply(result, Metrics::default(), vec![])
    }
}
fn bump(value: &str) -> Result<String> {
    revision(value)?
        .checked_add(1)
        .map(|v| v.to_string())
        .ok_or_else(|| error("anchor_capacity"))
}
fn pause(actual: AnchorFault, target: AnchorFault, stage: &str, metrics: &Metrics) -> Result<()> {
    if actual == target {
        crate::crypto::checkpoint(stage, metrics)?;
    }
    Ok(())
}
