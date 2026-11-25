use super::{
    super::{
        data::Saved, journal::Phase, recovery_types::RecoveryPhase, types::*, PersistentDevice,
    },
    recovery_types::*,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new("clock_invalid"))?
        .as_millis()
        .try_into()
        .map_err(|_| Error::new("clock_invalid"))
}
impl PersistentDevice {
    /// 有界查询一份已退休未解密原件；没有活动数据库游标跨公开边界。
    pub fn network_unavailable(
        &self,
        sequence: String,
    ) -> Result<Option<super::types::UnavailableMessage>> {
        number(&sequence)?;
        self.database.call(move |db| {
            db.read(|s| {
                let Some(n) = s.data.network.as_ref() else {
                    return Ok(None);
                };
                if !n.retired_events.contains(&sequence) {
                    return Ok(None);
                }
                let event = n
                    .events
                    .iter()
                    .find(|e| e.sequence == sequence)
                    .ok_or_else(|| Error::paused("network_store_invalid"))?;
                Ok(Some(super::types::UnavailableMessage {
                    sequence,
                    reason: "context_retired".into(),
                    acceptance: event.acceptance.clone(),
                    envelope: event
                        .envelope
                        .clone()
                        .ok_or_else(|| Error::paused("network_store_invalid"))?,
                }))
            })
        })
    }
    /// 明确授权后持久保存意图；材料由网络owner转交。返回不表示对端批准或恢复完成。
    pub fn network_recovery(
        &mut self,
        command: NetworkRecoveryCommand,
    ) -> Result<Option<NetworkRecoveryState>> {
        if matches!(command, NetworkRecoveryCommand::Status) {
            return self.database.call(|db| db.read(|s| projection(&s)));
        }
        let saved = self.database.call(|db| db.read(Ok))?;
        let network = saved
            .data
            .network
            .as_ref()
            .ok_or_else(|| Error::new("network_binding_required"))?;
        let binding = network
            .binding
            .as_ref()
            .ok_or_else(|| Error::new("network_binding_required"))?;
        let mut recovery = network.recovery.clone().unwrap_or_default();
        let decision_kind = command_kind(&command);
        match command {
            NetworkRecoveryCommand::Begin { request_id, action } => {
                id(&request_id)?;
                action.validate()?;
                let record = saved
                    .data
                    .requests
                    .get(&request_id)
                    .ok_or_else(|| Error::new("request_missing"))?;
                if !super::super::operations::matches_input(&record.hash, &action)? {
                    return Err(Error::new("request_conflict"));
                }
                if !matches!(record.result, RequestState::Pending) {
                    return Err(Error::new("request_not_pending"));
                }
                recoverable(&saved)?;
                if let Some(old) = &recovery.intent {
                    if old.request == request_id
                        && old.request_hash == record.hash
                        && !recovery
                            .round
                            .as_ref()
                            .is_some_and(|r| r.status == "closed")
                    {
                        return projection(&saved);
                    }
                }
                if recovery
                    .round
                    .as_ref()
                    .is_some_and(|r| !matches!(r.status.as_str(), "complete" | "closed"))
                {
                    return Err(Error::new("recovery_active"));
                }
                if saved.meta.session.as_ref().is_some_and(|s| {
                    !matches!(
                        s.phase,
                        RecoveryPhase::Closed | RecoveryPhase::Committed | RecoveryPhase::Finished
                    )
                }) {
                    return Err(Error::new("recovery_active"));
                }
                let mut nonce = [0u8; 32];
                getrandom::getrandom(&mut nonce).map_err(|_| Error::new("entropy_unavailable"))?;
                recovery = RecoveryData {
                    intent: Some(Reservation {
                        version: "successor-alpha1".into(),
                        id: hex(&nonce),
                        target: saved
                            .data
                            .state
                            .identity
                            .clone()
                            .ok_or_else(|| Error::new("initialize_required"))?,
                        peer: binding.peer.clone(),
                        conversation: binding.conversation.clone(),
                        old_context: saved.data.state.context.clone(),
                        previous: saved
                            .meta
                            .session
                            .as_ref()
                            .map(|s| s.offer.context())
                            .transpose()?,
                        request: request_id,
                        request_hash: record.hash.clone(),
                        deadline: (now()? + 15 * 60 * 1000).to_string(),
                    }),
                    round: recovery.round,
                    decision: None,
                };
            }
            NetworkRecoveryCommand::Approve { round_id }
            | NetworkRecoveryCommand::Reject { round_id }
            | NetworkRecoveryCommand::Seal { round_id } => {
                // 下方由命令判别指定具体授权，所有输入只引用已核验的本地轮。
                return self.decide_network_recovery(round_id, decision_kind);
            }
            NetworkRecoveryCommand::Status => return projection(&saved),
        }
        save(self, recovery)?;
        self.database.call(|db| db.read(|s| projection(&s)))
    }
    fn decide_network_recovery(
        &mut self,
        round_id: String,
        decision: &str,
    ) -> Result<Option<NetworkRecoveryState>> {
        let saved = self.database.call(|db| db.read(Ok))?;
        recoverable(&saved)?;
        let mut r = saved
            .data
            .network
            .as_ref()
            .and_then(|n| n.recovery.clone())
            .ok_or_else(|| Error::new("recovery_missing"))?;
        let round = r
            .round
            .as_ref()
            .filter(|r| r.reservation.id == round_id)
            .ok_or_else(|| Error::new("recovery_missing"))?;
        let target = Some(&round.reservation.target) == saved.data.state.identity.as_ref();
        if decision == "seal" {
            let phase = saved.meta.session.as_ref().map(|s| &s.phase);
            if !matches!(
                phase,
                Some(
                    RecoveryPhase::Building
                        | RecoveryPhase::Joining
                        | RecoveryPhase::Closing
                        | RecoveryPhase::Closed
                )
            ) {
                return Err(Error::new("recovery_close_not_allowed"));
            }
        } else {
            if target {
                return Err(Error::new("recovery_role_mismatch"));
            }
            if !round.materials.contains_key("offer") {
                return Err(Error::new("recovery_offer_required"));
            }
            if r.decision.as_deref() == Some(decision) {
                return projection(&saved);
            }
            if r.decision.is_some() {
                return Err(Error::new("recovery_decision_conflict"));
            }
            if decision == "approve" && now()? > number(&round.reservation.deadline)? {
                return Err(Error::new("recovery_deadline"));
            }
            if round.status != "offered" {
                return Err(Error::new("recovery_order"));
            }
        }
        r.decision = Some(decision.into());
        save(self, r)?;
        self.database.call(|db| db.read(|s| projection(&s)))
    }
}
fn command_kind(command: &NetworkRecoveryCommand) -> &'static str {
    match command {
        NetworkRecoveryCommand::Approve { .. } => "approve",
        NetworkRecoveryCommand::Reject { .. } => "reject",
        _ => "seal",
    }
}
fn recoverable(saved: &Saved) -> Result<()> {
    if saved
        .meta
        .journal
        .as_ref()
        .is_some_and(|j| j.candidate.is_some() || j.phase == Phase::Reserved || j.seed.is_some())
    {
        return Err(Error::new("request_recoverable"));
    }
    Ok(())
}
pub(super) fn save(device: &PersistentDevice, recovery: RecoveryData) -> Result<()> {
    device.database.call(move |db| {
        db.update(false, |s| {
            s.data
                .network
                .as_mut()
                .ok_or_else(|| Error::new("network_binding_required"))?
                .recovery = Some(recovery);
            Ok(())
        })
    })
}
