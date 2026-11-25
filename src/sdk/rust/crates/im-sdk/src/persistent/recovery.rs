//! 有限双持久端的显式后继协议；唯一活动轮、双方签名、旧上下文永久封存。
use super::{
    data::Saved, operations, recovery_types::*, recovery_wire as wire, types::*, PersistentDevice,
};

impl PersistentDevice {
    pub fn recovery(&mut self, command: RecoveryCommand) -> Result<RecoveryResult> {
        if !matches!(
            command,
            RecoveryCommand::Inspect { .. } | RecoveryCommand::Status
        ) && self
            .database
            .call(|db| db.read(|s| Ok(super::network::recovery_managed(&s))))?
        {
            return Err(Error::new("network_recovery_managed"));
        }
        self.recovery_internal(command)
    }
    pub(super) fn recovery_internal(&mut self, command: RecoveryCommand) -> Result<RecoveryResult> {
        let saved = self.database.call(|db| db.read(Ok))?;
        let result = match command {
            RecoveryCommand::Inspect { context } => {
                id(&context)?;
                saved
                    .meta
                    .session
                    .iter()
                    .chain(saved.meta.history.iter())
                    .find(|s| s.offer.context().ok().as_ref() == Some(&context))
                    .ok_or_else(|| Error::new("recovery_missing"))?
                    .result()
            }
            RecoveryCommand::Status => saved.meta.session.as_ref().map_or(
                Ok(RecoveryResult {
                    phase: None,
                    context: None,
                    packet: None,
                    commit: None,
                }),
                Session::result,
            ),
            RecoveryCommand::Begin { request_id, action } => {
                self.begin_recovery(saved, request_id, action)
            }
            RecoveryCommand::Accept { offer, peer } => self.accept_recovery(saved, offer, peer),
            RecoveryCommand::Reject { offer, peer } => self.reject_recovery(saved, offer, peer),
            RecoveryCommand::Join { approval } => self.join_recovery(saved, approval),
            RecoveryCommand::Confirm { ready } => self.confirm_recovery(saved, ready),
            RecoveryCommand::Finish { receipt } => self.finish_recovery(saved, receipt),
            RecoveryCommand::Close { peer_close } => self.close_recovery(saved, peer_close),
        }?;
        self.check_access()?;
        Ok(result)
    }
    fn begin_recovery(
        &self,
        mut saved: Saved,
        request: String,
        action: Action,
    ) -> Result<RecoveryResult> {
        id(&request)?;
        action.validate()?;
        let r = saved
            .data
            .requests
            .get(&request)
            .ok_or_else(|| Error::new("request_missing"))?;
        if !operations::matches_input(&r.hash, &action)? {
            return Err(Error::new("request_conflict"));
        }
        if !matches!(r.result, RequestState::Pending) {
            return Err(Error::new("request_not_pending"));
        }
        let request_hash = r.hash.clone();
        if let Some(s) = &saved.meta.session {
            if !matches!(
                s.phase,
                RecoveryPhase::Closed | RecoveryPhase::Committed | RecoveryPhase::Finished
            ) {
                if s.target && s.offer.request == request && s.offer.request_hash == request_hash {
                    return s.result();
                }
                return Err(Error::paused("recovery_active"));
            }
        }
        if let Some(j) = &saved.meta.journal {
            if j.candidate.is_some()
                || j.phase == super::journal::Phase::Reserved
                || j.seed.is_some()
            {
                return Err(Error::new("request_recoverable"));
            }
        }
        let own = saved
            .data
            .state
            .identity
            .clone()
            .ok_or_else(|| Error::paused("identity_evidence_missing"))?;
        let (conversation, peer) = match &action {
            Action::CreateGroup {
                conversation, peer, ..
            }
            | Action::JoinGroup {
                conversation, peer, ..
            } => (conversation.clone(), peer.clone()),
            Action::Send { .. } | Action::Receive { .. } => (
                saved
                    .data
                    .state
                    .conversation
                    .clone()
                    .ok_or_else(|| Error::paused("store_invalid"))?,
                saved
                    .data
                    .state
                    .peer
                    .clone()
                    .ok_or_else(|| Error::paused("store_invalid"))?,
            ),
            _ => return Err(Error::paused("identity_evidence_missing")),
        };
        if peer.scope.service != own.scope.service
            || peer.scope == own.scope
            || peer.identity_key == own.identity_key
        {
            return Err(Error::new("identity_mismatch"));
        }
        let base = operations::fingerprint(&saved)?;
        let previous = retire_session(&mut saved)?;
        saved
            .data
            .requests
            .get_mut(&request)
            .ok_or_else(|| Error::paused("store_invalid"))?
            .input = Some(action);
        let device = wire::fresh(&saved)?;
        let offer = Offer {
            target: own,
            peer,
            conversation,
            old_context: saved.data.state.context.clone(),
            previous,
            request,
            request_hash,
            key_package: hex(&device.key_package()?),
            transport: super::network::recovery_transport(&saved),
        };
        let packet = wire::sign(
            &saved,
            Body::Offer {
                offer: Box::new(offer.clone()),
            },
        )?;
        saved.meta.session = Some(Session {
            offer,
            offer_packet: packet,
            target: true,
            phase: RecoveryPhase::Offered,
            fresh: encode(&device.snapshot()?)?,
            candidate: None,
            approval: None,
            ready: None,
            receipt: None,
            own_close: None,
            peer_close: None,
        });
        super::checkpoint("recovery_before_offer");
        self.save_recovery(base, saved, false, "recovery_after_offer")
    }
    fn accept_recovery(
        &self,
        mut saved: Saved,
        packet: String,
        peer: Identity,
    ) -> Result<RecoveryResult> {
        let Body::Offer { offer } = wire::parse(&packet, &peer)? else {
            return Err(Error::new("invalid_recovery_material"));
        };
        let offer = *offer;
        if let Some(s) = &saved.meta.session {
            if s.offer_packet == packet && !s.target {
                return s.result();
            }
            if !matches!(
                s.phase,
                RecoveryPhase::Closed | RecoveryPhase::Committed | RecoveryPhase::Finished
            ) {
                return Err(Error::paused("recovery_active"));
            }
        }
        let st = &saved.data.state;
        if Some(&offer.peer) != st.identity.as_ref()
            || offer.target != peer
            || offer.old_context != st.context
            || st.peer.as_ref().is_some_and(|p| p != &peer)
            || st
                .conversation
                .as_ref()
                .is_some_and(|c| c != &offer.conversation)
            || offer.target.scope.service != st.scope.service
            || offer.target.scope == st.scope
        {
            return Err(Error::new("recovery_scope_mismatch"));
        }
        if let Some(j) = &saved.meta.journal {
            if j.candidate.is_some()
                || j.phase == super::journal::Phase::Reserved
                || j.seed.is_some()
            {
                return Err(Error::new("request_recoverable"));
            }
            if let Action::CreateGroup {
                peer: p,
                conversation,
                ..
            }
            | Action::JoinGroup {
                peer: p,
                conversation,
                ..
            } = &j.input
            {
                if p != &peer || conversation != &offer.conversation {
                    return Err(Error::new("recovery_scope_mismatch"));
                }
            }
        }
        if let Some(rid) = &saved.data.state.pending_request {
            let input = saved
                .data
                .requests
                .get(rid)
                .and_then(|r| r.input.as_ref())
                .ok_or_else(|| Error::paused("pending_input_required"))?;
            if let Action::CreateGroup {
                peer: p,
                conversation,
                ..
            }
            | Action::JoinGroup {
                peer: p,
                conversation,
                ..
            } = input
            {
                if p != &peer || conversation != &offer.conversation {
                    return Err(Error::new("recovery_scope_mismatch"));
                }
            }
        }
        let base = operations::fingerprint(&saved)?;
        let previous = retire_session(&mut saved)?;
        if offer.previous != previous {
            return Err(Error::new("recovery_predecessor_mismatch"));
        }
        let context = offer.context()?;
        saved.meta.session = Some(Session {
            offer: offer.clone(),
            offer_packet: packet,
            target: false,
            phase: RecoveryPhase::Building,
            fresh: vec![],
            candidate: None,
            approval: None,
            ready: None,
            receipt: None,
            own_close: None,
            peer_close: None,
        });
        self.compare_write(base, saved.clone(), false)?;
        super::checkpoint("recovery_after_accept");
        let base = operations::fingerprint(&saved)?;
        let mut device = wire::fresh(&saved)?;
        let welcome = device.create_group(
            context,
            peer.scope.account,
            peer.scope.device,
            unhex(&peer.identity_key, 32)?,
            unhex(&offer.key_package, 262144)?,
        )?;
        super::checkpoint("recovery_after_create_crypto");
        let approval = wire::sign(
            &saved,
            Body::Approval {
                context: offer.context()?,
                welcome: hex(&welcome),
            },
        )?;
        let session = session_mut(&mut saved)?;
        session.candidate = Some(encode(&device.snapshot()?)?);
        session.approval = Some(approval);
        session.phase = RecoveryPhase::Prepared;
        self.save_recovery(base, saved, false, "recovery_after_approval")
    }
    pub(super) fn save_recovery(
        &self,
        base: String,
        saved: Saved,
        committing: bool,
        checkpoint: &str,
    ) -> Result<RecoveryResult> {
        let mut result = session(&saved)?.result()?;
        if committing {
            result.commit = Some(RecoveryCommit {
                revision: saved.data.state.revision.clone(),
                context: saved.data.state.context.clone(),
            });
        }
        self.compare_write(base, saved, committing)
            .map_err(|error| {
                if error.code == "storage_failure" {
                    Error::paused(if committing {
                        "recovery_commit_unknown"
                    } else {
                        "recovery_write_unknown"
                    })
                } else {
                    error
                }
            })?;
        super::checkpoint(checkpoint);
        Ok(result)
    }
}
pub(super) fn session(saved: &Saved) -> Result<&Session> {
    saved
        .meta
        .session
        .as_ref()
        .ok_or_else(|| Error::new("recovery_missing"))
}
pub(super) fn session_mut(saved: &mut Saved) -> Result<&mut Session> {
    saved
        .meta
        .session
        .as_mut()
        .ok_or_else(|| Error::new("recovery_missing"))
}
pub(super) fn retire_session(saved: &mut Saved) -> Result<Option<String>> {
    if saved.meta.history.len() >= 16
        || saved.data.transitions.len() >= 16
        || encode(&saved.meta)?.len()
            + encode(&saved.data)?.len()
            + saved.crypto.len()
            + 8 * 1024 * 1024
            > super::store::MAX_META
    {
        return Err(Error::new("recovery_limit"));
    }
    if let Some(s) = saved.meta.session.take() {
        if !matches!(
            s.phase,
            RecoveryPhase::Closed | RecoveryPhase::Committed | RecoveryPhase::Finished
        ) {
            return Err(Error::paused("recovery_active"));
        }
        let previous = s.offer.context()?;
        saved.meta.history.push(s);
        Ok(Some(previous))
    } else {
        Ok(None)
    }
}
