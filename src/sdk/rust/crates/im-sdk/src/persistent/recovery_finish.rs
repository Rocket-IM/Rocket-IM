//! 有限双持久端的显式后继协议；唯一活动轮、双方签名、旧上下文永久封存。
use super::{
    data::{Saved, Transition},
    journal::Candidate,
    operations,
    recovery::{session, session_mut},
    recovery_types::*,
    recovery_wire as wire,
    types::*,
    PersistentDevice,
};

impl PersistentDevice {
    pub(super) fn join_recovery(&self, mut saved: Saved, packet: String) -> Result<RecoveryResult> {
        let s = session(&saved)?;
        if !s.target {
            return Err(Error::new("recovery_role_mismatch"));
        }
        let Body::Approval { context, welcome } = wire::parse(&packet, &s.offer.peer)? else {
            return Err(Error::new("invalid_recovery_material"));
        };
        if context != s.offer.context()? {
            return Err(Error::new("recovery_context_mismatch"));
        }
        if s.approval.as_ref().is_some_and(|p| p != &packet) {
            return Err(Error::new("recovery_material_conflict"));
        }
        if s.phase != RecoveryPhase::Offered {
            return if matches!(
                s.phase,
                RecoveryPhase::Joining | RecoveryPhase::Ready | RecoveryPhase::Finished
            ) {
                s.result()
            } else {
                Err(Error::paused("recovery_closed"))
            };
        }
        let base = operations::fingerprint(&saved)?;
        let s = session_mut(&mut saved)?;
        s.approval = Some(packet);
        s.phase = RecoveryPhase::Joining;
        self.compare_write(base, saved.clone(), false)?;
        super::checkpoint("recovery_after_join_reserve");
        let base = operations::fingerprint(&saved)?;
        let s = session(&saved)?;
        let mut device = wire::candidate_device(&s.fresh, &s.offer.target)?;
        device.join_group(
            context.clone(),
            s.offer.peer.scope.account.clone(),
            s.offer.peer.scope.device.clone(),
            unhex(&s.offer.peer.identity_key, 32)?,
            unhex(&welcome, 262144)?,
        )?;
        super::checkpoint("recovery_after_join_crypto");
        let ready = wire::sign(
            &saved,
            Body::Ready {
                context,
                approval_hash: hash(
                    s.approval
                        .as_ref()
                        .ok_or_else(|| Error::paused("store_invalid"))?
                        .as_bytes(),
                ),
            },
        )?;
        let s = session_mut(&mut saved)?;
        s.candidate = Some(encode(&device.snapshot()?)?);
        s.ready = Some(ready);
        s.phase = RecoveryPhase::Ready;
        self.save_recovery(base, saved, false, "recovery_after_ready")
    }
    pub(super) fn confirm_recovery(
        &self,
        mut saved: Saved,
        packet: String,
    ) -> Result<RecoveryResult> {
        let s = session(&saved)?;
        if s.target {
            return Err(Error::new("recovery_role_mismatch"));
        }
        let Body::Ready {
            context,
            approval_hash,
        } = wire::parse(&packet, &s.offer.target)?
        else {
            return Err(Error::new("invalid_recovery_material"));
        };
        if context != s.offer.context()?
            || s.approval
                .as_ref()
                .is_none_or(|a| hash(a.as_bytes()) != approval_hash)
        {
            return Err(Error::new("recovery_material_conflict"));
        }
        if s.phase == RecoveryPhase::Committed {
            return if s.ready.as_ref() == Some(&packet) {
                s.result()
            } else {
                Err(Error::new("recovery_material_conflict"))
            };
        }
        if s.phase != RecoveryPhase::Prepared {
            return Err(Error::paused("recovery_not_prepared"));
        }
        let base = operations::fingerprint(&saved)?;
        let receipt = wire::sign(
            &saved,
            Body::Commit {
                context,
                ready_hash: hash(packet.as_bytes()),
            },
        )?;
        let s = session_mut(&mut saved)?;
        s.ready = Some(packet);
        s.receipt = Some(receipt);
        s.phase = RecoveryPhase::Committed;
        install(&mut saved)?;
        self.save_recovery(base, saved, true, "recovery_after_confirm")
    }
    pub(super) fn finish_recovery(
        &self,
        mut saved: Saved,
        packet: String,
    ) -> Result<RecoveryResult> {
        let s = session(&saved)?;
        if !s.target {
            return Err(Error::new("recovery_role_mismatch"));
        }
        let Body::Commit {
            context,
            ready_hash,
        } = wire::parse(&packet, &s.offer.peer)?
        else {
            return Err(Error::new("invalid_recovery_material"));
        };
        if context != s.offer.context()?
            || s.ready
                .as_ref()
                .is_none_or(|r| hash(r.as_bytes()) != ready_hash)
        {
            return Err(Error::new("recovery_material_conflict"));
        }
        if s.phase == RecoveryPhase::Finished {
            return if s.receipt.as_ref() == Some(&packet) {
                s.result()
            } else {
                Err(Error::new("recovery_material_conflict"))
            };
        }
        if s.phase != RecoveryPhase::Ready {
            return Err(Error::paused("recovery_not_ready"));
        }
        let base = operations::fingerprint(&saved)?;
        let s = session_mut(&mut saved)?;
        s.receipt = Some(packet);
        s.phase = RecoveryPhase::Finished;
        install(&mut saved)?;
        self.save_recovery(base, saved, true, "recovery_after_finish")
    }
    pub(super) fn close_recovery(
        &self,
        mut saved: Saved,
        peer_close: Option<String>,
    ) -> Result<RecoveryResult> {
        let s = session(&saved)?;
        let base = operations::fingerprint(&saved)?;
        let context = s.offer.context()?;
        if let Some(packet) = &peer_close {
            if !matches!(wire::parse(packet,wire::expected_peer(s))?,Body::Close {context:c} if c == context)
            {
                return Err(Error::new("recovery_material_conflict"));
            }
            if matches!(
                s.phase,
                RecoveryPhase::Ready | RecoveryPhase::Committed | RecoveryPhase::Finished
            ) {
                return Err(Error::paused("recovery_must_finish"));
            }
        } else if !matches!(
            s.phase,
            RecoveryPhase::Building
                | RecoveryPhase::Joining
                | RecoveryPhase::Closing
                | RecoveryPhase::Closed
        ) {
            return Err(Error::new("recovery_close_not_allowed"));
        }
        let own_close = if let Some(p) = &s.own_close {
            p.clone()
        } else {
            wire::sign(&saved, Body::Close { context })?
        };
        let s = session_mut(&mut saved)?;
        if let Some(packet) = peer_close {
            if s.peer_close.as_ref().is_some_and(|p| p != &packet) {
                return Err(Error::new("recovery_material_conflict"));
            }
            s.peer_close = Some(packet);
        }
        s.own_close = Some(own_close);
        s.phase = if s.peer_close.is_some() {
            RecoveryPhase::Closed
        } else {
            RecoveryPhase::Closing
        };
        self.save_recovery(base, saved, false, "recovery_after_close")
    }
}
fn install(saved: &mut Saved) -> Result<()> {
    let s = session(saved)?;
    let context = s.offer.context()?;
    let crypto = s
        .candidate
        .clone()
        .ok_or_else(|| Error::paused("recovery_candidate_missing"))?;
    let peer = wire::expected_peer(s).clone();
    let conversation = s.offer.conversation.clone();
    saved.meta.archives.push(Candidate {
        data: saved.data.clone(),
        crypto: saved.crypto.clone(),
    });
    if let Some(rid) = saved.data.state.pending_request.take() {
        saved
            .data
            .requests
            .get_mut(&rid)
            .ok_or_else(|| Error::paused("store_invalid"))?
            .result = RequestState::Retired {
            context: context.clone(),
        };
    }
    saved.meta.journal = None;
    saved.data.state.context = context.clone();
    saved.data.state.peer = Some(peer);
    saved.data.state.conversation = Some(conversation);
    saved.data.state.revision = number(&saved.data.state.revision)?
        .checked_add(1)
        .ok_or_else(|| Error::new("revision_limit"))?
        .to_string();
    saved.data.transitions.push(Transition {
        context,
        revision: saved.data.state.revision.clone(),
    });
    saved.crypto = crypto;
    Ok(())
}
