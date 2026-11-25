//! 对端拒绝尚未批准的Offer：保存双方可核验的封存证据，不建立密码候选。
use super::{
    data::Saved, operations, recovery_types::*, recovery_wire as wire, types::*, PersistentDevice,
};

impl PersistentDevice {
    pub(super) fn reject_recovery(
        &self,
        mut saved: Saved,
        packet: String,
        peer: Identity,
    ) -> Result<RecoveryResult> {
        let Body::Offer { offer } = wire::parse(&packet, &peer)? else {
            return Err(Error::new("invalid_recovery_material"));
        };
        if let Some(s) = &saved.meta.session {
            if s.offer_packet == packet && !s.target {
                return if matches!(s.phase, RecoveryPhase::Closing | RecoveryPhase::Closed) {
                    s.result()
                } else {
                    Err(Error::new("recovery_already_authorized"))
                };
            }
            if !matches!(
                s.phase,
                RecoveryPhase::Closed | RecoveryPhase::Committed | RecoveryPhase::Finished
            ) {
                return Err(Error::paused("recovery_active"));
            }
        }
        let st = &saved.data.state;
        if saved.meta.journal.as_ref().is_some_and(|j| {
            j.candidate.is_some() || j.phase == super::journal::Phase::Reserved || j.seed.is_some()
        }) {
            return Err(Error::new("request_recoverable"));
        }
        if Some(&offer.peer) != st.identity.as_ref()
            || offer.target != peer
            || offer.old_context != st.context
            || st.peer.as_ref() != Some(&peer)
            || st.conversation.as_ref() != Some(&offer.conversation)
        {
            return Err(Error::new("recovery_scope_mismatch"));
        }
        let base = operations::fingerprint(&saved)?;
        let previous = super::recovery::retire_session(&mut saved)?;
        if offer.previous != previous {
            return Err(Error::new("recovery_predecessor_mismatch"));
        }
        let close = wire::sign(
            &saved,
            Body::Close {
                context: offer.context()?,
            },
        )?;
        saved.meta.session = Some(Session {
            offer: *offer,
            offer_packet: packet,
            target: false,
            phase: RecoveryPhase::Closing,
            fresh: vec![],
            candidate: None,
            approval: None,
            ready: None,
            receipt: None,
            own_close: Some(close),
            peer_close: None,
        });
        self.save_recovery(base, saved, false, "recovery_after_reject")
    }
}
