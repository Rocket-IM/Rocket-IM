//! 规范字节签名与完整会话关联；本地摘要不是防恶意回滚的外部锚。
use super::{
    data::{Data, Saved},
    recovery_types::*,
    types::*,
};
use rocket_crypto_core::{recovery::verify_recovery, storage::Snapshot, Device};

pub(super) fn sign(saved: &Saved, body: Body) -> Result<String> {
    let sender = saved
        .data
        .state
        .identity
        .clone()
        .ok_or_else(|| Error::paused("identity_evidence_missing"))?;
    let bytes = encode(&(sender.clone(), body.clone()))?;
    let s = &sender.scope;
    let signature = snapshot(saved)?.sign_recovery(&s.service, &s.account, &s.device, &bytes)?;
    Ok(hex(&encode(&Frame {
        sender,
        body,
        signature: hex(&signature),
    })?))
}
pub(super) fn parse(packet: &str, expected: &Identity) -> Result<Body> {
    let bytes = unhex(packet, 262144)?;
    let frame: Frame =
        serde_json::from_slice(&bytes).map_err(|_| Error::new("invalid_recovery_material"))?;
    if encode(&frame)? != bytes || &frame.sender != expected {
        return Err(Error::new("recovery_identity_mismatch"));
    }
    expected.validate()?;
    verify_recovery(
        &unhex(&expected.identity_key, 32)?,
        &encode(&(frame.sender, frame.body.clone()))?,
        &unhex(&frame.signature, 64)?,
    )
    .map_err(|_| Error::new("invalid_recovery_signature"))?;
    Ok(frame.body)
}
pub(super) fn context(body: &Body) -> Result<String> {
    Ok(match body {
        Body::Offer { offer } => offer.context()?,
        Body::Approval { context, .. }
        | Body::Ready { context, .. }
        | Body::Commit { context, .. }
        | Body::Close { context }
        | Body::Installed { context, .. } => context.clone(),
    })
}
pub(super) fn expected_peer(session: &Session) -> &Identity {
    if session.target {
        &session.offer.peer
    } else {
        &session.offer.target
    }
}
pub(super) fn fresh(saved: &Saved) -> Result<Device> {
    let scope = &saved.data.state.scope;
    Ok(snapshot(saved)?.fresh_context(&scope.service, &scope.account, &scope.device)?)
}
pub(super) fn candidate_device(bytes: &[u8], identity: &Identity) -> Result<Device> {
    let s = &identity.scope;
    let snap: Snapshot = decode(bytes)?;
    let device = Device::restore(snap, &s.service, &s.account, &s.device)?;
    if hex(&device.identity_key()?) != identity.identity_key {
        return Err(Error::paused("crypto_state_invalid"));
    }
    Ok(device)
}
pub(super) fn validate_session(session: &Session, data: &Data, _crypto: &[u8]) -> Result<()> {
    let bad = || Error::paused("recovery_evidence_invalid");
    let o = &session.offer;
    o.target.validate().map_err(|_| bad())?;
    o.peer.validate().map_err(|_| bad())?;
    id(&o.conversation).map_err(|_| bad())?;
    id(&o.old_context).map_err(|_| bad())?;
    id(&o.request).map_err(|_| bad())?;
    if o.target.scope.service != o.peer.scope.service
        || o.target.scope == o.peer.scope
        || o.target.identity_key == o.peer.identity_key
        || unhex(&o.request_hash, 32).map_err(|_| bad())?.len() != 32
    {
        return Err(bad());
    }
    if let Some(t) = &o.transport {
        if t.version != "successor-alpha1"
            || id(&t.round_id).is_err()
            || number(&t.deadline).is_err()
        {
            return Err(bad());
        }
    }
    let own = if session.target { &o.target } else { &o.peer };
    if data.state.identity.as_ref() != Some(own) {
        return Err(bad());
    }
    if !matches!(parse(&session.offer_packet,&o.target).map_err(|_| bad())?, Body::Offer { offer } if *offer == *o)
    {
        return Err(bad());
    }
    let ctx = o.context()?;
    for (packet, peer, kind) in [
        (&session.approval, &o.peer, 0),
        (&session.ready, &o.target, 1),
        (&session.receipt, &o.peer, 2),
    ] {
        if let Some(packet) = packet {
            let body = parse(packet, peer).map_err(|_| bad())?;
            if context(&body)? != ctx {
                return Err(bad());
            }
            match (kind, body) {
                (0, Body::Approval { welcome, .. }) if !welcome.is_empty() => {}
                (1, Body::Ready { approval_hash, .. })
                    if session
                        .approval
                        .as_ref()
                        .is_some_and(|a| hash(a.as_bytes()) == approval_hash) => {}
                (2, Body::Commit { ready_hash, .. })
                    if session
                        .ready
                        .as_ref()
                        .is_some_and(|r| hash(r.as_bytes()) == ready_hash) => {}
                _ => return Err(bad()),
            }
        }
    }
    for (p, who) in [
        (&session.own_close, own),
        (&session.peer_close, expected_peer(session)),
    ] {
        if let Some(p) = p {
            if !matches!(parse(p,who).map_err(|_| bad())?,Body::Close {context} if context == ctx) {
                return Err(bad());
            }
        }
    }
    use RecoveryPhase::*;
    let valid = match session.phase {
        Offered => session.target && session.candidate.is_none() && session.approval.is_none(),
        Building => !session.target && session.candidate.is_none() && session.approval.is_none(),
        Prepared => !session.target && session.candidate.is_some() && session.approval.is_some(),
        Joining => session.target && session.candidate.is_none() && session.approval.is_some(),
        Ready => session.target && session.candidate.is_some() && session.ready.is_some(),
        Committed => !session.target && session.candidate.is_some() && session.receipt.is_some(),
        Finished => session.target && session.candidate.is_some() && session.receipt.is_some(),
        Closing => session.own_close.is_some() && session.peer_close.is_none(),
        Closed => session.own_close.is_some() && session.peer_close.is_some(),
    };
    if !valid {
        return Err(bad());
    }
    if let Some(bytes) = &session.candidate {
        let device = candidate_device(bytes, own).map_err(|_| bad())?;
        let b = device.binding()?.ok_or_else(bad)?;
        let peer = expected_peer(session);
        if b.conversation != ctx
            || b.account != peer.scope.account
            || b.device != peer.scope.device
            || hex(&b.key) != peer.identity_key
        {
            return Err(bad());
        }
    }
    if session.target {
        let d = candidate_device(&session.fresh, own).map_err(|_| bad())?;
        if hex(&d.key_package()?) != o.key_package {
            return Err(bad());
        }
    }
    Ok(())
}
