//! Service仅转交；每次落盘前由原身份核验完整材料链和单调进度。
use super::{
    super::{data::Data, recovery_types::Body, recovery_wire as wire, types::*},
    recovery_types::*,
};

pub(super) fn validate_round(data: &Data, round: &Round) -> Result<()> {
    let bad = || Error::new("network_recovery_invalid");
    let q = &round.reservation;
    let n = data.network.as_ref().ok_or_else(bad)?;
    let binding = n.binding.as_ref().ok_or_else(bad)?;
    let own = data.state.identity.as_ref().ok_or_else(bad)?;
    if q.version != "successor-alpha1"
        || id(&q.id).is_err()
        || id(&q.request).is_err()
        || unhex(&q.request_hash, 32)?.len() != 32
        || number(&q.deadline).is_err()
        || q.conversation != binding.conversation
        || !((q.target == *own && q.peer == binding.peer)
            || (q.peer == *own && q.target == binding.peer))
        || (q.old_context != data.state.context
            && round.context.as_ref() != Some(&data.state.context))
        || round.materials.len() > 8
        || encode(round)?.len() > 2 * 1024 * 1024
    {
        return Err(bad());
    }
    let m = &round.materials;
    for (key, packet) in m {
        let target = matches!(
            key.as_str(),
            "offer" | "ready" | "close_target" | "installed_target"
        );
        let body = wire::parse(packet, if target { &q.target } else { &q.peer })?;
        if key != "offer" && Some(wire::context(&body)?) != round.context {
            return Err(bad());
        }
        match (key.as_str(), body) {
            ("offer", Body::Offer { offer }) => {
                if offer.target != q.target
                    || offer.peer != q.peer
                    || offer.conversation != q.conversation
                    || offer.old_context != q.old_context
                    || offer.previous != q.previous
                    || offer.request != q.request
                    || offer.request_hash != q.request_hash
                    || offer.transport != Some(q.transport())
                    || Some(offer.context()?) != round.context
                {
                    return Err(bad());
                }
            }
            ("approval", Body::Approval { .. }) if m.contains_key("offer") => {}
            ("ready", Body::Ready { approval_hash, .. })
                if m.get("approval")
                    .is_some_and(|p| hash(p.as_bytes()) == approval_hash) => {}
            ("commit", Body::Commit { ready_hash, .. })
                if m.get("ready")
                    .is_some_and(|p| hash(p.as_bytes()) == ready_hash) => {}
            ("installed_target" | "installed_peer", Body::Installed { receipt_hash, .. })
                if m.get("commit")
                    .is_some_and(|p| hash(p.as_bytes()) == receipt_hash) => {}
            ("close_target" | "close_peer", Body::Close { .. })
                if m.contains_key("offer") && !m.contains_key("ready") => {}
            _ => return Err(bad()),
        }
    }
    let status = if m.contains_key("close_target") && m.contains_key("close_peer") {
        "closed"
    } else if m.contains_key("close_target") || m.contains_key("close_peer") {
        "closing"
    } else if m.contains_key("installed_target") && m.contains_key("installed_peer") {
        "complete"
    } else if m.contains_key("commit") {
        "committed"
    } else if m.contains_key("ready") {
        "ready"
    } else if m.contains_key("approval") {
        "approved"
    } else if m.contains_key("offer") {
        "offered"
    } else {
        "reserved"
    };
    if status != round.status || (m.contains_key("offer") != round.context.is_some()) {
        return Err(bad());
    }
    Ok(())
}
pub(super) fn validate_progress(data: &Data, next: &Round) -> Result<()> {
    validate_round(data, next)?;
    if let Some(old) = data
        .network
        .as_ref()
        .and_then(|n| n.recovery.as_ref())
        .and_then(|r| r.round.as_ref())
    {
        if old.reservation.id == next.reservation.id {
            if old.reservation != next.reservation
                || old
                    .materials
                    .iter()
                    .any(|(k, v)| next.materials.get(k) != Some(v))
            {
                return Err(Error::paused("network_recovery_conflict"));
            }
        } else if !matches!(old.status.as_str(), "complete" | "closed")
            || next.reservation.previous != old.context
        {
            return Err(Error::paused("network_recovery_conflict"));
        }
    }
    Ok(())
}
