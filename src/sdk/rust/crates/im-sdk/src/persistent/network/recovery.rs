//! 网络owner每次只推进一个持久密码步骤；重传始终使用已保存签名原件。
use super::{
    super::{
        data::Saved,
        recovery_types::{Body, RecoveryCommand, RecoveryPhase, Session},
        recovery_wire as wire,
        types::*,
        PersistentDevice,
    },
    recovery_commands::save,
    recovery_types::*,
    recovery_validation::validate_progress,
    session::NetworkSession,
};
use serde_json::json;

impl NetworkSession {
    pub(super) fn recovery_step(&mut self, device: &mut PersistentDevice) -> Result<bool> {
        let saved = device.database.call(|db| db.read(Ok))?;
        let mut local = saved
            .data
            .network
            .as_ref()
            .and_then(|n| n.recovery.clone())
            .unwrap_or_default();
        if let Some(intent) = local.intent.clone().filter(|q| {
            local
                .round
                .as_ref()
                .is_none_or(|r| r.reservation.id != q.id)
        }) {
            let reply: Result<Round> = self.rpc("recovery_reserve", &intent);
            match reply {
                Ok(round) => {
                    record(device, &saved, &mut local, round)?;
                    return Ok(true);
                }
                Err(e) if e.code == "recovery_active" => {
                    // 在取得唯一预约前不生成Offer；竞争败者仍保留原未知请求，需另行批准胜出轮。
                    let round: Option<Round> = self.rpc("recovery_query", json!({"id":null}))?;
                    local.intent = None;
                    record(
                        device,
                        &saved,
                        &mut local,
                        round.ok_or_else(|| Error::new("network_recovery_invalid"))?,
                    )?;
                    return Ok(true);
                }
                Err(e) if e.code == "recovery_deadline" => {
                    // Service先查同ID幂等记录，再检查新预约期限：此错误证明没有预约成功。
                    // 尚未生成密码候选的授权可结束；原未知请求和历史保留，重新Begin须明确授权。
                    if saved.meta.session.as_ref().is_some_and(|s| {
                        s.offer
                            .transport
                            .as_ref()
                            .is_some_and(|t| t.round_id == intent.id)
                    }) {
                        return Err(Error::paused("network_recovery_conflict"));
                    }
                    local.intent = None;
                    save(device, local)?;
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
        let query_id = local
            .round
            .as_ref()
            .filter(|r| !matches!(r.status.as_str(), "complete" | "closed"))
            .map(|r| r.reservation.id.clone());
        let round: Option<Round> = self.rpc("recovery_query", json!({"id":query_id}))?;
        let Some(round) = round else {
            if local.round.is_some() {
                return Err(Error::paused("network_recovery_missing"));
            }
            return Ok(false);
        };
        if local.round.as_ref() != Some(&round) {
            record(device, &saved, &mut local, round)?;
            return Ok(true);
        }
        let own = saved
            .data
            .state
            .identity
            .as_ref()
            .ok_or_else(|| Error::new("initialize_required"))?;
        let target = &round.reservation.target == own;
        let session = saved.meta.session.as_ref().filter(|s| {
            s.offer
                .transport
                .as_ref()
                .is_some_and(|t| t.round_id == round.reservation.id)
        });
        if let Some(s) = session {
            if let Some((kind, packet)) = outgoing(&saved, s, &round)? {
                let reply: Round = self.rpc(
                    "recovery_publish",
                    json!({"id":round.reservation.id,"kind":kind,"packet":packet}),
                )?;
                super::super::checkpoint("network_recovery_after_publish");
                record(device, &saved, &mut local, reply)?;
                return Ok(true);
            }
        }
        let command = next_command(&saved, &local, &round, session, target)?;
        if let Some(command) = command {
            // 所有密码/候选操作复用原协议；Building/Joining无候选不会再调用Accept/Join。
            device.recovery_internal(command)?;
            return Ok(true);
        }
        if round.status == "complete" && round.context.as_ref() == Some(&saved.data.state.context) {
            return Ok(false);
        }
        // 尚未批准的对端可继续原上下文正常同步；未知执行方仍由原pending门禁阻挡。
        Ok(session.is_some() || local.intent.is_some() || local.decision.is_some())
    }
}
fn record(
    device: &PersistentDevice,
    saved: &Saved,
    local: &mut RecoveryData,
    round: Round,
) -> Result<()> {
    validate_progress(&saved.data, &round)?;
    let same = saved.meta.session.as_ref().is_some_and(|s| {
        s.offer
            .transport
            .as_ref()
            .is_some_and(|t| t.round_id == round.reservation.id)
    });
    if !same {
        let previous = saved
            .meta
            .session
            .as_ref()
            .map(|s| s.offer.context())
            .transpose()?;
        if previous != round.reservation.previous {
            return Err(Error::new("recovery_predecessor_mismatch"));
        }
    }
    if local
        .round
        .as_ref()
        .is_some_and(|r| r.reservation.id != round.reservation.id)
    {
        local.decision = None;
    }
    if Some(&round.reservation.peer) == saved.data.state.identity.as_ref() {
        local.intent = None;
    }
    if Some(&round.reservation.target) == saved.data.state.identity.as_ref()
        && local.intent.as_ref() != Some(&round.reservation)
    {
        return Err(Error::new("recovery_authorization_missing"));
    }
    let known_commit = round.materials.contains_key("commit")
        && saved
            .meta
            .session
            .as_ref()
            .is_some_and(|s| s.target && s.phase == RecoveryPhase::Ready);
    local.round = Some(round);
    save(device, local.clone())?;
    if known_commit {
        super::super::checkpoint("network_recovery_after_known_commit");
    }
    Ok(())
}
fn outgoing(saved: &Saved, s: &Session, round: &Round) -> Result<Option<(&'static str, String)>> {
    let target = s.target;
    let own_close = if target { "close_target" } else { "close_peer" };
    let m = &round.materials;
    if let Some(packet) = s.own_close.as_ref().filter(|_| !m.contains_key(own_close)) {
        return Ok(Some((own_close, packet.clone())));
    }
    if matches!(s.phase, RecoveryPhase::Closing | RecoveryPhase::Closed) {
        return Ok(None);
    }
    let packets = if target {
        vec![
            ("offer", Some(&s.offer_packet)),
            ("ready", s.ready.as_ref()),
        ]
    } else {
        vec![
            ("approval", s.approval.as_ref()),
            ("commit", s.receipt.as_ref()),
        ]
    };
    for (kind, packet) in packets {
        if let Some(packet) = packet {
            if !m.contains_key(kind) {
                return Ok(Some((kind, packet.clone())));
            }
            if m.get(kind) != Some(packet) {
                return Err(Error::new("recovery_material_conflict"));
            }
        }
    }
    if matches!(s.phase, RecoveryPhase::Committed | RecoveryPhase::Finished) {
        let kind = if target {
            "installed_target"
        } else {
            "installed_peer"
        };
        if !m.contains_key(kind) {
            let receipt = s
                .receipt
                .as_ref()
                .ok_or_else(|| Error::new("recovery_candidate_missing"))?;
            return Ok(Some((
                kind,
                wire::sign(
                    saved,
                    Body::Installed {
                        context: s.offer.context()?,
                        receipt_hash: hash(receipt.as_bytes()),
                    },
                )?,
            )));
        }
    }
    Ok(None)
}
fn next_command(
    saved: &Saved,
    local: &RecoveryData,
    round: &Round,
    s: Option<&Session>,
    target: bool,
) -> Result<Option<RecoveryCommand>> {
    let m = &round.materials;
    let Some(s) = s else {
        if target {
            let q = local
                .intent
                .as_ref()
                .ok_or_else(|| Error::new("recovery_authorization_missing"))?;
            let action = saved
                .data
                .requests
                .get(&q.request)
                .and_then(|r| r.input.clone())
                .ok_or_else(|| Error::new("pending_input_required"))?;
            return Ok(Some(RecoveryCommand::Begin {
                request_id: q.request.clone(),
                action,
            }));
        }
        let Some(offer) = m.get("offer") else {
            return Ok(None);
        };
        return Ok(match local.decision.as_deref() {
            Some("approve") => Some(RecoveryCommand::Accept {
                offer: offer.clone(),
                peer: round.reservation.target.clone(),
            }),
            Some("reject") => Some(RecoveryCommand::Reject {
                offer: offer.clone(),
                peer: round.reservation.target.clone(),
            }),
            _ => None,
        });
    };
    if !matches!(
        s.phase,
        RecoveryPhase::Closed
            | RecoveryPhase::Ready
            | RecoveryPhase::Committed
            | RecoveryPhase::Finished
    ) {
        if let Some(packet) = m.get(if target { "close_peer" } else { "close_target" }) {
            return Ok(Some(RecoveryCommand::Close {
                peer_close: Some(packet.clone()),
            }));
        }
        if local.decision.as_deref() == Some("seal") && s.phase != RecoveryPhase::Closing {
            return Ok(Some(RecoveryCommand::Close { peer_close: None }));
        }
    }
    Ok(match s.phase {
        RecoveryPhase::Offered => m.get("approval").map(|p| RecoveryCommand::Join {
            approval: p.clone(),
        }),
        RecoveryPhase::Prepared => m
            .get("ready")
            .map(|p| RecoveryCommand::Confirm { ready: p.clone() }),
        RecoveryPhase::Ready => m
            .get("commit")
            .map(|p| RecoveryCommand::Finish { receipt: p.clone() }),
        _ => None,
    })
}
