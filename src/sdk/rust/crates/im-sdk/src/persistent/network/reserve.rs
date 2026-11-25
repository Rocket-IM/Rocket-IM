//! 仅投影原ID结清及已下载的连续控制原件；不下载、解密或创建请求。
use super::{
    super::{data::Saved, recovery_types::RecoveryPhase, types::*},
    types::Acceptance,
};

pub(in crate::persistent) fn install_receipt(s: &Saved) -> Result<Option<String>> {
    let Some(session) = s
        .meta
        .session
        .as_ref()
        .filter(|v| v.target && v.phase == RecoveryPhase::Ready && v.candidate.is_some())
    else {
        return Ok(None);
    };
    let Some(local) = s.data.network.as_ref().and_then(|n| n.recovery.as_ref()) else {
        return Ok(None);
    };
    let Some(round) = local.round.as_ref() else {
        return Ok(None);
    };
    if local.intent.as_ref() != Some(&round.reservation)
        || session
            .offer
            .transport
            .as_ref()
            .is_none_or(|t| t.round_id != round.reservation.id)
        || round.context.as_deref() != Some(&session.offer.context()?)
    {
        return Ok(None);
    }
    Ok(round.materials.get("commit").cloned())
}

pub(in crate::persistent) fn project_known(s: &mut Saved) -> Result<(usize, usize, usize, usize)> {
    let Some(n) = s.data.network.as_mut() else {
        return Ok((0, 0, 0, encode(&s.data)?.len()));
    };
    let mut sends = 0;
    // ACK所有字段由原件确定，唯一未知的序号仅1..256，最大表示3字节。
    // ACK分支保留StoredMessage；永久拒绝移除其重复投影且仅增加固定rejection标记。
    // 每个原件的ACK增长严格支配该拒绝分支，不能同时叠加两种互斥结果。
    for (id, record) in &s.data.requests {
        let RequestState::Complete { outcome } = &record.result else {
            continue;
        };
        let Value::Sent { envelope } = &outcome.value else {
            continue;
        };
        if record.rejection.is_some()
            || n.not_accepted.contains(&envelope.message_id)
            || n.accepted.contains_key(&envelope.message_id)
        {
            continue;
        }
        let ack = Acceptance {
            request_id: id.clone(),
            message_id: envelope.message_id.clone(),
            sequence: "256".into(),
            envelope_hash: hash(&encode(envelope)?),
        };
        // 即使只有极短正文，原消息投影也大于拒绝标记；保持生产类型校验此不变量。
        let original = s
            .data
            .messages
            .iter()
            .find(|m| m.envelope == *envelope)
            .ok_or_else(|| Error::paused("store_invalid"))?;
        let rejection =
            serde_json::json!({"rejection":{"source":"service_send","code":"message_limit"}});
        if encode(original)?.len() < encode(&rejection)?.len() {
            return Err(Error::paused("reserve_model_invalid"));
        }
        n.accepted.insert(envelope.message_id.clone(), ack);
        sends += 1;
    }
    let ack_peak = encode(&s.data)?.len();
    let n = s
        .data
        .network
        .as_mut()
        .ok_or_else(|| Error::paused("store_invalid"))?;
    let start = number(&n.processed)? as usize;
    let mut controls = 0;
    for event in n.events.iter().skip(start) {
        if event.envelope.is_some() || !matches!(event.kind.as_str(), "delivered" | "unavailable") {
            break;
        }
        n.accepted.insert(
            event.acceptance.message_id.clone(),
            event.acceptance.clone(),
        );
        if event.kind == "delivered" {
            n.delivered.insert(event.acceptance.message_id.clone());
        } else {
            n.unavailable.insert(event.acceptance.message_id.clone());
        }
        n.processed = event.sequence.clone();
        controls += 1;
    }
    let reports = (number(&n.processed)? - number(&n.reported)?) as usize;
    n.reported = n.processed.clone();
    Ok((sends, controls, reports, ack_peak))
}
