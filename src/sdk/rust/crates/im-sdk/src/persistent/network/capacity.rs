//! 网络所有者只提供计数、游标和授权阶段，不返回信箱或恢复材料。
use super::super::{capacity_types::CapacityCursors, data::Saved, metering::*, types::*};
pub(in crate::persistent) struct Observation {
    pub events: usize,
    pub cursors: Option<CapacityCursors>,
    pub phase: Option<String>,
    pub authorized: bool,
    pub process_blockers: Vec<(&'static str, &'static str)>,
}
pub(in crate::persistent) fn capacity(
    saved: &Saved,
    encoded: &EncodedSaved,
) -> Result<Observation> {
    let network = saved.data.network.as_ref();
    Ok(Observation {
        process_blockers: process_blockers(saved, encoded)?,
        events: network.map_or(0, |n| n.events.len()),
        cursors: network.map(|n| CapacityCursors {
            downloaded: n.events.len().to_string(),
            processed: n.processed.clone(),
            reported: n.reported.clone(),
        }),
        phase: super::recovery_types::projection(saved)?.map(|v| v.phase),
        authorized: network.and_then(|n| n.recovery.as_ref()).is_some_and(|r| {
            r.intent.is_some() || matches!(r.decision.as_deref(), Some("approve" | "seal"))
        }),
    })
}

fn process_blockers(
    saved: &Saved,
    encoded: &EncodedSaved,
) -> Result<Vec<(&'static str, &'static str)>> {
    let mut out = vec![];
    let Some(n) = saved.data.network.as_ref() else {
        return Ok(out);
    };
    let Some(event) = n.events.get(number(&n.processed)? as usize) else {
        return Ok(out);
    };
    let Some(envelope) = event.envelope.as_ref().filter(|e| {
        event.kind == "message" && !super::queue::retired_context(&saved.data, &e.context)
    }) else {
        return Ok(out);
    };
    // 原请求终态和同一已接收密文的缓存路径不能被普通消息槽上限误伤。
    if saved
        .data
        .requests
        .contains_key(&format!("network-receive-{}", event.sequence))
    {
        return Ok(out);
    }
    if saved.data.requests.len() >= MAX_REQUESTS {
        out.push(("request_limit", "requests"));
    }
    let delta = growth(&Action::Receive {
        envelope: envelope.clone(),
    })?;
    if encoded.data_preflight_exceeded(delta) {
        out.push(("data_preflight_limit", "data_bytes"));
    }
    if encoded.meta_preflight_exceeded(delta) {
        out.push(("meta_preflight_limit", "meta_bytes"));
    }
    if saved.data.messages.len() >= MAX_MESSAGES
        && !saved.data.messages.iter().any(|m| &m.envelope == envelope)
    {
        out.push(("message_limit", "ordinary_messages"));
    }
    Ok(out)
}
