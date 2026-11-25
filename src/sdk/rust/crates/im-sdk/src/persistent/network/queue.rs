//! 退休原件仍保留接受事实和连续信箱位置，解密失败终态不冒充送达。
use super::{
    super::{
        data::{Data, Saved},
        types::*,
        PersistentDevice,
    },
    ledger,
    types::Event,
};
pub(super) fn retired_context(data: &Data, context: &str) -> bool {
    context != data.state.context
        && (context == "initial" || data.transitions.iter().any(|t| t.context == context))
}
pub(super) fn process_event(
    device: &mut PersistentDevice,
    saved: &Saved,
    event: Event,
) -> Result<()> {
    match (&*event.kind, event.envelope.clone()) {
        ("message", Some(envelope)) => {
            if retired_context(&saved.data, &envelope.context) {
                let known = saved
                    .data
                    .messages
                    .iter()
                    .any(|m| m.receipt.is_some() && m.envelope == envelope);
                device.database.call(move |db| {
                    db.update(false, |s| {
                        let n = s
                            .data
                            .network
                            .as_mut()
                            .ok_or_else(|| Error::paused("network_store_invalid"))?;
                        if !known {
                            n.retired_events.insert(event.sequence.clone());
                        }
                        n.processed = event.sequence;
                        Ok(())
                    })
                })?;
            } else {
                let outcome = device.execute(
                    format!("network-receive-{}", event.sequence),
                    Action::Receive {
                        envelope: envelope.clone(),
                    },
                )?;
                if outcome.cached {
                    device.database.call(move |db| {
                        db.update(false, |s| ledger::mark_received(&mut s.data, &envelope))
                    })?;
                }
            }
        }
        ("delivered" | "unavailable", None) => {
            device.database.call(move |db| {
                db.update(false, |s| {
                    ledger::validate_ack(&s.data, &event.acceptance)?;
                    let n = s
                        .data
                        .network
                        .as_mut()
                        .ok_or_else(|| Error::paused("network_store_invalid"))?;
                    if n.accepted
                        .get(&event.acceptance.message_id)
                        .is_some_and(|a| a != &event.acceptance)
                    {
                        return Err(Error::paused("network_acceptance_conflict"));
                    }
                    n.accepted.insert(
                        event.acceptance.message_id.clone(),
                        event.acceptance.clone(),
                    );
                    if event.kind == "delivered" {
                        n.delivered.insert(event.acceptance.message_id);
                    } else {
                        n.unavailable.insert(event.acceptance.message_id);
                    }
                    n.processed = event.sequence;
                    Ok(())
                })
            })?;
        }
        _ => return Err(Error::paused("network_event_invalid")),
    }
    Ok(())
}
