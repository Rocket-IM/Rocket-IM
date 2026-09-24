//! 预约确认后才计算候选；重复投递复用已提交消息，不实例化密码引擎。
use super::{
    contract::{Action, Candidate, Outcome, Prepared, ReceiveValue, Request, Reservation, Scope},
    engine::Engine,
    Metrics,
};
use crate::model::{revision, Error, Result};
use serde_json::{json, Value};

pub(super) fn compute(
    scope: &Scope,
    request: &Request,
    prepared: Prepared,
    metrics: &mut Metrics,
) -> Result<(Reservation, Candidate)> {
    let duplicate = prepared.duplicate.is_some();
    let (provider, identity, conversation, value) = if let Some(saved) = prepared.duplicate {
        (
            prepared.provider.ok_or_else(super::model::corrupt)?,
            prepared.identity.ok_or_else(super::model::corrupt)?,
            prepared.conversation,
            encoded(saved)?,
        )
    } else {
        let had_provider = prepared.provider.is_some();
        let mut engine = match prepared.provider {
            Some(bytes) => {
                metrics.provider_restores += 1;
                Engine::restore(&bytes, scope)?
            }
            None => {
                metrics.provider_news += 1;
                Engine::new(scope)?
            }
        };
        if had_provider
            && (Some(engine.identity()) != prepared.identity
                || engine.conversation() != prepared.conversation)
        {
            return Err(super::model::corrupt());
        }
        let value = match &request.action {
            Action::Initialize {} => encoded(engine.identity())?,
            Action::CreateGroup { conversation, peer } => {
                json!({"welcome":engine.create_group(conversation,peer)?})
            }
            Action::RebuildAdd { plan, peer } => engine.add_rebuild_member(peer, plan)?,
            Action::Send {
                message_id, text, ..
            } => {
                metrics.candidate_sends += 1;
                encoded(engine.send(message_id, text)?)?
            }
            Action::Receive { sequence, envelope } => {
                metrics.candidate_receives += 1;
                encoded(ReceiveValue {
                    sequence: sequence.clone(),
                    duplicate: false,
                    message: engine.receive(envelope)?,
                })?
            }
        };
        (
            engine.export()?,
            engine.identity(),
            engine.conversation(),
            value,
        )
    };
    let next_revision = increment(&prepared.reservation.base_revision, true)?;
    let encryptions = increment(
        &prepared.encryptions,
        matches!(request.action, Action::Send { .. }),
    )?;
    let decryptions = increment(
        &prepared.decryptions,
        matches!(request.action, Action::Receive { .. }) && !duplicate,
    )?;
    let processed_cursor = match &request.action {
        Action::Receive { sequence, .. } => sequence.clone(),
        _ => prepared.processed_cursor,
    };
    Ok((
        prepared.reservation,
        Candidate {
            provider,
            identity,
            conversation,
            encryptions,
            processed_cursor,
            decryptions,
            outcome: Outcome {
                revision: next_revision,
                kind: request.action.operation().into(),
                cached: false,
                value,
            },
        },
    ))
}

fn increment(value: &str, advance: bool) -> Result<String> {
    revision(value)?
        .checked_add(u64::from(advance))
        .map(|value| value.to_string())
        .ok_or_else(|| Error::new("crypto_limit", true))
}
fn encoded(value: impl serde::Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| Error::new("encoding_failed", true))
}
