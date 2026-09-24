//! 接收游标、消息去重、结果与摘要的交叉核验，不实例化密码引擎。
use super::{
    corrupt, model, parsed, revision, serialized, Envelope, Meta, Outcome, ReceiveValue, Result,
    Scope, LIMIT,
};
use crate::{
    crypto::contract::Action,
    model::{valid_id, Error},
};

pub(in crate::crypto) fn message_key(envelope: &Envelope) -> Result<String> {
    Ok(model::hash(
        serialized(&[
            &envelope.service,
            &envelope.conversation,
            &envelope.sender_account,
            &envelope.sender_device,
            &envelope.message_id,
        ])?
        .as_bytes(),
    ))
}
pub(in crate::crypto) fn envelope_hash(envelope: &Envelope) -> Result<String> {
    Ok(model::hash(serialized(envelope)?.as_bytes()))
}
fn action_hash(sequence: &str, envelope: &Envelope) -> Result<String> {
    Ok(model::hash(
        serialized(&Action::Receive {
            sequence: sequence.into(),
            envelope: envelope.clone(),
        })?
        .as_bytes(),
    ))
}

pub(in crate::crypto) fn value(meta: &Meta, sequence: &str) -> Result<Option<ReceiveValue>> {
    let Some(receipt) = meta.receipts.iter().find(|r| r.sequence == sequence) else {
        return Ok(None);
    };
    let result = meta
        .results
        .iter()
        .find(|r| r.request_id == receipt.request_id)
        .ok_or_else(corrupt)?;
    parsed(&serialized(&result.outcome.value)?).map(Some)
}

pub(in crate::crypto) fn validate(meta: &Meta, scope: &Scope) -> Result<()> {
    let cursor = revision(&meta.processed_cursor).map_err(|_| corrupt())?;
    let decryptions = revision(&meta.decryptions).map_err(|_| corrupt())?;
    if cursor != meta.receipts.len() as u64 || decryptions != meta.inbox.len() as u64 {
        return Err(corrupt());
    }
    if meta.conversation.is_none() && (cursor != 0 || decryptions != 0) {
        return Err(corrupt());
    }
    let mut previous_revision = 0;
    for (index, receipt) in meta.receipts.iter().enumerate() {
        if receipt.sequence != (index + 1).to_string() {
            return Err(corrupt());
        }
        let inbox = meta
            .inbox
            .iter()
            .find(|v| v.summary.message_key == receipt.message_key)
            .ok_or_else(corrupt)?;
        let downloaded = meta
            .downloads
            .iter()
            .find(|entry| entry.summary.sequence == receipt.sequence)
            .ok_or_else(corrupt)?;
        if downloaded.envelope != inbox.envelope {
            return Err(corrupt());
        }
        let result = meta
            .results
            .iter()
            .find(|v| v.request_id == receipt.request_id)
            .ok_or_else(corrupt)?;
        let received: ReceiveValue = parsed(&serialized(&result.outcome.value)?)?;
        let current_revision = revision(&result.outcome.revision).map_err(|_| corrupt())?;
        let first = revision(&inbox.summary.first_sequence).map_err(|_| corrupt())?;
        if current_revision <= previous_revision
            || first == 0
            || first > index as u64 + 1
            || result.outcome.kind != "receive"
            || result.input_hash != receipt.input_hash
            || receipt.input_hash != action_hash(&receipt.sequence, &inbox.envelope)?
            || received.sequence != receipt.sequence
            || received.duplicate != (inbox.summary.first_sequence != receipt.sequence)
            || received.message != inbox.message
        {
            return Err(corrupt());
        }
        previous_revision = current_revision;
    }
    for inbox in &meta.inbox {
        let e = &inbox.envelope;
        let summary = &inbox.summary;
        if ![
            &e.service,
            &e.conversation,
            &e.sender_account,
            &e.sender_device,
            &e.message_id,
        ]
        .into_iter()
        .all(|v| valid_id(v))
            || e.service != scope.service
            || Some(&e.conversation) != meta.conversation.as_ref()
            || e.message_id != summary.message_id
            || e.sender_account != summary.sender_account
            || e.sender_device != summary.sender_device
            || inbox.message.message_id != summary.message_id
            || inbox.message.sender_account != summary.sender_account
            || model::text(&inbox.message.text).is_err()
            || summary.message_key != message_key(e)?
            || inbox.envelope_hash != envelope_hash(e)?
            || summary.ciphertext_hash
                != model::hash(&model::decode(&e.ciphertext).map_err(|_| corrupt())?)
            || summary.text_hash != model::hash(inbox.message.text.as_bytes())
            || !meta.receipts.iter().any(|r| {
                r.message_key == summary.message_key && r.sequence == summary.first_sequence
            })
        {
            return Err(corrupt());
        }
    }
    Ok(())
}

/// 调用方须先检查持久 pending；缓存与去重均不得绕过该门。
pub(in crate::crypto) fn cached(
    meta: &Meta,
    scope: &Scope,
    sequence: &str,
    envelope: &Envelope,
    input_hash: &str,
) -> Result<Option<Outcome>> {
    if meta.conversation.is_none() {
        return Err(Error::new("crypto_no_group", false));
    }
    if envelope.service != scope.service {
        return Err(Error::new("crypto_scope_mismatch", false));
    }
    if Some(&envelope.conversation) != meta.conversation.as_ref() {
        return Err(Error::new("crypto_scope_mismatch", false));
    }
    if let Some(receipt) = meta.receipts.iter().find(|r| r.sequence == sequence) {
        if receipt.input_hash != input_hash {
            return Err(Error::new("receive_sequence_conflict", false));
        }
        let result = meta
            .results
            .iter()
            .find(|r| r.request_id == receipt.request_id)
            .ok_or_else(corrupt)?;
        let mut outcome = result.outcome.clone();
        outcome.cached = true;
        return Ok(Some(outcome));
    }
    super::download::check_receive(meta, sequence, envelope)?;
    let next = revision(&meta.processed_cursor)?
        .checked_add(1)
        .ok_or_else(corrupt)?;
    let incoming = revision(sequence)?;
    if incoming != next {
        return Err(Error::new(
            if incoming > next {
                "receive_gap"
            } else {
                "receive_sequence_conflict"
            },
            false,
        ));
    }
    let key = message_key(envelope)?;
    if let Some(old) = meta.inbox.iter().find(|v| v.summary.message_key == key) {
        if old.envelope_hash != envelope_hash(envelope)? {
            return Err(Error::new("receive_message_conflict", false));
        }
    } else if meta.inbox.len() >= LIMIT {
        return Err(Error::new("crypto_limit", false));
    }
    if meta.receipts.len() >= LIMIT {
        return Err(Error::new("crypto_limit", false));
    }
    Ok(None)
}

pub(in crate::crypto) fn duplicate(
    meta: &Meta,
    sequence: &str,
    envelope: &Envelope,
) -> Result<Option<ReceiveValue>> {
    let key = message_key(envelope)?;
    meta.inbox
        .iter()
        .find(|v| v.summary.message_key == key)
        .map(|old| {
            if old.envelope_hash != envelope_hash(envelope)? {
                return Err(corrupt());
            }
            Ok(ReceiveValue {
                sequence: sequence.into(),
                duplicate: true,
                message: old.message.clone(),
            })
        })
        .transpose()
}
