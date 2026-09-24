//! 接收候选校验与 inbox/receipt 写入，复用最终提交事务。
use crate::{
    crypto::{
        contract::{Action, Candidate, ReceiveValue, Request, Reservation},
        model,
        query::{self, Meta},
        schema::corrupt,
    },
    model::{revision, Error, Result},
};
use rusqlite::{params, Transaction};

pub(super) fn validate(meta: &Meta, request: &Request, candidate: &Candidate) -> Result<bool> {
    let Action::Receive { sequence, envelope } = &request.action else {
        return Err(corrupt());
    };
    let value: ReceiveValue = query::parsed(&query::serialized(&candidate.outcome.value)?)?;
    let duplicate = query::receive::duplicate(meta, sequence, envelope)?;
    let expected_count = revision(&meta.decryptions)?
        .checked_add(u64::from(duplicate.is_none()))
        .ok_or_else(corrupt)?;
    let next_sequence = revision(&meta.processed_cursor)?
        .checked_add(1)
        .ok_or_else(corrupt)?;
    if candidate.processed_cursor != *sequence
        || sequence != &next_sequence.to_string()
        || candidate.decryptions != expected_count.to_string()
        || candidate.conversation != meta.conversation
        || meta.conversation.is_none()
        || meta.identity.as_ref() != Some(&candidate.identity)
        || value.sequence != *sequence
        || value.duplicate != duplicate.is_some()
        || value.message.message_id != envelope.message_id
        || value.message.sender_account != envelope.sender_account
        || model::text(&value.message.text).is_err()
    {
        return Err(corrupt());
    }
    if let Some(old) = duplicate {
        if query::serialized(&value)? != query::serialized(&old)? {
            return Err(corrupt());
        }
    }
    Ok(value.duplicate)
}

pub(super) fn save(
    tx: &Transaction<'_>,
    request: &Request,
    reservation: &Reservation,
    candidate: &Candidate,
) -> Result<()> {
    let Action::Receive { sequence, envelope } = &request.action else {
        return Err(corrupt());
    };
    let value: ReceiveValue = query::parsed(&query::serialized(&candidate.outcome.value)?)?;
    let key = query::receive::message_key(envelope)?;
    if !value.duplicate {
        tx.execute("INSERT INTO crypto_inbox(message_key,first_sequence,message_id,sender_account,sender_device,envelope_hash,ciphertext_hash,text_hash,envelope_json,plaintext_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![key,sequence,envelope.message_id,envelope.sender_account,envelope.sender_device,query::receive::envelope_hash(envelope)?,model::hash(&model::decode(&envelope.ciphertext)?),model::hash(value.message.text.as_bytes()),query::serialized(envelope)?,query::serialized(&value.message)?]).map_err(Error::database)?;
    }
    tx.execute("INSERT INTO crypto_receipts(sequence,message_key,request_id,input_hash) VALUES(?1,?2,?3,?4)",params![sequence,key,request.request_id,reservation.input_hash]).map_err(Error::database)?;
    Ok(())
}
