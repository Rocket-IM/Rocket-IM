//! 接收记录的有界读取；仅使用调用方传入的显式事务。
use super::{corrupt, parsed, valid_hash, Inbox, InboxSummary, Receipt, Result, LIMIT};
use crate::model::{valid_id, Error};
use rusqlite::Transaction;

pub(super) fn inbox(tx: &Transaction<'_>) -> Result<Vec<Inbox>> {
    let oversized: i64 = tx.query_row("SELECT count(*) FROM crypto_inbox WHERE length(envelope_json)>262144 OR length(plaintext_json)>32768", [], |r| r.get(0)).map_err(Error::database)?;
    if oversized != 0 {
        return Err(corrupt());
    }
    let mut statement = tx.prepare("SELECT message_key,first_sequence,message_id,sender_account,sender_device,envelope_hash,ciphertext_hash,text_hash,envelope_json,plaintext_json FROM crypto_inbox ORDER BY message_key LIMIT 129").map_err(Error::database)?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                InboxSummary {
                    message_key: r.get(0)?,
                    first_sequence: r.get(1)?,
                    message_id: r.get(2)?,
                    sender_account: r.get(3)?,
                    sender_device: r.get(4)?,
                    ciphertext_hash: r.get(6)?,
                    text_hash: r.get(7)?,
                },
                r.get::<_, String>(5)?,
                r.get::<_, String>(8)?,
                r.get::<_, String>(9)?,
            ))
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    if rows.len() > LIMIT {
        return Err(corrupt());
    }
    rows.into_iter()
        .map(|(summary, envelope_hash, envelope_json, plaintext_json)| {
            if ![
                &summary.message_id,
                &summary.sender_account,
                &summary.sender_device,
            ]
            .into_iter()
            .all(|v| valid_id(v))
                || ![
                    &summary.message_key,
                    &summary.ciphertext_hash,
                    &summary.text_hash,
                    &envelope_hash,
                ]
                .into_iter()
                .all(|v| valid_hash(v))
            {
                return Err(corrupt());
            }
            Ok(Inbox {
                summary,
                envelope_hash,
                envelope: parsed(&envelope_json)?,
                message: parsed(&plaintext_json)?,
            })
        })
        .collect()
}

pub(super) fn receipts(tx: &Transaction<'_>) -> Result<Vec<Receipt>> {
    let mut statement = tx.prepare("SELECT sequence,message_key,request_id,input_hash FROM crypto_receipts ORDER BY length(sequence),sequence LIMIT 129").map_err(Error::database)?;
    let rows = statement
        .query_map([], |r| {
            Ok(Receipt {
                sequence: r.get(0)?,
                message_key: r.get(1)?,
                request_id: r.get(2)?,
                input_hash: r.get(3)?,
            })
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    if rows.len() > LIMIT {
        return Err(corrupt());
    }
    for row in &rows {
        if !valid_id(&row.request_id)
            || !valid_hash(&row.message_key)
            || !valid_hash(&row.input_hash)
        {
            return Err(corrupt());
        }
    }
    Ok(rows)
}
