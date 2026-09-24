//! 原始下载记录的有界读取与关系校验；仅使用调用方显式事务，不读取 provider。
use super::{
    corrupt, model, parsed, receive, revision, DownloadSummary, Downloaded, Envelope, Meta, Result,
    Scope, LIMIT,
};
use crate::{crypto::contract::Action, model::Error};
use rusqlite::Transaction;

pub(in crate::crypto) fn load(tx: &Transaction<'_>) -> Result<Vec<Downloaded>> {
    let oversized: i64 = tx
        .query_row(
            "SELECT count(*) FROM crypto_downloads WHERE length(envelope_json)>262144",
            [],
            |r| r.get(0),
        )
        .map_err(Error::database)?;
    if oversized != 0 {
        return Err(corrupt());
    }
    let mut statement = tx.prepare("SELECT sequence,envelope_hash,ciphertext_hash,envelope_json FROM crypto_downloads ORDER BY length(sequence),sequence LIMIT 129").map_err(Error::database)?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                DownloadSummary {
                    sequence: r.get(0)?,
                    envelope_hash: r.get(1)?,
                    ciphertext_hash: r.get(2)?,
                },
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    if rows.len() > LIMIT {
        return Err(corrupt());
    }
    rows.into_iter()
        .map(|(summary, envelope)| {
            Ok(Downloaded {
                summary,
                envelope: parsed(&envelope)?,
            })
        })
        .collect()
}

pub(in crate::crypto) fn validate(meta: &Meta, scope: &Scope) -> Result<()> {
    let downloaded = revision(&meta.download_cursor).map_err(|_| corrupt())?;
    let processed = revision(&meta.processed_cursor).map_err(|_| corrupt())?;
    if downloaded != meta.downloads.len() as u64
        || processed > downloaded
        || (meta.conversation.is_none() && downloaded != 0)
    {
        return Err(corrupt());
    }
    for (index, record) in meta.downloads.iter().enumerate() {
        let summary = &record.summary;
        let envelope = &record.envelope;
        if summary.sequence != (index + 1).to_string()
            || envelope.service != scope.service
            || Some(&envelope.conversation) != meta.conversation.as_ref()
            || summary.envelope_hash != receive::envelope_hash(envelope)?
            || summary.ciphertext_hash
                != model::hash(&model::decode(&envelope.ciphertext).map_err(|_| corrupt())?)
        {
            return Err(corrupt());
        }
        Action::Receive {
            sequence: summary.sequence.clone(),
            envelope: envelope.clone(),
        }
        .validate()
        .map_err(|_| corrupt())?;
    }
    Ok(())
}

/// 接收兼容入口只能匹配已保存原文，或补入紧邻下载游标的下一条记录。
pub(in crate::crypto) fn check_receive(
    meta: &Meta,
    sequence: &str,
    envelope: &Envelope,
) -> Result<()> {
    if let Some(old) = meta
        .downloads
        .iter()
        .find(|v| v.summary.sequence == sequence)
    {
        if old.envelope != *envelope {
            return Err(Error::new("receive_sequence_conflict", false));
        }
        return Ok(());
    }
    let next = revision(&meta.download_cursor)?
        .checked_add(1)
        .ok_or_else(corrupt)?;
    if revision(sequence)? != next {
        return Err(Error::new("receive_gap", false));
    }
    if meta.downloads.len() >= LIMIT {
        return Err(Error::new("crypto_limit", false));
    }
    Ok(())
}
