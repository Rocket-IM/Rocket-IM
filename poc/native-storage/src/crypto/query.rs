//! 所有查询借用显式事务；公开元数据预检不读取 provider BLOB。
#[path = "download_query.rs"]
pub(super) mod download;
#[path = "receive_relations.rs"]
pub(super) mod receive;
#[path = "receive_query.rs"]
mod receive_query;
#[path = "query_relations.rs"]
mod relations;
use rusqlite::Transaction;
use serde::{de::DeserializeOwned, Serialize};

use super::{
    contract::{
        DownloadSummary, InboxSummary, Inspect, OutboxSummary, Outcome, ReceiveValue, Reservation,
        Scope,
    },
    model::{self, Envelope, Identity, PlainMessage},
    schema::{self, corrupt},
};
use crate::model::{revision, valid_id, Error, Result};

pub(super) const LIMIT: usize = 128;
pub(super) const PROVIDER_LIMIT: usize = 2 * 1024 * 1024;
pub(super) struct StoredResult {
    pub request_id: String,
    pub input_hash: String,
    pub outcome: Outcome,
}
pub(super) struct Outbound {
    pub attempt_id: String,
    pub message_id: String,
    pub request_id: String,
    pub input_hash: String,
    pub envelope: Envelope,
}
pub(super) struct Inbox {
    pub summary: InboxSummary,
    pub envelope_hash: String,
    pub envelope: Envelope,
    pub message: PlainMessage,
}
pub(super) struct Receipt {
    pub sequence: String,
    pub message_key: String,
    pub request_id: String,
    pub input_hash: String,
}
pub(super) struct Downloaded {
    pub summary: DownloadSummary,
    pub envelope: Envelope,
}
pub(super) struct Meta {
    pub revision: String,
    pub identity: Option<Identity>,
    pub conversation: Option<String>,
    pub provider_hash: String,
    pub provider_bytes: usize,
    pub encryptions: String,
    pub results: Vec<StoredResult>,
    pub outbox: Vec<Outbound>,
    pub processed_cursor: String,
    pub decryptions: String,
    pub inbox: Vec<Inbox>,
    pub receipts: Vec<Receipt>,
    pub download_cursor: String,
    pub downloads: Vec<Downloaded>,
}

pub(super) fn serialized<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| corrupt())
}
pub(super) fn parsed<T: DeserializeOwned + Serialize>(text: &str) -> Result<T> {
    if text.len() > 256 * 1024 {
        return Err(corrupt());
    }
    let value: T = serde_json::from_str(text).map_err(|_| corrupt())?;
    let raw: serde_json::Value = serde_json::from_str(text).map_err(|_| corrupt())?;
    if serde_json::to_value(&value).map_err(|_| corrupt())? != raw {
        return Err(corrupt());
    }
    Ok(value)
}
pub(super) fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn pending(tx: &Transaction<'_>) -> Result<Option<Reservation>> {
    let mut s=tx.prepare("SELECT singleton,request_id,operation,input_hash,base_revision,base_provider_hash FROM crypto_pending LIMIT 2").map_err(Error::database)?;
    let values = s
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                Reservation {
                    request_id: r.get(1)?,
                    operation: r.get(2)?,
                    input_hash: r.get(3)?,
                    base_revision: r.get(4)?,
                    base_provider_hash: r.get(5)?,
                },
            ))
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    if values.len() > 1 {
        return Err(corrupt());
    }
    if let Some((id, value)) = values.into_iter().next() {
        if id != 1
            || !valid_id(&value.request_id)
            || !matches!(
                value.operation.as_str(),
                "initialize" | "create_group" | "send" | "receive" | "rebuild_add"
            )
            || !valid_hash(&value.input_hash)
            || (!value.base_provider_hash.is_empty() && !valid_hash(&value.base_provider_hash))
        {
            return Err(corrupt());
        }
        revision(&value.base_revision).map_err(|_| corrupt())?;
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

pub(super) fn load(tx: &Transaction<'_>, scope: &Scope) -> Result<Meta> {
    schema::validate(tx)?;
    let count: i64 = tx
        .query_row("SELECT count(*) FROM crypto_meta", [], |r| r.get(0))
        .map_err(Error::database)?;
    if count != 1 {
        return Err(corrupt());
    }
    let oversized:i64=tx.query_row("SELECT count(*) FROM crypto_meta WHERE length(identity_json)>131072 OR length(provider)>2097152",[],|r|r.get(0)).map_err(Error::database)?;
    if oversized != 0 {
        return Err(corrupt());
    }
    let (format,stored_scope,identity,provider_len,mut meta)=tx.query_row("SELECT format,service,account,device,identity_json,length(provider),revision,conversation,provider_hash,encryptions,processed_cursor,decryptions,download_cursor FROM crypto_meta WHERE singleton=1",[],|r|Ok((
        r.get::<_,String>(0)?,Scope{service:r.get(1)?,account:r.get(2)?,device:r.get(3)?},r.get::<_,Option<String>>(4)?,r.get::<_,Option<i64>>(5)?,
        Meta{revision:r.get(6)?,identity:None,conversation:r.get(7)?,provider_hash:r.get(8)?,provider_bytes:0,encryptions:r.get(9)?,processed_cursor:r.get(10)?,decryptions:r.get(11)?,results:vec![],outbox:vec![],inbox:vec![],receipts:vec![],download_cursor:r.get(12)?,downloads:vec![]}
    ))).map_err(Error::database)?;
    let expected_format = match schema::version(tx)? {
        5 => schema::REBUILD_FORMAT,
        4 => schema::ANCHOR_FORMAT,
        _ => schema::FORMAT,
    };
    if format != expected_format || &stored_scope != scope {
        return Err(Error::new("crypto_scope_mismatch", true));
    }
    meta.identity = identity.as_deref().map(parsed).transpose()?;
    meta.provider_bytes = provider_len
        .map(usize::try_from)
        .transpose()
        .map_err(|_| corrupt())?
        .unwrap_or(0);
    let rev = revision(&meta.revision).map_err(|_| corrupt())?;
    let encryptions = revision(&meta.encryptions).map_err(|_| corrupt())?;
    match &meta.identity {
        None => {
            if provider_len.is_some()
                || !meta.provider_hash.is_empty()
                || meta.conversation.is_some()
                || rev != 0
                || encryptions != 0
            {
                return Err(corrupt());
            }
        }
        Some(identity) => {
            if identity.service != scope.service
                || identity.account != scope.account
                || identity.device != scope.device
                || meta.provider_bytes == 0
                || meta.provider_bytes > PROVIDER_LIMIT
                || !valid_hash(&meta.provider_hash)
                || model::decode(&identity.identity_key)
                    .map_err(|_| corrupt())?
                    .len()
                    != 32
            {
                return Err(corrupt());
            }
            if let Some(conversation) = &meta.conversation {
                if !valid_id(conversation) || !identity.key_package.is_empty() {
                    return Err(corrupt());
                }
            } else {
                model::decode(&identity.key_package).map_err(|_| corrupt())?;
            }
        }
    }
    meta.results = results(tx)?;
    meta.outbox = outbox(tx)?;
    meta.inbox = receive_query::inbox(tx)?;
    meta.receipts = receive_query::receipts(tx)?;
    meta.downloads = download::load(tx)?;
    relations::validate(&meta, scope)?;
    download::validate(&meta, scope)?;
    receive::validate(&meta, scope)?;
    Ok(meta)
}

fn results(tx: &Transaction<'_>) -> Result<Vec<StoredResult>> {
    let oversized: i64 = tx
        .query_row(
            "SELECT count(*) FROM crypto_results WHERE length(outcome_json)>262144",
            [],
            |r| r.get(0),
        )
        .map_err(Error::database)?;
    if oversized != 0 {
        return Err(corrupt());
    }
    let mut s=tx.prepare("SELECT request_id,input_hash,kind,outcome_json FROM crypto_results ORDER BY request_id LIMIT 129").map_err(Error::database)?;
    let rows = s
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
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
        .map(|(request_id, input_hash, kind, json)| {
            let outcome: Outcome = parsed(&json)?;
            if !valid_id(&request_id)
                || !valid_hash(&input_hash)
                || outcome.kind != kind
                || outcome.cached
                || !matches!(
                    kind.as_str(),
                    "initialize" | "create_group" | "send" | "receive" | "rebuild_add"
                )
            {
                return Err(corrupt());
            }
            Ok(StoredResult {
                request_id,
                input_hash,
                outcome,
            })
        })
        .collect()
}

fn outbox(tx: &Transaction<'_>) -> Result<Vec<Outbound>> {
    let oversized: i64 = tx
        .query_row(
            "SELECT count(*) FROM crypto_outbox WHERE length(envelope_json)>262144",
            [],
            |r| r.get(0),
        )
        .map_err(Error::database)?;
    if oversized != 0 {
        return Err(corrupt());
    }
    let mut s=tx.prepare("SELECT attempt_id,message_id,request_id,input_hash,envelope_json FROM crypto_outbox ORDER BY attempt_id LIMIT 129").map_err(Error::database)?;
    let rows = s
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    if rows.len() > LIMIT {
        return Err(corrupt());
    }
    rows.into_iter()
        .map(|(attempt_id, message_id, request_id, input_hash, json)| {
            if ![&attempt_id, &message_id, &request_id]
                .into_iter()
                .all(|v| valid_id(v))
                || !valid_hash(&input_hash)
            {
                return Err(corrupt());
            }
            Ok(Outbound {
                attempt_id,
                message_id,
                request_id,
                input_hash,
                envelope: parsed(&json)?,
            })
        })
        .collect()
}

pub(super) fn provider(tx: &Transaction<'_>, meta: &Meta) -> Result<Option<Vec<u8>>> {
    let blob: Option<Vec<u8>> = tx
        .query_row(
            "SELECT provider FROM crypto_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(Error::database)?;
    if blob.as_ref().map_or(0, Vec::len) != meta.provider_bytes
        || blob.as_deref().map(model::hash).unwrap_or_default() != meta.provider_hash
    {
        return Err(corrupt());
    }
    Ok(blob)
}

pub(super) fn inspect(scope: &Scope, meta: Meta, pending: Option<Reservation>) -> Result<Inspect> {
    if pending.as_ref().is_some_and(|p| {
        p.base_revision != meta.revision || p.base_provider_hash != meta.provider_hash
    }) {
        return Err(corrupt());
    }
    let outbox = meta
        .outbox
        .iter()
        .map(|entry| {
            Ok(OutboxSummary {
                attempt_id: entry.attempt_id.clone(),
                message_id: entry.message_id.clone(),
                ciphertext_hash: model::hash(
                    &model::decode(&entry.envelope.ciphertext).map_err(|_| corrupt())?,
                ),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Inspect {
        scope: scope.clone(),
        revision: meta.revision,
        identity: meta.identity,
        conversation: meta.conversation,
        provider_hash: meta.provider_hash,
        provider_bytes: meta.provider_bytes,
        encryptions: meta.encryptions,
        pending,
        outbox,
        result_count: meta.results.len(),
        processed_cursor: meta.processed_cursor,
        decryptions: meta.decryptions,
        inbox: meta.inbox.into_iter().map(|entry| entry.summary).collect(),
        receipt_count: meta.receipts.len(),
        download_cursor: meta.download_cursor,
        downloads: meta
            .downloads
            .into_iter()
            .map(|entry| entry.summary)
            .collect(),
    })
}
