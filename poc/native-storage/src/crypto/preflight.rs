//! 元数据预检复用于预约与执行；不实例化密码引擎，不写业务记录或交付缓存结果。
use super::{
    contract::{Action, DownloadRecord, DownloadRequest, Fault, Outcome, Request, Scope},
    query::{self, Meta},
    schema,
    store::persistence,
};
use crate::model::{revision, Error, Result};
use rusqlite::Transaction;
use serde::Deserialize;

/// 与协调器用于承诺的原输入一一对应；重建激活仍走独立的 linked 状态门。
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Input {
    Execute(Request),
    Download(DownloadRequest),
    Process {
        request_id: String,
        sequence: String,
        fault: Fault,
    },
    RebuildApprove(Request),
}
impl Input {
    pub(crate) fn check(&self, tx: &Transaction<'_>, scope: &Scope) -> Result<()> {
        let meta = query::load(tx, scope)?;
        match self {
            Self::Execute(value) | Self::RebuildApprove(value) => {
                request(&meta, scope, value, &persistence::input_hash(value)?)?;
            }
            Self::Download(value) => {
                download(&meta, scope, value)?;
            }
            Self::Process {
                request_id,
                sequence,
                fault,
            } => {
                let value = process(&meta, request_id, sequence, *fault)
                    .ok_or_else(|| Error::new("download_not_found", false))?;
                request(&meta, scope, &value, &persistence::input_hash(&value)?)?;
            }
        }
        Ok(())
    }
}

pub(super) fn request(
    meta: &Meta,
    scope: &Scope,
    request: &Request,
    input_hash: &str,
) -> Result<Option<Outcome>> {
    super::contract::validate_id(&request.request_id)?;
    request.action.validate()?;
    if let Some(old) = meta
        .results
        .iter()
        .find(|item| item.request_id == request.request_id)
    {
        if old.input_hash != input_hash {
            return Err(Error::new("crypto_request_conflict", false));
        }
        let mut outcome = old.outcome.clone();
        outcome.cached = true;
        return Ok(Some(outcome));
    }
    if let Action::Receive { sequence, envelope } = &request.action {
        if let Some(value) = query::receive::cached(meta, scope, sequence, envelope, input_hash)? {
            return Ok(Some(value));
        }
    }
    if let Action::Send {
        attempt_id,
        message_id,
        ..
    } = &request.action
    {
        if let Some(old) = meta
            .outbox
            .iter()
            .find(|item| &item.attempt_id == attempt_id)
        {
            if &old.message_id != message_id || old.input_hash != input_hash {
                return Err(Error::new("crypto_attempt_conflict", false));
            }
            let result = meta
                .results
                .iter()
                .find(|item| item.request_id == old.request_id)
                .ok_or_else(schema::corrupt)?;
            let mut outcome = result.outcome.clone();
            outcome.cached = true;
            return Ok(Some(outcome));
        }
        if meta
            .outbox
            .iter()
            .any(|item| &item.message_id == message_id)
        {
            return Err(Error::new("crypto_message_conflict", false));
        }
        if meta.outbox.len() >= query::LIMIT {
            return Err(Error::new("crypto_limit", false));
        }
    }
    match &request.action {
        Action::Initialize {} if meta.identity.is_some() => {
            return Err(Error::new("crypto_already_initialized", false))
        }
        Action::CreateGroup { .. } if meta.conversation.is_some() => {
            return Err(Error::new("crypto_already_grouped", false))
        }
        Action::CreateGroup { .. } if meta.identity.is_none() => {
            return Err(Error::new("crypto_not_initialized", false))
        }
        Action::Send { .. } if meta.conversation.is_none() => {
            return Err(Error::new("crypto_no_group", false))
        }
        _ => {}
    }
    if meta.results.len() >= query::LIMIT {
        return Err(Error::new("crypto_limit", false));
    }
    crate::model::revision(&meta.revision)?
        .checked_add(1)
        .ok_or_else(schema::corrupt)?;
    Ok(None)
}

pub(super) fn download<'a>(
    meta: &Meta,
    scope: &Scope,
    request: &'a DownloadRequest,
) -> Result<(u64, Vec<&'a DownloadRecord>)> {
    request.validate()?;
    if meta.conversation.is_none() {
        return Err(Error::new("crypto_no_group", false));
    }
    let mut cursor = revision(&meta.download_cursor)?;
    let mut additions = Vec::new();
    for record in &request.records {
        let envelope = &record.envelope;
        if envelope.service != scope.service
            || Some(&envelope.conversation) != meta.conversation.as_ref()
        {
            return Err(Error::new("crypto_scope_mismatch", false));
        }
        if let Some(old) = meta
            .downloads
            .iter()
            .find(|v| v.summary.sequence == record.sequence)
        {
            if old.envelope != *envelope {
                return Err(Error::new("download_sequence_conflict", false));
            }
            continue;
        }
        if revision(&record.sequence)? != cursor.checked_add(1).ok_or_else(schema::corrupt)? {
            return Err(Error::new("download_gap", false));
        }
        if meta.downloads.len() + additions.len() >= query::LIMIT {
            return Err(Error::new("crypto_limit", false));
        }
        cursor += 1;
        additions.push(record);
    }
    Ok((cursor, additions))
}

pub(super) fn process(
    meta: &Meta,
    request_id: &str,
    sequence: &str,
    fault: Fault,
) -> Option<Request> {
    meta.downloads
        .iter()
        .find(|v| v.summary.sequence == sequence)
        .map(|record| Request {
            request_id: request_id.into(),
            action: Action::Receive {
                sequence: sequence.into(),
                envelope: record.envelope.clone(),
            },
            fault,
        })
}
