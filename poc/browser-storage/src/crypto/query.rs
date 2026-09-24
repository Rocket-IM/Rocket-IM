//! 显式事务中的有界读取与公开投影；查询不会恢复或调用 OpenMLS。

use rusqlite::{OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use super::model::{hash, Envelope, Identity};
use crate::protocol::{parse_revision, ApiError, Scope};

pub(super) const LIMIT: usize = 32;
pub(super) const PROVIDER_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Outbound {
    pub attempt_id: String,
    pub message_id: String,
    pub plaintext_hash: String,
    pub ciphertext_hash: String,
    pub envelope: Envelope,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Event {
    pub sequence: String,
    pub event_id: String,
    pub ciphertext_hash: String,
    pub status: String,
    pub envelope: Envelope,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Message {
    pub sequence: String,
    pub event_id: String,
    pub message_id: String,
    pub sender_account: String,
    pub text: String,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Reservation {
    pub operation: String,
    pub attempt_id: String,
    pub input_hash: String,
    pub base_revision: String,
    pub base_provider_hash: Option<String>,
}

pub(super) struct State {
    pub revision: String,
    pub identity: Option<Identity>,
    pub conversation: Option<String>,
    pub provider: Option<Vec<u8>>,
    pub encryptions: String,
    pub decryptions: String,
    pub download_cursor: String,
    pub processing_cursor: String,
    pub outbox: Vec<Outbound>,
    pub events: Vec<Event>,
    pub messages: Vec<Message>,
    pub receipts: Vec<String>,
    pub welcome: Option<String>,
}

pub(super) fn corrupt() -> ApiError {
    ApiError::new(
        "crypto_store_corrupt",
        "密码实验保存状态不完整或不匹配。",
        true,
    )
}

pub(super) fn serialized<T: Serialize>(value: &T) -> Result<String, ApiError> {
    serde_json::to_string(value).map_err(|_| corrupt())
}

fn parsed<T: DeserializeOwned>(text: &str) -> Result<T, ApiError> {
    if text.len() > 256 * 1024 {
        return Err(corrupt());
    }
    serde_json::from_str(text).map_err(|_| corrupt())
}

pub(super) fn reservation(tx: &Transaction<'_>) -> Result<Option<Reservation>, ApiError> {
    tx.query_row(
        "SELECT operation, attempt_id, input_hash, base_revision, base_provider_hash
        FROM crypto_reservation WHERE singleton = 1",
        [],
        |row| {
            Ok(Reservation {
                operation: row.get(0)?,
                attempt_id: row.get(1)?,
                input_hash: row.get(2)?,
                base_revision: row.get(3)?,
                base_provider_hash: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(ApiError::database)
}

fn rows<T: DeserializeOwned>(tx: &Transaction<'_>, sql: &str) -> Result<Vec<T>, ApiError> {
    let mut statement = tx.prepare(sql).map_err(ApiError::database)?;
    let texts = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(ApiError::database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::database)?;
    if texts.len() > LIMIT {
        return Err(corrupt());
    }
    texts.iter().map(|text| parsed(text)).collect()
}

pub(super) fn load(tx: &Transaction<'_>, scope: &Scope) -> Result<State, ApiError> {
    let provider_length: Option<i64> = tx
        .query_row(
            "SELECT length(provider) FROM crypto_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(ApiError::database)?;
    if provider_length.is_some_and(|length| length < 1 || length > PROVIDER_LIMIT as i64) {
        return Err(corrupt());
    }
    let (service, account, format, identity, mut state) = tx
        .query_row(
            "SELECT service, account, format, identity_json, revision, conversation, provider,
        encryptions, decryptions, download_cursor, processing_cursor, welcome
        FROM crypto_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    State {
                        revision: row.get(4)?,
                        identity: None,
                        conversation: row.get(5)?,
                        provider: row.get(6)?,
                        encryptions: row.get(7)?,
                        decryptions: row.get(8)?,
                        download_cursor: row.get(9)?,
                        processing_cursor: row.get(10)?,
                        welcome: row.get(11)?,
                        outbox: Vec::new(),
                        events: Vec::new(),
                        messages: Vec::new(),
                        receipts: Vec::new(),
                    },
                ))
            },
        )
        .map_err(ApiError::database)?;
    if service != scope.service || account != scope.account || format != 1 {
        return Err(corrupt());
    }
    state.identity = identity.as_deref().map(parsed).transpose()?;
    if state.identity.is_some() != state.provider.is_some()
        || state.identity.as_ref().is_some_and(|id| {
            id.service != service || id.account != account || id.device != scope.device
        })
    {
        return Err(corrupt());
    }
    for value in [
        &state.revision,
        &state.encryptions,
        &state.decryptions,
        &state.download_cursor,
        &state.processing_cursor,
    ] {
        parse_revision(value).map_err(|_| corrupt())?;
    }
    if parse_revision(&state.processing_cursor)? > parse_revision(&state.download_cursor)? {
        return Err(corrupt());
    }
    state.outbox = rows(
        tx,
        "SELECT record_json FROM crypto_outbox ORDER BY attempt_id LIMIT 33",
    )?;
    state.events = rows(
        tx,
        "SELECT record_json FROM crypto_events ORDER BY length(sequence), sequence LIMIT 33",
    )?;
    state.messages = rows(
        tx,
        "SELECT record_json FROM crypto_messages ORDER BY length(sequence), sequence LIMIT 33",
    )?;
    state.receipts = rows(
        tx,
        "SELECT record_json FROM crypto_receipts ORDER BY event_id LIMIT 33",
    )?;
    if state
        .events
        .iter()
        .any(|event| !matches!(event.status.as_str(), "pending" | "processed" | "duplicate"))
    {
        return Err(corrupt());
    }
    if state.identity.is_none()
        && (state.conversation.is_some()
            || state.welcome.is_some()
            || !state.outbox.is_empty()
            || !state.events.is_empty()
            || !state.messages.is_empty())
    {
        return Err(corrupt());
    }
    Ok(state)
}

impl State {
    pub fn provider_hash(&self) -> Option<String> {
        self.provider.as_deref().map(hash)
    }

    pub fn snapshot(&self, scope: &Scope, pending: Option<&Reservation>, change: &str) -> Value {
        let mut outbox: Vec<_> = self.outbox.iter().collect();
        outbox.sort_by(|left, right| left.attempt_id.cmp(&right.attempt_id));
        let mut receipts: Vec<_> = self.receipts.iter().collect();
        receipts.sort();
        let events: Vec<_> = self
            .events
            .iter()
            .map(|event| {
                json!({
                    "sequence":event.sequence, "eventId":event.event_id,
                    "ciphertextHash":event.ciphertext_hash, "status":event.status,
                })
            })
            .collect();
        json!({"service":scope.service, "account":scope.account, "device":scope.device,
            "status":if pending.is_some() {"paused"} else if self.identity.is_some() {"ready"} else {"empty"},
            "revision":self.revision, "identity":self.identity, "conversation":self.conversation,
            "providerHash":self.provider_hash(),
            "pending":pending.map(|item| json!({"operation":item.operation,"attemptId":item.attempt_id})),
            "encryptions":self.encryptions, "decryptions":self.decryptions,
            "downloadCursor":self.download_cursor, "processingCursor":self.processing_cursor,
            "outbox":outbox, "events":events, "messages":self.messages,
            "receipts":receipts, "welcome":self.welcome, "change":change})
    }
}
