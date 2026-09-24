//! 合成实验的公开命令；密码 provider BLOB 与数据库句柄均不属于公共契约。
use super::model::{Envelope, Identity, PlainMessage};
use crate::model::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub service: String,
    pub account: String,
    pub device: String,
}

pub(crate) fn validate_id(value: &str) -> Result<()> {
    if crate::model::valid_id(value) {
        Ok(())
    } else {
        Err(Error::new("invalid_id", false))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Initialize {},
    CreateGroup {
        conversation: String,
        peer: Identity,
    },
    /// 只由独立锚重建批准入口执行；普通 execute 必须拒绝。
    RebuildAdd {
        plan: serde_json::Value,
        peer: Identity,
    },
    Receive {
        sequence: String,
        envelope: Envelope,
    },
    Send {
        attempt_id: String,
        message_id: String,
        text: String,
    },
}
impl Action {
    pub(crate) fn operation(&self) -> &'static str {
        match self {
            Self::Initialize {} => "initialize",
            Self::CreateGroup { .. } => "create_group",
            Self::Send { .. } => "send",
            Self::Receive { .. } => "receive",
            Self::RebuildAdd { .. } => "rebuild_add",
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Initialize {} => Ok(()),
            Self::CreateGroup { conversation, peer } => {
                for value in [conversation, &peer.service, &peer.account, &peer.device] {
                    validate_id(value)?;
                }
                if super::model::decode(&peer.identity_key)?.len() != 32 {
                    return Err(Error::new("invalid_identity", false));
                }
                super::model::decode(&peer.key_package)?;
                Ok(())
            }
            Self::RebuildAdd { plan, peer } => {
                super::engine::Engine::validate_rebuild_plan(plan, peer)
            }
            Self::Receive { sequence, envelope } => {
                receive_sequence(sequence)?;
                for id in [
                    &envelope.service,
                    &envelope.conversation,
                    &envelope.sender_account,
                    &envelope.sender_device,
                    &envelope.message_id,
                ] {
                    validate_id(id)?;
                }
                super::model::decode(&envelope.ciphertext)?;
                Ok(())
            }
            Self::Send {
                attempt_id,
                message_id,
                text,
            } => {
                validate_id(attempt_id)?;
                validate_id(message_id)?;
                if text.is_empty() || text.len() > 4096 {
                    return Err(Error::new("invalid_text", false));
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn receive_sequence(value: &str) -> Result<u64> {
    crate::model::revision(value)
        .ok()
        .filter(|number| *number > 0)
        .ok_or_else(|| Error::new("invalid_sequence", false))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveValue {
    pub sequence: String,
    pub duplicate: bool,
    pub message: PlainMessage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxSummary {
    pub message_key: String,
    pub first_sequence: String,
    pub message_id: String,
    pub sender_account: String,
    pub sender_device: String,
    pub ciphertext_hash: String,
    pub text_hash: String,
}

/// 合成下载流中的原始密文，序号为无损的十进制正整数；尚未经过解密认证。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRecord {
    pub sequence: String,
    pub envelope: Envelope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRequest {
    pub records: Vec<DownloadRecord>,
    #[serde(default)]
    pub fault: Fault,
}
impl DownloadRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.records.is_empty() || self.records.len() > 16 {
            return Err(Error::new("invalid_download_batch", false));
        }
        if !matches!(
            self.fault,
            Fault::None
                | Fault::AfterSql
                | Fault::RefuseCommit
                | Fault::BeforeCommit
                | Fault::AfterCommit
        ) {
            return Err(Error::new("invalid_download_fault", false));
        }
        let mut previous: Option<u64> = None;
        for record in &self.records {
            Action::Receive {
                sequence: record.sequence.clone(),
                envelope: record.envelope.clone(),
            }
            .validate()?;
            let sequence = receive_sequence(&record.sequence)?;
            if previous.is_some_and(|value| value.checked_add(1) != Some(sequence)) {
                return Err(Error::new("invalid_download_batch", false));
            }
            previous = Some(sequence);
        }
        Ok(())
    }
}

/// 仅确认原始下载记录持久化；不表示已解密、已读或已向 Service 确认。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DownloadOutcome {
    pub download_cursor: String,
    pub processed_cursor: String,
    pub added: usize,
    pub cached: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadSummary {
    pub sequence: String,
    pub envelope_hash: String,
    pub ciphertext_hash: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    #[default]
    None,
    ReserveRefuse,
    AfterReserve,
    AfterCrypto,
    AfterSql,
    RefuseCommit,
    BeforeCommit,
    AfterCommit,
    PauseAfterReserve,
    PauseAfterCrypto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
    pub action: Action,
    #[serde(default)]
    pub fault: Fault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub request_id: String,
    pub operation: String,
    pub input_hash: String,
    pub base_revision: String,
    pub base_provider_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inspect {
    pub scope: Scope,
    pub revision: String,
    pub identity: Option<Identity>,
    pub conversation: Option<String>,
    pub provider_hash: String,
    pub provider_bytes: usize,
    pub encryptions: String,
    pub pending: Option<Reservation>,
    pub outbox: Vec<OutboxSummary>,
    pub result_count: usize,
    pub processed_cursor: String,
    pub decryptions: String,
    pub inbox: Vec<InboxSummary>,
    pub receipt_count: usize,
    pub download_cursor: String,
    pub downloads: Vec<DownloadSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxSummary {
    pub attempt_id: String,
    pub message_id: String,
    pub ciphertext_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub revision: String,
    pub kind: String,
    pub cached: bool,
    pub value: serde_json::Value,
}

// 这些值只在 Rust 协调线程与数据库线程之间传递，不提供给宿主。
pub(crate) struct Prepared {
    pub reservation: Reservation,
    pub provider: Option<Vec<u8>>,
    pub identity: Option<Identity>,
    pub conversation: Option<String>,
    pub encryptions: String,
    pub processed_cursor: String,
    pub decryptions: String,
    pub duplicate: Option<ReceiveValue>,
}
pub(crate) enum Preparation {
    Cached(Outcome),
    Reserved(Box<Prepared>),
}
pub(crate) struct Candidate {
    pub provider: Vec<u8>,
    pub identity: Identity,
    pub conversation: Option<String>,
    pub encryptions: String,
    pub outcome: Outcome,
    pub processed_cursor: String,
    pub decryptions: String,
}
