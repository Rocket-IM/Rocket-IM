//! 密码实验的有界公开命令；故障控制不进入业务幂等摘要。

use serde::{Deserialize, Serialize};

use super::model::{decode, Envelope, Identity};
use crate::protocol::{parse_revision, validate_id, ApiError};

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Inspect,
    Initialize,
    CreateGroup {
        conversation: String,
        peer: Identity,
    },
    JoinGroup {
        conversation: String,
        peer: Identity,
        welcome: String,
    },
    Send {
        #[serde(rename = "attemptId")]
        attempt_id: String,
        #[serde(rename = "messageId")]
        message_id: String,
        text: String,
    },
    Download {
        event: DownloadEvent,
    },
    ProcessNext,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DownloadEvent {
    pub sequence: String,
    pub event_id: String,
    pub envelope: Envelope,
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TestFault {
    AfterCrypto,
    AfterSql,
    RefuseCommit,
    ReserveRefuse,
    LoseReservationTable,
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TestCheckpoint {
    AfterReserve,
    AfterCrypto,
    BeforeCommit,
    AfterCommit,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestOptions {
    pub fault: Option<TestFault>,
    pub checkpoint: Option<TestCheckpoint>,
}

pub(crate) struct Request {
    pub action: Action,
    pub test: TestOptions,
}

impl Request {
    pub fn parse(json: &str, test_mode: bool) -> Result<Self, ApiError> {
        if json.len() > 256 * 1024 {
            return Err(ApiError::invalid());
        }
        let mut value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| ApiError::invalid())?;
        let object = value.as_object_mut().ok_or_else(ApiError::invalid)?;
        let test = match object.remove("test") {
            Some(_) if !test_mode => return Err(ApiError::test_only()),
            Some(test) => serde_json::from_value(test).map_err(|_| ApiError::invalid())?,
            None => TestOptions::default(),
        };
        let action: Action = serde_json::from_value(value).map_err(|_| ApiError::invalid())?;
        if test.fault.is_some() && test.checkpoint.is_some() {
            return Err(ApiError::invalid());
        }
        if test.fault == Some(TestFault::LoseReservationTable)
            && !matches!(action, Action::Send { .. })
        {
            return Err(ApiError::invalid());
        }
        if matches!(action, Action::Inspect) && (test.fault.is_some() || test.checkpoint.is_some())
        {
            return Err(ApiError::invalid());
        }
        if matches!(action, Action::Download { .. })
            && (matches!(
                test.fault,
                Some(TestFault::AfterCrypto | TestFault::ReserveRefuse)
            ) || matches!(
                test.checkpoint,
                Some(TestCheckpoint::AfterReserve | TestCheckpoint::AfterCrypto)
            ))
        {
            return Err(ApiError::invalid());
        }
        match &action {
            Action::CreateGroup { conversation, peer }
            | Action::JoinGroup {
                conversation, peer, ..
            } => {
                validate_id(conversation)?;
                validate_identity(peer)?;
            }
            Action::Send {
                attempt_id,
                message_id,
                text,
            } => {
                validate_id(attempt_id)?;
                validate_id(message_id)?;
                if text.is_empty() || text.len() > 4096 {
                    return Err(ApiError::invalid());
                }
            }
            Action::Download { event } => {
                validate_id(&event.event_id)?;
                if parse_revision(&event.sequence)? == 0 {
                    return Err(ApiError::invalid());
                }
                validate_envelope(&event.envelope)?;
            }
            _ => {}
        }
        if let Action::JoinGroup { welcome, .. } = &action {
            bounded_bytes(welcome)?;
        }
        Ok(Self { action, test })
    }
}

fn bounded_bytes(text: &str) -> Result<(), ApiError> {
    decode(text).map(|_| ()).map_err(|_| ApiError::invalid())
}

fn validate_identity(identity: &Identity) -> Result<(), ApiError> {
    for id in [&identity.service, &identity.account, &identity.device] {
        validate_id(id)?;
    }
    if decode(&identity.identity_key)
        .map_err(|_| ApiError::invalid())?
        .len()
        != 32
    {
        return Err(ApiError::invalid());
    }
    if !identity.key_package.is_empty() {
        bounded_bytes(&identity.key_package)?;
    }
    Ok(())
}

pub(super) fn validate_envelope(envelope: &Envelope) -> Result<(), ApiError> {
    for id in [
        &envelope.service,
        &envelope.conversation,
        &envelope.sender_account,
        &envelope.sender_device,
        &envelope.message_id,
    ] {
        validate_id(id)?;
    }
    bounded_bytes(&envelope.ciphertext)
}

impl Action {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Initialize => "initialize",
            Self::CreateGroup { .. } => "create_group",
            Self::JoinGroup { .. } => "join_group",
            Self::Send { .. } => "send",
            Self::Download { .. } => "download",
            Self::ProcessNext => "process_next",
        }
    }
}
