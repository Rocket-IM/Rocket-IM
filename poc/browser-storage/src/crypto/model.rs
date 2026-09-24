//! 公开实验值与有界编码；provider 私密快照不属于这些类型。
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::{validate_id, ApiError};

pub(super) const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_ENTRIES: usize = 4096;
pub(super) const MAX_PROTOCOL_BYTES: usize = 64 * 1024;
pub(super) const MAX_TEXT_BYTES: usize = 4096;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Identity {
    pub service: String,
    pub account: String,
    pub device: String,
    pub identity_key: String,
    pub key_package: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Envelope {
    pub service: String,
    pub conversation: String,
    pub sender_account: String,
    pub sender_device: String,
    pub message_id: String,
    pub ciphertext: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PlainMessage {
    pub message_id: String,
    pub sender_account: String,
    pub text: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MessageContext {
    pub version: u32,
    pub service: String,
    pub conversation: String,
    pub sender_account: String,
    pub sender_device: String,
    pub message_id: String,
}

impl MessageContext {
    pub fn from_envelope(envelope: &Envelope) -> Result<Self, ApiError> {
        for value in [
            &envelope.service,
            &envelope.conversation,
            &envelope.sender_account,
            &envelope.sender_device,
            &envelope.message_id,
        ] {
            validate_id(value)?;
        }
        Ok(Self {
            version: 1,
            service: envelope.service.clone(),
            conversation: envelope.conversation.clone(),
            sender_account: envelope.sender_account.clone(),
            sender_device: envelope.sender_device.clone(),
            message_id: envelope.message_id.clone(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthenticatedPlaintext {
    pub context: MessageContext,
    pub text: String,
}

pub(super) fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub(super) fn decode(encoded: &str) -> Result<Vec<u8>, ApiError> {
    if encoded.is_empty() || encoded.len() > MAX_PROTOCOL_BYTES.div_ceil(3) * 4 {
        return Err(limit());
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| ApiError::invalid())?;
    if bytes.len() > MAX_PROTOCOL_BYTES || encode(&bytes) != encoded {
        return Err(ApiError::invalid());
    }
    Ok(bytes)
}

pub(super) fn text(value: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(limit());
    }
    Ok(())
}

pub(super) fn require(condition: bool, code: &'static str) -> Result<(), ApiError> {
    if condition {
        Ok(())
    } else {
        Err(ApiError::new(
            code,
            "密码实验状态或认证上下文不匹配。",
            true,
        ))
    }
}

pub(super) fn failed<T, E>(result: Result<T, E>) -> Result<T, ApiError> {
    result.map_err(|_| {
        ApiError::new(
            "crypto_failed",
            "密码操作失败，候选状态不可继续使用。",
            true,
        )
    })
}

pub(super) fn limit() -> ApiError {
    ApiError::new("crypto_limit", "密码实验输入或状态超过上限。", true)
}

pub(super) fn corrupt() -> ApiError {
    ApiError::new("crypto_state_corrupt", "密码快照格式或绑定不合法。", true)
}
