//! 历史副本迁移的公共声明；不包含正文或任何端侧私钥。
use crate::permission::{types, Identity, PermissionError};
use serde::{Deserialize, Serialize};

pub const MAX_BODY: usize = 256 * 1024;
pub const REQUEST_DOMAIN: &[u8] = b"Rockets-IM/POC/history-request/v1\0";
pub const PACKAGE_DOMAIN: &[u8] = b"Rockets-IM/POC/history-package/v1\0";
pub const RECEIPT_DOMAIN: &[u8] = b"Rockets-IM/POC/history-receipt/v1\0";

pub(super) fn invalid() -> PermissionError {
    PermissionError::new("history_invalid", "历史迁移字段、编码或范围无效")
}
pub(super) fn check(
    ok: bool,
    code: &'static str,
    text: &'static str,
) -> Result<(), PermissionError> {
    if ok {
        Ok(())
    } else {
        Err(PermissionError::new(code, text))
    }
}
pub fn bytes(value: &str, limit: usize) -> Result<Vec<u8>, PermissionError> {
    types::bytes(value, limit).map_err(|_| invalid())
}
pub fn decimal(value: &str) -> Result<u64, PermissionError> {
    types::decimal(value).map_err(|_| invalid())
}
fn id(value: &str) -> Result<(), PermissionError> {
    types::id(value).map_err(|_| invalid())
}
fn hash(value: &str) -> Result<(), PermissionError> {
    types::hash(value).map_err(|_| invalid())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub acceptance_id: String,
    pub envelope_sha256: String,
}
pub fn validate_selection(selection: &[Selection]) -> Result<(), PermissionError> {
    if !(1..=16).contains(&selection.len())
        || !selection
            .windows(2)
            .all(|w| w[0].acceptance_id < w[1].acceptance_id)
    {
        return Err(invalid());
    }
    for selected in selection {
        id(&selected.acceptance_id)?;
        hash(&selected.envelope_sha256)?;
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestStatement {
    pub protocol_version: String,
    pub transfer_id: String,
    pub service_id: String,
    pub conversation_id: String,
    pub source: Identity,
    pub target: Identity,
    pub authorization_version: String,
    pub crypto_state_ref: String,
    pub recipient_key: String,
    pub selection: Vec<Selection>,
    pub nonce: String,
    pub issued_at_unix_secs: String,
    pub expires_at_unix_secs: String,
}
impl RequestStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-history-request-1" {
            return Err(invalid());
        }
        for value in [
            &self.transfer_id,
            &self.service_id,
            &self.conversation_id,
            &self.source.account_id,
            &self.source.device_id,
            &self.target.account_id,
            &self.target.device_id,
        ] {
            id(value)?;
        }
        decimal(&self.authorization_version)?;
        hash(&self.crypto_state_ref)?;
        hash(&self.nonce)?;
        if bytes(&self.recipient_key, 32)?.len() != 32 {
            return Err(invalid());
        }
        validate_selection(&self.selection)?;
        let issued = decimal(&self.issued_at_unix_secs)?;
        let expires = decimal(&self.expires_at_unix_secs)?;
        if !expires
            .checked_sub(issued)
            .is_some_and(|s| (1..=300).contains(&s))
        {
            return Err(invalid());
        }
        check(
            self.source.account_id == self.target.account_id
                && self.source.device_id != self.target.device_id,
            "history_denied",
            "只能迁移给同账号另一台当前有效设备",
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageStatement {
    pub protocol_version: String,
    pub transfer_id: String,
    pub request_sha256: String,
    pub ciphertext_sha256: String,
}
impl PackageStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-history-package-1" {
            return Err(invalid());
        }
        id(&self.transfer_id)?;
        hash(&self.request_sha256)?;
        hash(&self.ciphertext_sha256)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub statement_bytes: String,
    pub signature_bytes: String,
    pub kem_output: String,
    pub ciphertext: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub transfer_id: String,
    pub request_sha256: String,
    pub package_sha256: String,
    pub authorization_version: String,
    pub crypto_state_ref: String,
    pub accepted_at_unix_ms: String,
    pub expires_at_unix_secs: String,
}
impl ReceiptStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-history-receipt-1" {
            return Err(invalid());
        }
        for value in [&self.service_id, &self.conversation_id, &self.transfer_id] {
            id(value)?;
        }
        for value in [
            &self.request_sha256,
            &self.package_sha256,
            &self.crypto_state_ref,
        ] {
            hash(value)?;
        }
        decimal(&self.authorization_version)?;
        let accepted = decimal(&self.accepted_at_unix_ms)?;
        let expires = decimal(&self.expires_at_unix_secs)?;
        check(
            accepted / 1000 < expires,
            "history_invalid",
            "接受时间必须在到期前",
        )
    }
}
