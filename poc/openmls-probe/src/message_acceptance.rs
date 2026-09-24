//! Service 对精确消息字节的接受承诺；不证明密码有效或恶意Service没有倒签。
use crate::permission::{
    receipts::{self, SignedRecord},
    types, PermissionError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SIGNING_DOMAIN: &[u8] = b"Rocket-IM/POC/message-acceptance/v1\0";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAcceptanceStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub acceptance_id: String,
    pub envelope_sha256: String,
    pub authorization_version: String,
    pub crypto_state_ref: String,
}
impl MessageAcceptanceStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-message-acceptance-1" {
            return Err(PermissionError::new(
                "invalid_acceptance",
                "消息接受协议不支持",
            ));
        }
        for value in [&self.service_id, &self.conversation_id, &self.acceptance_id] {
            types::id(value)?;
        }
        types::hash(&self.envelope_sha256)?;
        types::hash(&self.crypto_state_ref)?;
        types::decimal(&self.authorization_version)?;
        Ok(())
    }
}
pub fn envelope_digest(header: &[u8], payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"Rocket-IM/POC/message-envelope/v1\0");
    for bytes in [header, payload] {
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn verify(
    key: &str,
    receipt: &SignedRecord,
) -> Result<MessageAcceptanceStatement, PermissionError> {
    let raw = types::bytes(&receipt.statement_bytes, 16 * 1024)?;
    let statement: MessageAcceptanceStatement = serde_json::from_slice(&raw)
        .map_err(|_| PermissionError::new("invalid_acceptance", "消息接受声明字段无效"))?;
    statement.validate()?;
    receipts::signature(key, SIGNING_DOMAIN, &raw, &receipt.signature_bytes)
        .map_err(|_| PermissionError::new("acceptance_signature", "消息接受签名无效"))?;
    Ok(statement)
}
