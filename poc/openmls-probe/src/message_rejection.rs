//! Service 对精确旧状态尝试的最终拒绝；所需检查点不替代本机实际权限链验证。
use crate::permission::{
    receipts::{self, SignedRecord},
    types, Identity, PermissionError,
};
use serde::{Deserialize, Deserializer, Serialize};

pub const SIGNING_DOMAIN: &[u8] = b"Rocket-IM/POC/message-rejection/v1\0";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRejectionStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub sender: Identity,
    pub logical_message_id: String,
    pub attempt_id: String,
    pub envelope_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    pub replaces_attempt_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub predecessor_closure_id: Option<String>,
    pub closure_id: String,
    pub outcome: String,
    pub code: String,
    pub required_authorization_version: String,
    pub required_crypto_state_ref: String,
}
// 必填 null 与缺失具有不同协议含义，不能使用 serde 的 Option 缺省。
fn required_nullable<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
impl MessageRejectionStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        let invalid = || PermissionError::new("rejection_invalid", "消息拒绝声明字段无效");
        if self.protocol_version != "rim-message-rejection-1"
            || self.outcome != "rejected_final"
            || self.code != "state_stale"
            || self.replaces_attempt_id.is_some() != self.predecessor_closure_id.is_some()
            || self.replaces_attempt_id.as_ref() == Some(&self.attempt_id)
            || self.predecessor_closure_id.as_ref() == Some(&self.closure_id)
        {
            return Err(invalid());
        }
        for value in [
            &self.service_id,
            &self.conversation_id,
            &self.sender.account_id,
            &self.sender.device_id,
            &self.logical_message_id,
            &self.attempt_id,
            &self.closure_id,
        ]
        .into_iter()
        .chain(self.replaces_attempt_id.iter())
        .chain(self.predecessor_closure_id.iter())
        {
            types::id(value).map_err(|_| invalid())?;
        }
        types::hash(&self.envelope_sha256).map_err(|_| invalid())?;
        types::hash(&self.required_crypto_state_ref).map_err(|_| invalid())?;
        types::decimal(&self.required_authorization_version).map_err(|_| invalid())?;
        Ok(())
    }
}
pub fn verify(
    key: &str,
    receipt: &SignedRecord,
) -> Result<MessageRejectionStatement, PermissionError> {
    let raw = types::bytes(&receipt.statement_bytes, 16 * 1024)
        .map_err(|_| PermissionError::new("rejection_invalid", "拒绝声明编码无效"))?;
    let statement: MessageRejectionStatement = serde_json::from_slice(&raw)
        .map_err(|_| PermissionError::new("rejection_invalid", "拒绝声明字段无效"))?;
    statement.validate()?;
    receipts::signature(key, SIGNING_DOMAIN, &raw, &receipt.signature_bytes)
        .map_err(|_| PermissionError::new("rejection_signature", "消息拒绝签名无效"))?;
    Ok(statement)
}
