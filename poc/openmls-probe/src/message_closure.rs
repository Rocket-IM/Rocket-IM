//! Service 对未提交原尝试的签名封口；不声明密码有效，也不释放另一逻辑消息的发送门。
use crate::permission::{
    receipts::{self, SignedRecord},
    types, Identity, PermissionError,
};
use serde::{Deserialize, Deserializer, Serialize};

pub const SIGNING_DOMAIN: &[u8] = b"Rocket-IM/POC/message-closure/v1\0";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageClosureStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub sender: Identity,
    pub logical_message_id: String,
    pub attempt_id: String,
    pub envelope_sha256: String,
    // null 是协议值；自定义反序列化使字段缺失不被当成 null。
    #[serde(deserialize_with = "required_nullable")]
    pub replaces_attempt_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub predecessor_closure_id: Option<String>,
    pub closure_id: String,
    pub outcome: String,
}
fn required_nullable<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
impl MessageClosureStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        let invalid = || PermissionError::new("closure_invalid", "消息封口声明字段无效");
        if self.protocol_version != "rim-message-closure-1"
            || self.outcome != "cancelled_before_accept"
            || self.replaces_attempt_id.is_some() != self.predecessor_closure_id.is_some()
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
        if self.replaces_attempt_id.as_ref() == Some(&self.attempt_id)
            || self.predecessor_closure_id.as_ref() == Some(&self.closure_id)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
pub fn verify(
    key: &str,
    receipt: &SignedRecord,
) -> Result<MessageClosureStatement, PermissionError> {
    let raw = types::bytes(&receipt.statement_bytes, 16 * 1024)
        .map_err(|_| PermissionError::new("closure_invalid", "封口声明编码无效"))?;
    let statement: MessageClosureStatement = serde_json::from_slice(&raw)
        .map_err(|_| PermissionError::new("closure_invalid", "封口声明字段无效"))?;
    statement.validate()?;
    receipts::signature(key, SIGNING_DOMAIN, &raw, &receipt.signature_bytes)
        .map_err(|_| PermissionError::new("closure_signature", "消息封口签名无效"))?;
    Ok(statement)
}
