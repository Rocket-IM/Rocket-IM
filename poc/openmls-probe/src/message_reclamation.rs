//! 有界合成回收许可：Service 确認原目标处理与同意，客户端仍须验证本机依赖。
use crate::permission::{
    receipts::{self, SignedRecord},
    types, Identity, PermissionError,
};
use serde::{Deserialize, Serialize};

pub const SIGNING_DOMAIN: &[u8] = b"Rocket-IM/POC/message-reclaim/v1\0";
pub const RETENTION_DOMAIN: &[u8] = b"Rocket-IM/POC/stream-retention/v1\0";
pub const MAX_MESSAGES: usize = 16;
pub const MAX_STATEMENT_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub acceptance_id: String,
    pub envelope_sha256: String,
    pub availability: String,
    pub recipients: Vec<Identity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub plan_id: String,
    pub account_id: String,
    pub device_id: String,
    pub stream_id: String,
    pub processed_seq: String,
    pub messages: Vec<Message>,
}
impl Statement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-message-reclaim-1"
            || self.messages.is_empty()
            || self.messages.len() > MAX_MESSAGES
        {
            return Err(PermissionError::new(
                "reclaim_invalid",
                "回收许可版本或批量无效",
            ));
        }
        for value in [
            &self.service_id,
            &self.conversation_id,
            &self.plan_id,
            &self.account_id,
            &self.device_id,
            &self.stream_id,
        ] {
            types::id(value)?;
        }
        types::decimal(&self.processed_seq)?;
        let mut previous = None;
        for message in &self.messages {
            types::id(&message.acceptance_id)?;
            types::hash(&message.envelope_sha256)?;
            if !matches!(message.availability.as_str(), "deleted" | "expired")
                || message.recipients.is_empty()
                || message.recipients.len() > 5
                || previous.is_some_and(|old: &str| old >= message.acceptance_id.as_str())
            {
                return Err(PermissionError::new(
                    "reclaim_invalid",
                    "回收消息终态、顺序或目标无效",
                ));
            }
            previous = Some(message.acceptance_id.as_str());
            let mut recipient = None;
            for target in &message.recipients {
                types::id(&target.account_id)?;
                types::id(&target.device_id)?;
                let key = (&target.account_id, &target.device_id);
                if recipient.is_some_and(|old| old >= key) {
                    return Err(PermissionError::new(
                        "reclaim_invalid",
                        "原目标必须排序且唯一",
                    ));
                }
                recipient = Some(key);
            }
        }
        Ok(())
    }
}
pub fn verify(key: &str, receipt: &SignedRecord) -> Result<Statement, PermissionError> {
    let raw = types::bytes(&receipt.statement_bytes, MAX_STATEMENT_BYTES)?;
    let statement: Statement = serde_json::from_slice(&raw)
        .map_err(|_| PermissionError::new("reclaim_invalid", "回收许可字段无效"))?;
    statement.validate()?;
    receipts::signature(key, SIGNING_DOMAIN, &raw, &receipt.signature_bytes)
        .map_err(|_| PermissionError::new("reclaim_signature", "回收许可签名无效"))?;
    Ok(statement)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub account_id: String,
    pub device_id: String,
    pub stream_id: String,
    pub after_seq: String,
    pub limit: String,
    pub floor: String,
    pub watermark: String,
}
impl RetentionStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        for value in [
            &self.service_id,
            &self.account_id,
            &self.device_id,
            &self.stream_id,
        ] {
            types::id(value)?;
        }
        let after = types::decimal(&self.after_seq)?;
        let floor = types::decimal(&self.floor)?;
        let high = types::decimal(&self.watermark)?;
        let limit = types::decimal(&self.limit)?;
        if self.protocol_version != "rim-stream-retention-1"
            || after >= floor
            || floor > high
            || !(1..=100).contains(&limit)
        {
            return Err(PermissionError::new(
                "retention_invalid",
                "设备流缺口声明范围无效",
            ));
        }
        Ok(())
    }
}
pub fn verify_retention(
    key: &str,
    receipt: &SignedRecord,
) -> Result<RetentionStatement, PermissionError> {
    let raw = types::bytes(&receipt.statement_bytes, MAX_STATEMENT_BYTES)?;
    let statement: RetentionStatement = serde_json::from_slice(&raw)
        .map_err(|_| PermissionError::new("retention_invalid", "设备流缺口声明字段无效"))?;
    statement.validate()?;
    receipts::signature(key, RETENTION_DOMAIN, &raw, &receipt.signature_bytes)
        .map_err(|_| PermissionError::new("retention_signature", "设备流缺口声明签名无效"))?;
    Ok(statement)
}
