//! 固定 Service 公钥的检查点观察；签名不证明全局最新或没有向其他设备分叉。
use crate::permission::{
    receipts::{self, SignedRecord},
    types, Identity, PermissionCheckpoint, PermissionError,
};
use serde::{Deserialize, Serialize};

pub const SIGNING_DOMAIN: &[u8] = b"Rockets-IM/POC/consistency-head/v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub actor: Identity,
    pub challenge: String,
    pub checkpoint: PermissionCheckpoint,
}

impl HeadStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-consistency-head-1" {
            return Err(PermissionError::new(
                "invalid_consistency",
                "检查点观察协议不支持",
            ));
        }
        for value in [
            &self.service_id,
            &self.conversation_id,
            &self.actor.account_id,
            &self.actor.device_id,
        ] {
            types::id(value)?;
        }
        types::hash(&self.challenge)?;
        self.checkpoint.validate()?;
        if !self
            .checkpoint
            .members
            .iter()
            .any(|member| member.identity() == self.actor)
        {
            return Err(PermissionError::new(
                "invalid_consistency",
                "观察签发对象不在声明的检查点成员中",
            ));
        }
        if self.service_id != self.checkpoint.service_id
            || self.conversation_id != self.checkpoint.conversation_id
        {
            return Err(PermissionError::new(
                "consistency_context",
                "观察与检查点范围不一致",
            ));
        }
        Ok(())
    }
}

pub fn verify(key: &str, head: &SignedRecord) -> Result<HeadStatement, PermissionError> {
    let raw = types::bytes(&head.statement_bytes, 16 * 1024)?;
    let statement: HeadStatement = serde_json::from_slice(&raw)
        .map_err(|_| PermissionError::new("invalid_consistency", "观察声明字段无效"))?;
    statement.validate()?;
    receipts::signature(key, SIGNING_DOMAIN, &raw, &head.signature_bytes)
        .map_err(|_| PermissionError::new("consistency_signature", "观察签名无效"))?;
    Ok(statement)
}
