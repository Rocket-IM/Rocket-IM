//! 普通设备流的 Service 来源与原始分页完整性证明；不证明最新水位或诚实服务端。
use crate::permission::{
    receipts::{self, SignedRecord},
    types, PermissionError,
};
use serde::{Deserialize, Serialize};

pub const SIGNING_DOMAIN: &[u8] = b"Rockets-IM/POC/stream-page/v1\0";
pub const PAGE_BYTES_LIMIT: usize = 740 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub account_id: String,
    pub device_id: String,
    pub stream_id: String,
    pub after_seq: String,
    pub limit: String,
    pub page_sha256: String,
}

fn invalid() -> PermissionError {
    PermissionError::new("stream_page_invalid", "普通签页字段、编码或版本无效")
}

impl PageStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "RIM-STREAM-PAGE-POC-1" {
            return Err(invalid());
        }
        for id in [
            &self.service_id,
            &self.account_id,
            &self.device_id,
            &self.stream_id,
        ] {
            types::id(id).map_err(|_| invalid())?;
        }
        types::decimal(&self.after_seq).map_err(|_| invalid())?;
        let limit = types::decimal(&self.limit).map_err(|_| invalid())?;
        if !(1..=100).contains(&limit) {
            return Err(invalid());
        }
        types::hash(&self.page_sha256).map_err(|_| invalid())
    }
}

/// 保留声明原始字节验签；调用方还须核对本机范围、页摘要及单调游标。
pub fn verify(key: &str, receipt: &SignedRecord) -> Result<PageStatement, PermissionError> {
    let raw = types::bytes(&receipt.statement_bytes, 16 * 1024).map_err(|_| invalid())?;
    let statement: PageStatement = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    statement.validate()?;
    receipts::signature(key, SIGNING_DOMAIN, &raw, &receipt.signature_bytes)
        .map_err(|_| PermissionError::new("stream_page_signature", "普通设备流签页验签失败"))?;
    Ok(statement)
}

#[cfg(test)]
#[path = "stream_page_tests.rs"]
mod tests;
