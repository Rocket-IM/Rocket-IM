//! 公开证据交换只认证来源及范围，不证明渠道独立、远端 MLS 或全局新鲜度。
use crate::permission::{
    receipts::{self, RecoveryRecord, SignedRecord},
    types, Identity, PermissionCheckpoint, PermissionError,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REQUEST_DOMAIN: &[u8] = b"Rockets-IM/POC/consistency-exchange-request/v1\0";
pub const PACKAGE_DOMAIN: &[u8] = b"Rockets-IM/POC/consistency-exchange-package/v1\0";
pub const REQUEST_LIMIT: usize = 16 * 1024;
pub const PACKAGE_LIMIT: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    ManualInPerson,
    SyntheticLocal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub source: Identity,
    pub target: Identity,
    pub source_fingerprint: String,
    pub target_fingerprint: String,
    pub challenge: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub source: Identity,
    pub target: Identity,
    pub challenge: String,
    pub request_sha256: String,
    pub predecessor: PermissionCheckpoint,
    pub record: RecoveryRecord,
}

fn invalid(_error: impl std::fmt::Display) -> PermissionError {
    PermissionError::new("exchange_invalid", "对照字段、编码、尺寸或 JSON 无效")
}

fn scope(
    service: &str,
    conversation: &str,
    source: &Identity,
    target: &Identity,
) -> Result<(), PermissionError> {
    for id in [
        service,
        conversation,
        &source.account_id,
        &source.device_id,
        &target.account_id,
        &target.device_id,
    ] {
        types::id(id).map_err(invalid)?;
    }
    if source == target {
        return Err(invalid("对照双方必须是不同设备"));
    }
    Ok(())
}

pub fn fingerprint(key: &str) -> Result<String, PermissionError> {
    Ok(hash_bytes(receipts::validate_key(key)?.as_bytes()))
}

fn hash_bytes(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 固定 SignedRecord 字段次序；原声明原文作为字符串保留，不重编码签名原文。
pub fn request_digest(request: &SignedRecord) -> Result<String, PermissionError> {
    Ok(hash_bytes(&serde_json::to_vec(request).map_err(invalid)?))
}

fn parse<T: DeserializeOwned>(signed: &SignedRecord, limit: usize) -> Result<T, PermissionError> {
    let raw = types::bytes(&signed.statement_bytes, limit).map_err(invalid)?;
    serde_json::from_slice(&raw).map_err(invalid)
}

pub fn parse_request(request: &SignedRecord) -> Result<RequestStatement, PermissionError> {
    let statement: RequestStatement = parse(request, REQUEST_LIMIT)?;
    if statement.protocol_version != "rim-consistency-exchange-request-1" {
        return Err(invalid("对照请求协议不支持"));
    }
    scope(
        &statement.service_id,
        &statement.conversation_id,
        &statement.source,
        &statement.target,
    )?;
    for value in [
        &statement.source_fingerprint,
        &statement.target_fingerprint,
        &statement.challenge,
    ] {
        types::hash(value).map_err(invalid)?;
    }
    Ok(statement)
}

pub fn parse_package(package: &SignedRecord) -> Result<PackageStatement, PermissionError> {
    let statement: PackageStatement = parse(package, PACKAGE_LIMIT)?;
    if statement.protocol_version != "rim-consistency-exchange-package-1" {
        return Err(invalid("对照证据包协议不支持"));
    }
    scope(
        &statement.service_id,
        &statement.conversation_id,
        &statement.source,
        &statement.target,
    )?;
    types::hash(&statement.challenge).map_err(invalid)?;
    types::hash(&statement.request_sha256).map_err(invalid)?;
    statement.predecessor.validate()?;
    Ok(statement)
}

pub fn verify_signature(
    key: &str,
    domain: &[u8],
    signed: &SignedRecord,
    limit: usize,
) -> Result<(), PermissionError> {
    let raw = types::bytes(&signed.statement_bytes, limit).map_err(invalid)?;
    receipts::signature(key, domain, &raw, &signed.signature_bytes)
        .map_err(|_| PermissionError::new("exchange_signature", "对照原始声明签名无效"))
}
