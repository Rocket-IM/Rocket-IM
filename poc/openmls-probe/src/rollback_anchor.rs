//! 阶段 0 独立锚契约：签名认证精确请求与单锚事实，不证明硬件或故障域独立。
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod authority;
pub mod rebuild;
mod storage;

pub const PROTOCOL: &str = "rim-rollback-anchor-1";
pub const INPUT_LIMIT: usize = 32 * 1024;
pub const STATEMENT_LIMIT: usize = 8 * 1024;
pub const REQUEST_DOMAIN: &[u8] = b"Rockets-IM/POC/rollback-anchor-request/v1\0";
pub const RESPONSE_DOMAIN: &[u8] = b"Rockets-IM/POC/rollback-anchor-response/v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub service: String,
    pub account: String,
    pub device: String,
    pub identity_key: String,
    pub store_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Reserve,
    Finish,
    Inspect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Reserved,
    ReservedDuplicate,
    Finished,
    FinishedDuplicate,
    Inspected,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Closure {
    Rebuilt,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_version: String,
    pub scope: Scope,
    pub challenge: String,
    pub action: Action,
    pub expected_revision: String,
    pub txn: String,
    pub head: String,
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub protocol_version: String,
    pub scope: Scope,
    pub challenge: String,
    pub request_sha256: String,
    pub action: Action,
    pub status: Status,
    pub head: String,
    pub active_txn: Option<String>,
    /// 十进制无符号计数，用于精确CAS与诊断；不能单独代替完整摘要和事务匹配。
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure: Option<Closure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub statement_bytes: String,
    pub signature_bytes: String,
}

#[derive(Debug, Clone)]
pub struct AnchorError {
    pub code: &'static str,
    pub message: &'static str,
}

impl AnchorError {
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    pub fn response(&self) -> serde_json::Value {
        serde_json::json!({"ok":false,"error":{"code":self.code,"message":self.message}})
    }
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AnchorError {}

fn invalid() -> AnchorError {
    AnchorError::new("anchor_invalid", "锚字段、编码、版本或尺寸无效")
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn decode_hex(value: &str) -> Result<[u8; 32], AnchorError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(bytes)
}

pub fn public_key(seed: &[u8; 32]) -> String {
    encode_hex(SigningKey::from_bytes(seed).verifying_key().as_bytes())
}

pub fn validate_head(head: &str) -> Result<(), AnchorError> {
    if head != "absent" {
        decode_hex(head)?;
    }
    Ok(())
}

pub fn validate_revision(value: &str) -> Result<u64, AnchorError> {
    let revision = value.parse::<u64>().map_err(|_| invalid())?;
    if revision.to_string() != value {
        return Err(invalid());
    }
    Ok(revision)
}

impl Scope {
    pub fn validate(&self) -> Result<(), AnchorError> {
        for value in [&self.service, &self.account, &self.device] {
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                return Err(invalid());
            }
        }
        decode_hex(&self.identity_key)?;
        decode_hex(&self.store_id)?;
        Ok(())
    }
}

impl Request {
    pub fn validate(&self) -> Result<(), AnchorError> {
        if self.protocol_version != PROTOCOL {
            return Err(invalid());
        }
        self.scope.validate()?;
        validate_revision(&self.expected_revision)?;
        decode_hex(&self.challenge)?;
        decode_hex(&self.txn)?;
        validate_head(&self.head)?;
        match self.action {
            Action::Finish => {
                decode_hex(&self.target)?;
            }
            Action::Reserve | Action::Inspect if self.target != "absent" => return Err(invalid()),
            _ => {}
        }
        Ok(())
    }
}

impl Response {
    fn validate(&self) -> Result<(), AnchorError> {
        if self.protocol_version != PROTOCOL {
            return Err(invalid());
        }
        self.scope.validate()?;
        decode_hex(&self.challenge)?;
        decode_hex(&self.request_sha256)?;
        validate_head(&self.head)?;
        if let Some(txn) = &self.active_txn {
            decode_hex(txn)?;
        }
        validate_revision(&self.revision)?;
        let valid_status = matches!(
            (self.action, self.status),
            (_, Status::Conflict)
                | (
                    Action::Reserve,
                    Status::Reserved | Status::ReservedDuplicate
                )
                | (Action::Finish, Status::Finished | Status::FinishedDuplicate)
                | (Action::Inspect, Status::Inspected)
        );
        if !valid_status {
            return Err(invalid());
        }
        Ok(())
    }
}

fn decode_base64(value: &str, limit: usize) -> Result<Vec<u8>, AnchorError> {
    if value.len() > limit.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = STANDARD.decode(value).map_err(|_| invalid())?;
    if bytes.len() > limit || STANDARD.encode(&bytes) != value {
        return Err(invalid());
    }
    Ok(bytes)
}

fn sign<T: Serialize>(value: &T, seed: &[u8; 32], domain: &[u8]) -> Result<Signed, AnchorError> {
    let raw = serde_json::to_vec(value).map_err(|_| invalid())?;
    if raw.len() > STATEMENT_LIMIT {
        return Err(invalid());
    }
    let mut message = domain.to_vec();
    message.extend(&raw);
    Ok(Signed {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(SigningKey::from_bytes(seed).sign(&message).to_bytes()),
    })
}

fn verify<T: DeserializeOwned>(
    signed: &Signed,
    key: &str,
    domain: &[u8],
) -> Result<T, AnchorError> {
    let raw = decode_base64(&signed.statement_bytes, STATEMENT_LIMIT)?;
    let signature = decode_base64(&signed.signature_bytes, 64)?;
    let signature = Signature::from_slice(&signature).map_err(|_| invalid())?;
    let key = VerifyingKey::from_bytes(&decode_hex(key)?).map_err(|_| invalid())?;
    let mut message = domain.to_vec();
    message.extend(&raw);
    key.verify_strict(&message, &signature)
        .map_err(|_| AnchorError::new("anchor_signature", "锚声明原文签名无效"))?;
    serde_json::from_slice(&raw).map_err(|_| invalid())
}

pub fn sign_request(request: &Request, seed: &[u8; 32]) -> Result<Signed, AnchorError> {
    request.validate()?;
    sign(request, seed, REQUEST_DOMAIN)
}

pub fn verify_request(signed: &Signed, key: &str) -> Result<Request, AnchorError> {
    let request: Request = verify(signed, key, REQUEST_DOMAIN)?;
    request.validate()?;
    Ok(request)
}

pub fn request_digest(signed: &Signed) -> Result<String, AnchorError> {
    Ok(hash_bytes(
        &serde_json::to_vec(signed).map_err(|_| invalid())?,
    ))
}

pub fn sign_response(response: &Response, seed: &[u8; 32]) -> Result<Signed, AnchorError> {
    response.validate()?;
    sign(response, seed, RESPONSE_DOMAIN)
}

/// 响应必须对应调用方仍持有的本次原请求；调用方另行判断 head、active 及状态许可。
pub fn verify_response(
    signed: &Signed,
    key: &str,
    request: &Signed,
) -> Result<Response, AnchorError> {
    let response: Response = verify(signed, key, RESPONSE_DOMAIN)?;
    response.validate()?;
    let raw = decode_base64(&request.statement_bytes, STATEMENT_LIMIT)?;
    let original: Request = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    original.validate()?;
    if response.request_sha256 != request_digest(request)?
        || response.challenge != original.challenge
        || response.scope != original.scope
        || response.action != original.action
    {
        return Err(AnchorError::new(
            "anchor_response_binding",
            "锚响应不属于本次请求及范围",
        ));
    }
    Ok(response)
}

#[cfg(test)]
#[path = "rollback_anchor_tests.rs"]
mod tests;
