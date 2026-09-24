//! 合成本地锚 wire 契约；签名证明请求与锚声明，不证明生产故障域独立。
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::{validate_id, ApiError};

pub(super) const PROTOCOL: &str = "rim-rollback-anchor-1";
pub(super) const INPUT_LIMIT: usize = 32 * 1024;
const STATEMENT_LIMIT: usize = 8 * 1024;
const REQUEST_DOMAIN: &[u8] = b"Rockets-IM/POC/rollback-anchor-request/v1\0";
const RESPONSE_DOMAIN: &[u8] = b"Rockets-IM/POC/rollback-anchor-response/v1\0";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    pub service: String,
    pub account: String,
    pub device: String,
    pub identity_key: String,
    pub store_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Action {
    Reserve,
    Finish,
    Inspect,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Reserved,
    ReservedDuplicate,
    Finished,
    FinishedDuplicate,
    Inspected,
    Conflict,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Closure {
    Rebuilt,
    Cancelled,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub protocol_version: String,
    pub scope: Scope,
    pub challenge: String,
    pub action: Action,
    pub expected_revision: String,
    pub txn: String,
    pub head: String,
    pub target: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Response {
    pub protocol_version: String,
    pub scope: Scope,
    pub challenge: String,
    pub request_sha256: String,
    pub action: Action,
    pub status: Status,
    pub head: String,
    pub active_txn: Option<String>,
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure: Option<Closure>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Signed {
    pub statement_bytes: String,
    pub signature_bytes: String,
}

pub(super) fn invalid() -> ApiError {
    ApiError::new("anchor_invalid", "锚字段、编码、版本或尺寸无效。", false)
}

pub(super) fn hash_bytes(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn decode_hex(value: &str) -> Result<[u8; 32], ApiError> {
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

pub(super) fn random_hex() -> Result<String, ApiError> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| ApiError::new("anchor_random", "无法取得锚请求所需随机数。", false))?;
    Ok(encode_hex(&bytes))
}

fn validate_head(value: &str) -> Result<(), ApiError> {
    if value != "absent" {
        decode_hex(value)?;
    }
    Ok(())
}

fn validate_revision(value: &str) -> Result<(), ApiError> {
    crate::protocol::parse_revision(value).map_err(|_| invalid())?;
    Ok(())
}

impl Scope {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        validate_id(&self.service).map_err(|_| invalid())?;
        validate_id(&self.account).map_err(|_| invalid())?;
        validate_id(&self.device).map_err(|_| invalid())?;
        decode_hex(&self.identity_key)?;
        decode_hex(&self.store_id)?;
        Ok(())
    }
}

impl Request {
    fn validate(&self) -> Result<(), ApiError> {
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
    fn validate(&self) -> Result<(), ApiError> {
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
        if !matches!(
            (self.action, self.status),
            (_, Status::Conflict)
                | (
                    Action::Reserve,
                    Status::Reserved | Status::ReservedDuplicate
                )
                | (Action::Finish, Status::Finished | Status::FinishedDuplicate)
                | (Action::Inspect, Status::Inspected)
        ) {
            return Err(invalid());
        }
        Ok(())
    }
}

fn decode_base64(value: &str, limit: usize) -> Result<Vec<u8>, ApiError> {
    if value.len() > limit.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = STANDARD.decode(value).map_err(|_| invalid())?;
    if bytes.len() > limit || STANDARD.encode(&bytes) != value {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(super) fn sign<T: Serialize>(
    value: &T,
    key: &SigningKey,
    domain: &[u8],
) -> Result<Signed, ApiError> {
    let raw = serde_json::to_vec(value).map_err(|_| invalid())?;
    if raw.len() > STATEMENT_LIMIT {
        return Err(invalid());
    }
    let mut message = domain.to_vec();
    message.extend(&raw);
    Ok(Signed {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(key.sign(&message).to_bytes()),
    })
}

pub(super) fn verify<T: DeserializeOwned>(
    signed: &Signed,
    key: &str,
    domain: &[u8],
) -> Result<T, ApiError> {
    let raw = decode_base64(&signed.statement_bytes, STATEMENT_LIMIT)?;
    let signature = decode_base64(&signed.signature_bytes, 64)?;
    let signature = Signature::from_slice(&signature).map_err(|_| invalid())?;
    let key = VerifyingKey::from_bytes(&decode_hex(key)?).map_err(|_| invalid())?;
    let mut message = domain.to_vec();
    message.extend(&raw);
    key.verify_strict(&message, &signature)
        .map_err(|_| ApiError::new("anchor_signature", "锚声明原文签名无效。", false))?;
    serde_json::from_slice(&raw).map_err(|_| invalid())
}

pub(super) fn sign_request(request: &Request, key: &SigningKey) -> Result<Signed, ApiError> {
    request.validate()?;
    sign(request, key, REQUEST_DOMAIN)
}

/// 新挑战与原请求摘要阻止响应串用；head、active_txn 和许可状态由协调层判定。
pub(super) fn verify_response(
    signed: &Signed,
    key: &str,
    request: &Signed,
) -> Result<Response, ApiError> {
    let response: Response = verify(signed, key, RESPONSE_DOMAIN)?;
    response.validate()?;
    let raw = decode_base64(&request.statement_bytes, STATEMENT_LIMIT)?;
    let original: Request = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    original.validate()?;
    let request_hash = hash_bytes(&serde_json::to_vec(request).map_err(|_| invalid())?);
    if response.request_sha256 != request_hash
        || response.challenge != original.challenge
        || response.scope != original.scope
        || response.action != original.action
    {
        return Err(ApiError::new(
            "anchor_response_binding",
            "锚响应不属于本次请求及范围。",
            false,
        ));
    }
    if response.closure.is_some() {
        return Err(ApiError::new("anchor_closed", "锚范围已经封闭。", false));
    }
    Ok(response)
}
