//! 设备注册的私钥持有证明；不证明账号历史或现实联系人身份。
use crate::permission::{receipts, types, PermissionError};
use base64::{engine::general_purpose::STANDARD, Engine};
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const SIGNING_DOMAIN: &[u8] = b"Rocket-IM/POC/device-registration/v1\0";
pub const STATEMENT_LIMIT: usize = 4096;
pub const MAX_VALIDITY_MS: u64 = 300_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub protocol_version: String,
    pub service_id: String,
    pub account_id: String,
    pub device_id: String,
    pub registration_id: String,
    pub signature_key: String,
    pub purpose: String,
    pub challenge_nonce: String,
    pub issued_at_ms: String,
    pub expires_at_ms: String,
}

fn invalid() -> PermissionError {
    PermissionError::new("registration_invalid", "设备注册挑战的字段、编码或范围无效")
}

/// 解析原始挑战，校验规范编码和有界有效期间。
/// 当前有效期、挑战出处、消费与不可改绑由 Service 在接受事务中检查。
pub fn parse_challenge(encoded: &str) -> Result<Challenge, PermissionError> {
    let raw = types::bytes(encoded, STATEMENT_LIMIT).map_err(|_| invalid())?;
    let statement: Challenge = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    if statement.protocol_version != "rim-device-registration-1"
        || statement.purpose != "register_device"
    {
        return Err(invalid());
    }
    for id in [
        &statement.service_id,
        &statement.account_id,
        &statement.device_id,
        &statement.registration_id,
    ] {
        types::id(id).map_err(|_| invalid())?;
    }
    receipts::validate_key(&statement.signature_key).map_err(|_| invalid())?;
    let nonce = types::bytes(&statement.challenge_nonce, 32).map_err(|_| invalid())?;
    if nonce.len() != 32 {
        return Err(invalid());
    }
    let issued = types::decimal(&statement.issued_at_ms).map_err(|_| invalid())?;
    let expires = types::decimal(&statement.expires_at_ms).map_err(|_| invalid())?;
    if !expires
        .checked_sub(issued)
        .is_some_and(|period| period > 0 && period <= MAX_VALIDITY_MS)
    {
        return Err(invalid());
    }
    Ok(statement)
}

/// 验证准确原文及对应身份公钥的 Ed25519 签名，不重新编码签名原文。
/// 有效证明只表达私钥持有；调用者仍需匹配已保存挑战和当前访问权限。
pub fn verify_proof(proof: &receipts::SignedRecord) -> Result<Challenge, PermissionError> {
    let statement = parse_challenge(&proof.statement_bytes)?;
    let raw = types::bytes(&proof.statement_bytes, STATEMENT_LIMIT).map_err(|_| invalid())?;
    receipts::signature(
        &statement.signature_key,
        SIGNING_DOMAIN,
        &raw,
        &proof.signature_bytes,
    )
    .map_err(|_| PermissionError::new("registration_signature", "设备私钥持有证明无效"))?;
    Ok(statement)
}

/// 使用已有设备签名器签准确挑战，调用者须先核对本机实例、账号和设备。
/// 不生成身份钥、不改变 MLS 状态，也不把本机时钟当作接受或幂等依据。
pub fn sign_challenge(
    encoded: &str,
    signer: &impl Signer,
) -> Result<receipts::SignedRecord, PermissionError> {
    parse_challenge(encoded)?;
    let raw = types::bytes(encoded, STATEMENT_LIMIT).map_err(|_| invalid())?;
    let mut message = SIGNING_DOMAIN.to_vec();
    message.extend(raw);
    let signature = signer
        .sign(&message)
        .map_err(|_| PermissionError::new("registration_signature", "设备注册签名失败"))?;
    let proof = receipts::SignedRecord {
        statement_bytes: encoded.to_owned(),
        signature_bytes: STANDARD.encode(signature),
    };
    verify_proof(&proof)?;
    Ok(proof)
}

pub(crate) fn execute(input: &str) -> Result<Value, PermissionError> {
    if input.len() > 1024 * 1024 {
        return Err(PermissionError::new(
            "resource_exhausted",
            "设备注册校验输入超过 1 MiB",
        ));
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        operation: String,
        proof: receipts::SignedRecord,
    }
    let request: Request = serde_json::from_str(input).map_err(|_| invalid())?;
    if request.operation != "verify_device_registration" {
        return Err(invalid());
    }
    let statement = verify_proof(&request.proof)?;
    Ok(json!({"ok":true,"result":{"statement":statement}}))
}

#[cfg(test)]
#[path = "device_registration_tests.rs"]
mod tests;
