//! 公共迁移证明校验；不读取端目录，也不解密历史正文。
mod types;
use crate::permission::{
    receipts::{self, SignedRecord},
    Identity, PermissionCheckpoint, PermissionError,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
pub use types::*;
use types::{check, invalid};

fn digest(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    for raw in parts {
        hash.update((raw.len() as u64).to_be_bytes());
        hash.update(raw);
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
pub fn request_digest(request: &SignedRecord) -> Result<String, PermissionError> {
    let raw = bytes(&request.statement_bytes, 16 * 1024)?;
    let signature = bytes(&request.signature_bytes, 64)?;
    Ok(digest(
        b"Rocket-IM/POC/history-request-digest/v1\0",
        &[&raw, &signature],
    ))
}
pub fn ciphertext_digest(kem: &[u8], ciphertext: &[u8]) -> String {
    digest(b"Rocket-IM/POC/history-ciphertext/v1\0", &[kem, ciphertext])
}
pub fn package_digest(package: &Package) -> Result<String, PermissionError> {
    let raw = bytes(&package.statement_bytes, 16 * 1024)?;
    let signature = bytes(&package.signature_bytes, 64)?;
    let kem = bytes(&package.kem_output, 32)?;
    let ciphertext = bytes(&package.ciphertext, MAX_BODY + 16)?;
    Ok(digest(
        b"Rocket-IM/POC/history-package-digest/v1\0",
        &[&raw, &signature, &kem, &ciphertext],
    ))
}
pub fn hpke_info(request: &SignedRecord) -> Result<Vec<u8>, PermissionError> {
    let hash = request_digest(request)?;
    let mut info = b"Rocket-IM/POC/history-hpke/v1\0".to_vec();
    // 摘要由上面的固定实现生成，仅转换为32个原始字节。
    for i in (0..hash.len()).step_by(2) {
        info.push(u8::from_str_radix(&hash[i..i + 2], 16).map_err(|_| invalid())?);
    }
    Ok(info)
}
fn member_key<'a>(
    cp: &'a PermissionCheckpoint,
    identity: &Identity,
) -> Result<&'a str, PermissionError> {
    cp.members
        .iter()
        .find(|m| m.identity() == *identity)
        .map(|m| m.signature_key.as_str())
        .ok_or_else(|| PermissionError::new("history_denied", "迁移设备不属于当前检查点"))
}
fn signature(key: &str, domain: &[u8], raw: &[u8], signature: &str) -> Result<(), PermissionError> {
    receipts::signature(key, domain, raw, signature)
        .map_err(|_| PermissionError::new("history_signature", "历史迁移签名无效"))
}
pub fn verify_request(
    cp: &PermissionCheckpoint,
    request: &SignedRecord,
) -> Result<RequestStatement, PermissionError> {
    cp.validate()?;
    let raw = bytes(&request.statement_bytes, 16 * 1024)?;
    let statement: RequestStatement = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    statement.validate()?;
    check(
        statement.service_id == cp.service_id
            && statement.conversation_id == cp.conversation_id
            && statement.authorization_version == cp.authorization_version
            && statement.crypto_state_ref == cp.crypto_state_ref,
        "history_context",
        "历史迁移请求不属于当前群检查点",
    )?;
    member_key(cp, &statement.source)?;
    signature(
        member_key(cp, &statement.target)?,
        REQUEST_DOMAIN,
        &raw,
        &request.signature_bytes,
    )?;
    Ok(statement)
}
pub fn verify(
    cp: &PermissionCheckpoint,
    request: &SignedRecord,
    package: &Package,
) -> Result<(RequestStatement, PackageStatement), PermissionError> {
    let request_statement = verify_request(cp, request)?;
    let raw = bytes(&package.statement_bytes, 16 * 1024)?;
    let statement: PackageStatement = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    statement.validate()?;
    let kem = bytes(&package.kem_output, 32)?;
    let ciphertext = bytes(&package.ciphertext, MAX_BODY + 16)?;
    check(
        kem.len() == 32 && ciphertext.len() >= 16,
        "history_invalid",
        "HPKE输出长度无效",
    )?;
    check(
        statement.transfer_id == request_statement.transfer_id
            && statement.request_sha256 == request_digest(request)?
            && statement.ciphertext_sha256 == ciphertext_digest(&kem, &ciphertext),
        "history_context",
        "历史包与精确请求或密文不匹配",
    )?;
    signature(
        member_key(cp, &request_statement.source)?,
        PACKAGE_DOMAIN,
        &raw,
        &package.signature_bytes,
    )?;
    Ok((request_statement, statement))
}
pub fn verify_receipt(
    key: &str,
    request: &SignedRecord,
    package: &Package,
    receipt: &SignedRecord,
) -> Result<ReceiptStatement, PermissionError> {
    let raw = bytes(&receipt.statement_bytes, 16 * 1024)?;
    let statement: ReceiptStatement = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    statement.validate()?;
    signature(key, RECEIPT_DOMAIN, &raw, &receipt.signature_bytes)?;
    let r: RequestStatement = serde_json::from_slice(&bytes(&request.statement_bytes, 16 * 1024)?)
        .map_err(|_| invalid())?;
    check(
        statement.service_id == r.service_id
            && statement.conversation_id == r.conversation_id
            && statement.transfer_id == r.transfer_id
            && statement.authorization_version == r.authorization_version
            && statement.crypto_state_ref == r.crypto_state_ref
            && statement.expires_at_unix_secs == r.expires_at_unix_secs
            && statement.request_sha256 == request_digest(request)?
            && statement.package_sha256 == package_digest(package)?
            && decimal(&statement.accepted_at_unix_ms)? / 1000 >= decimal(&r.issued_at_unix_secs)?,
        "history_context",
        "Service回执未绑定此请求与完整包",
    )?;
    Ok(statement)
}
pub fn execute(input: &str) -> Result<Value, PermissionError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Operation {
        VerifyHistoryTransfer,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        operation: Operation,
        checkpoint: PermissionCheckpoint,
        request: SignedRecord,
        package: Package,
    }
    check(
        input.len() <= 1024 * 1024,
        "resource_exhausted",
        "校验输入超过1MiB",
    )?;
    let input: Input = serde_json::from_str(input).map_err(|_| invalid())?;
    let Operation::VerifyHistoryTransfer = input.operation;
    let (request, package) = verify(&input.checkpoint, &input.request, &input.package)?;
    Ok(
        json!({"ok":true,"result":{"request":request,"package":package,
        "request_sha256":request_digest(&input.request)?,"package_sha256":package_digest(&input.package)?}}),
    )
}
