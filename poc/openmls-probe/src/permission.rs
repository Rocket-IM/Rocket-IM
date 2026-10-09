//! 只使用公共检查点验证权限声明，不加载用户目录或解密任何消息。

mod action;
pub mod admission;
pub mod receipts;
pub(crate) mod types;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
pub use types::{Action, Identity, Member, PermissionCheckpoint, Proof, Statement, SIGNING_DOMAIN};

#[derive(Debug)]
pub struct PermissionError {
    pub code: &'static str,
    message: &'static str,
}
impl PermissionError {
    pub(crate) fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
    pub fn response(&self) -> Value {
        json!({"ok":false,"error":{"code":self.code,"message":self.message}})
    }
}
impl fmt::Display for PermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for PermissionError {}
fn check(
    condition: bool,
    code: &'static str,
    message: &'static str,
) -> Result<(), PermissionError> {
    if condition {
        Ok(())
    } else {
        Err(PermissionError::new(code, message))
    }
}

pub fn commit_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 返回下一公共检查点及严格解析后的声明。是否处于当前有效期由首次接受的 Service 检查；
/// 离线接收者仍须能验证过去已接受的链。此函数不证明实际 MLS Commit 可应用。
pub fn verify(
    checkpoint: &PermissionCheckpoint,
    proof: &Proof,
) -> Result<(PermissionCheckpoint, Statement), PermissionError> {
    checkpoint.validate()?;
    let raw = types::bytes(&proof.statement_bytes, 16 * 1024)?;
    let statement = Statement::parse(&raw)?;
    let commit = types::bytes(&proof.commit_bytes, 512 * 1024)?;
    let signature = types::bytes(&proof.signature_bytes, 64)?;
    check(
        statement.service_id == checkpoint.service_id
            && statement.conversation_id == checkpoint.conversation_id,
        "permission_context",
        "权限声明与实例或会话不匹配",
    )?;
    let old_version = types::decimal(&checkpoint.authorization_version)?;
    check(
        statement.previous_authorization_version == checkpoint.authorization_version
            && old_version.checked_add(1)
                == Some(types::decimal(&statement.authorization_version)?),
        "permission_version",
        "权限版本必须准确递增一且不能溢出",
    )?;
    check(
        statement.from_state_ref == checkpoint.crypto_state_ref
            && statement.to_state_ref != statement.from_state_ref,
        "permission_conflict",
        "权限声明前后密码引用与检查点冲突",
    )?;
    let remaining = checkpoint.remaining(&statement.actor, &statement.action)?;
    check(
        commit_digest(&commit) == statement.commit_sha256,
        "permission_commit",
        "Commit 原始字节摘要不匹配",
    )?;
    let signer = checkpoint
        .members
        .iter()
        .find(|member| member.identity() == statement.actor)
        .ok_or_else(|| PermissionError::new("permission_denied", "签名设备不在可信检查点"))?;
    let key: [u8; 32] = types::bytes(&signer.signature_key, 32)?
        .try_into()
        .map_err(|_| PermissionError::new("invalid_permission", "签名公钥长度错误"))?;
    let verifier = VerifyingKey::from_bytes(&key)
        .map_err(|_| PermissionError::new("invalid_permission", "无效签名公钥"))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| PermissionError::new("permission_signature", "签名长度错误"))?;
    let mut signed = SIGNING_DOMAIN.to_vec();
    signed.extend(&raw);
    verifier
        .verify_strict(&signed, &signature)
        .map_err(|_| PermissionError::new("permission_signature", "权限签名验证失败"))?;
    let next = PermissionCheckpoint {
        service_id: checkpoint.service_id.clone(),
        conversation_id: checkpoint.conversation_id.clone(),
        authorization_version: statement.authorization_version.clone(),
        crypto_state_ref: statement.to_state_ref.clone(),
        owner_account_id: checkpoint.owner_account_id.clone(),
        members: remaining,
    };
    Ok((next, statement))
}

pub fn execute(input: &str) -> Result<Value, PermissionError> {
    check(
        input.len() <= 1024 * 1024,
        "resource_exhausted",
        "权限校验输入超过 1 MiB",
    )?;
    #[derive(Deserialize)]
    struct Dispatch {
        operation: Option<String>,
    }
    let dispatch: Dispatch = serde_json::from_str(input)
        .map_err(|_| PermissionError::new("invalid_permission", "校验请求 JSON 无效"))?;
    if let Some(operation) = dispatch.operation {
        return match operation.as_str() {
            "verify_device_registration" => crate::device_registration::execute(input),
            "verify_rebuild_stream" | "verify_rebuild_pull" => {
                crate::rebuild_stream::execute(input)
            }
            _ => crate::history_transfer::execute(input),
        };
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        checkpoint: PermissionCheckpoint,
        change: Proof,
        close: Option<receipts::SignedRecord>,
        #[serde(default, deserialize_with = "admission::present_material")]
        join: Option<admission::JoinMaterial>,
    }
    let request: Request = serde_json::from_str(input)
        .map_err(|_| PermissionError::new("invalid_permission", "权限请求 JSON 无效"))?;
    if let Some(close) = request.close {
        check(
            request.join.is_none(),
            "invalid_join_material",
            "封口不携带入群材料",
        )?;
        let statement = receipts::verify_close(&request.checkpoint, &request.change, &close)?;
        return Ok(json!({"ok":true,"result":{"statement":statement}}));
    }
    let (checkpoint, statement) = verify(&request.checkpoint, &request.change)?;
    if let Some(join) = request.join {
        admission::verify_material(&statement, &join)?;
    }
    Ok(json!({"ok":true,"result":{"checkpoint":checkpoint,"statement":statement}}))
}
