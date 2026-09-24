//! 重建后继的新消息流授权。只验证固定信任与历史签名事实；当前访问权和锚状态另查。
mod types;
use crate::{
    permission::{
        self,
        receipts::{self, SignedRecord},
        types as fields, PermissionError,
    },
    rollback_anchor::{self as anchor, rebuild},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
pub use types::*;

fn invalid() -> PermissionError {
    PermissionError::new(
        "rebuild_stream_invalid",
        "重建消息流字段、编码、版本或尺寸无效",
    )
}

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

fn anchor_error(error: anchor::AnchorError) -> PermissionError {
    PermissionError::new(error.code, error.message)
}

/// 摘要使用独立域以及两段 u64 大端长度；JSON 保留原始字节，不重新序列化。
/// request、binding、pull 共用此格式，签名域与协议版本负责区分声明种类。
pub fn signed_digest(record: &SignedRecord) -> Result<String, PermissionError> {
    let raw = fields::bytes(&record.statement_bytes, STATEMENT_LIMIT)?;
    let signature = fields::bytes(&record.signature_bytes, 64)?;
    check(
        signature.len() == 64,
        "rebuild_stream_invalid",
        "签名长度必须是64字节",
    )?;
    let mut digest = Sha256::new();
    digest.update(SIGNED_DIGEST_DOMAIN);
    for part in [&raw, &signature] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    Ok(anchor::encode_hex(&digest.finalize()))
}

pub use signed_digest as binding_digest;
pub use signed_digest as pull_digest;
pub use signed_digest as request_digest;

fn parse<T: DeserializeOwned>(record: &SignedRecord) -> Result<(T, Vec<u8>), PermissionError> {
    let raw = fields::bytes(&record.statement_bytes, STATEMENT_LIMIT)?;
    let statement = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    Ok((statement, raw))
}

fn signature(
    key: &str,
    domain: &[u8],
    raw: &[u8],
    record: &SignedRecord,
) -> Result<(), PermissionError> {
    receipts::signature(key, domain, raw, &record.signature_bytes)
        .map_err(|_| PermissionError::new("rebuild_stream_signature", "重建消息流声明签名无效"))
}

fn identity_key(scope: &anchor::Scope) -> Result<String, PermissionError> {
    Ok(STANDARD.encode(anchor::decode_hex(&scope.identity_key).map_err(anchor_error)?))
}

/// 校验固定批准端、唯一后继链接的已签事实和已接受 AddDevice；
/// 不证明链接目前未取消，也不证明客户端已实际应用 Welcome。调用者须另查当前权限。
pub fn verify_registration(
    trusted: &Trust,
    registration: &Registration,
) -> Result<RequestStatement, PermissionError> {
    check(
        serde_json::to_vec(registration)
            .map_err(|_| invalid())?
            .len()
            <= REGISTRATION_LIMIT,
        "resource_exhausted",
        "消息流注册超过1MiB",
    )?;
    trusted.validate()?;
    let plan = &registration.plan;
    plan.validate().map_err(anchor_error)?;
    check(
        plan.old_scope == trusted.old_scope
            && plan.anchor_public_key == trusted.anchor_public_key
            && plan.trust == trusted.trust,
        "rebuild_stream_denied",
        "注册未绑定预固定重建信任",
    )?;
    rebuild::verify_approval(plan, &registration.approval).map_err(anchor_error)?;
    let response = rebuild::verify_rebuild_response(
        &registration.anchor_response,
        &trusted.anchor_public_key,
        plan,
        &registration.anchor_request,
    )
    .map_err(anchor_error)?;
    check(
        !response.cancelled
            && matches!(
                (response.action, response.status),
                (
                    rebuild::Action::Link,
                    rebuild::Status::Linked | rebuild::Status::Duplicate
                ) | (rebuild::Action::Inspect, rebuild::Status::Linked)
            ),
        "rebuild_stream_denied",
        "注册缺少有效后继链接的签名事实",
    )?;
    let (_, joined) =
        permission::verify(&trusted.trust.checkpoint, &registration.join_record.change)?;
    let (receipt, receipted) =
        receipts::verify_receipt(&trusted.trust.relay_receipt_key, &registration.join_record)?;
    check(
        receipt.outcome == receipts::Outcome::Accepted
            && receipted == joined
            && joined.actor == trusted.trust.authorizer.identity(),
        "rebuild_stream_denied",
        "加入证明未经固定批准设备及Service接受",
    )?;
    let key = identity_key(&plan.successor_scope)?;
    check(
        matches!(&joined.action, permission::Action::AddDevice {
        member, key_package_sha256, history_policy, ..
    } if member.account_id == plan.successor_scope.account
        && member.device_id == plan.successor_scope.device
        && member.signature_key == key
        && key_package_sha256 == &plan.key_package_sha256
        && history_policy == "from_join"),
        "rebuild_stream_denied",
        "加入证明未精确授权新设备、公钥、KeyPackage及历史范围",
    )?;
    let (request, raw): (RequestStatement, _) = parse(&registration.request)?;
    request.validate()?;
    check(
        request.plan_sha256 == plan.digest().map_err(anchor_error)?
            && request.successor_scope == plan.successor_scope
            && request.conversation_id == trusted.trust.checkpoint.conversation_id
            && request.join_proof_sha256
                == receipts::proof_digest(&registration.join_record.change)?,
        "rebuild_stream_context",
        "新流请求未绑定重建计划及精确加入证明",
    )?;
    signature(&key, REQUEST_DOMAIN, &raw, &registration.request)?;
    Ok(request)
}

/// 验证 Service 原文签名；客户端仍须与持久注册请求逐项比较。
pub fn verify_binding(
    key: &str,
    binding: &SignedRecord,
) -> Result<BindingStatement, PermissionError> {
    let (statement, raw): (BindingStatement, _) = parse(binding)?;
    statement.validate()?;
    signature(key, BINDING_DOMAIN, &raw, binding)?;
    Ok(statement)
}

/// binding 必须来自已验证或服务端持久记录；调用者另将 binding_sha256
/// 与该完整签名记录的 signed_digest 比较，不能只信任请求自带摘要。
pub fn verify_pull(
    binding: &BindingStatement,
    request: &SignedRecord,
) -> Result<PullStatement, PermissionError> {
    binding.validate()?;
    let (statement, raw): (PullStatement, _) = parse(request)?;
    statement.validate()?;
    check(
        statement.successor_scope == binding.successor_scope
            && statement.conversation_id == binding.conversation_id
            && statement.stream_id == binding.stream_id,
        "rebuild_stream_context",
        "拉取请求与新流授权不符",
    )?;
    signature(
        &identity_key(&binding.successor_scope)?,
        PULL_DOMAIN,
        &raw,
        request,
    )?;
    Ok(statement)
}

/// 客户端另核对活动请求、绑定摘要和 page_bytes 摘要后，才可推进游标。
pub fn verify_page(key: &str, receipt: &SignedRecord) -> Result<PageStatement, PermissionError> {
    let (statement, raw): (PageStatement, _) = parse(receipt)?;
    statement.validate()?;
    signature(key, PAGE_DOMAIN, &raw, receipt)?;
    Ok(statement)
}

pub fn execute(input: &str) -> Result<Value, PermissionError> {
    #[derive(Deserialize)]
    #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
    enum Input {
        VerifyRebuildStream {
            trusted: Box<Trust>,
            registration: Box<Registration>,
        },
        VerifyRebuildPull {
            binding: Box<BindingStatement>,
            request: SignedRecord,
        },
    }
    check(
        input.len() <= REGISTRATION_LIMIT,
        "resource_exhausted",
        "校验输入超过1MiB",
    )?;
    let input: Input = serde_json::from_str(input).map_err(|_| invalid())?;
    let result = match input {
        Input::VerifyRebuildStream {
            trusted,
            registration,
        } => json!({
            "request": verify_registration(&trusted, &registration)?,
            "request_sha256": request_digest(&registration.request)?,
        }),
        Input::VerifyRebuildPull { binding, request } => json!({
            "pull": verify_pull(&binding, &request)?, "request_sha256": pull_digest(&request)?,
        }),
    };
    Ok(json!({"ok":true,"result":result}))
}

#[cfg(test)]
mod tests;
