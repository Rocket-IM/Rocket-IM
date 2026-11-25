//! Q01 独立业务许可、设备批准及目录对照；来源认证不证明全局新鲜度。
pub mod directory;
mod types;
use crate::permission::{
    receipts::{self, SignedRecord},
    types as wire, PermissionError,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use openmls_traits::signatures::Signer;
use serde::Deserialize;
use serde_json::{json, Value};
pub use types::*;
pub const LIMIT: usize = 384 * 1024;
pub fn ensure(ok: bool, code: &'static str) -> Result<(), PermissionError> {
    if ok {
        Ok(())
    } else {
        Err(PermissionError::new(
            code,
            "身份来源、授权或目录证据不满足契约",
        ))
    }
}
pub fn parse(proof: &SignedRecord) -> Result<Document, PermissionError> {
    let raw = wire::bytes(&proof.statement_bytes, LIMIT)?;
    let doc: Document = serde_json::from_slice(&raw)
        .map_err(|_| PermissionError::new("identity_source_invalid", "签名对象字段无效"))?;
    doc.validate()?;
    // 新协议固定字段序与紧凑UTF-8字节；旧协议签名对象不受此规则影响。
    ensure(
        serde_json::to_vec(&doc).ok().as_ref() == Some(&raw),
        "identity_source_encoding",
    )?;
    Ok(doc)
}
pub fn verify(proof: &SignedRecord, key: &str) -> Result<Document, PermissionError> {
    let doc = parse(proof)?;
    receipts::signature(
        key,
        doc.domain(),
        &wire::bytes(&proof.statement_bytes, LIMIT)?,
        &proof.signature_bytes,
    )?;
    Ok(doc)
}
pub fn sign(doc: &Document, signer: &impl Signer) -> Result<SignedRecord, PermissionError> {
    doc.validate()?;
    let raw = serde_json::to_vec(doc)
        .map_err(|_| PermissionError::new("identity_source_encoding", "编码失败"))?;
    ensure(raw.len() <= LIMIT, "resource_exhausted")?;
    let mut message = doc.domain().to_vec();
    message.extend(&raw);
    Ok(SignedRecord {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(
            signer
                .sign(&message)
                .map_err(|_| PermissionError::new("identity_source_signature", "签名失败"))?,
        ),
    })
}
pub(crate) fn execute(input: &str) -> Result<Value, PermissionError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        operation: String,
        proof: SignedRecord,
        key: String,
        roots: Option<Roots>,
    }
    let i: Input = serde_json::from_str(input)
        .map_err(|_| PermissionError::new("identity_source_invalid", "请求无效"))?;
    ensure(
        i.operation == "verify_identity_source",
        "identity_source_invalid",
    )?;
    let doc = verify(&i.proof, &i.key)?;
    if let (Some(roots), Document::Directory(response)) = (&i.roots, &doc) {
        directory::verify_chain(&response.snapshots, roots)?;
    }
    Ok(json!({"ok":true,"result":{"document":doc}}))
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod vector_tests;
