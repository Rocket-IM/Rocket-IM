//! Service 回执只证明固定签名钥的承诺，不替代端侧 MLS 或分叉验证。
use super::{
    check, commit_digest, types, Identity, PermissionCheckpoint, PermissionError, Proof, Statement,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RECEIPT_DOMAIN: &[u8] = b"Rocket-IM/POC/permission-receipt/v1\0";
pub const CLOSE_DOMAIN: &[u8] = b"Rocket-IM/POC/permission-close/v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecord {
    pub statement_bytes: String,
    pub signature_bytes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Accepted,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub actor: Identity,
    pub change_id: String,
    pub proof_sha256: String,
    pub outcome: Outcome,
    pub authorization_version: String,
    pub crypto_state_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub actor: Identity,
    pub change_id: String,
    pub proof_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecord {
    pub change: Proof,
    pub receipt: SignedRecord,
}

pub fn proof_digest(proof: &Proof) -> Result<String, PermissionError> {
    let mut digest = Sha256::new();
    digest.update(b"Rocket-IM/POC/permission-proof/v1\0");
    for (value, limit) in [
        (&proof.statement_bytes, 16 * 1024),
        (&proof.signature_bytes, 64),
        (&proof.commit_bytes, 512 * 1024),
    ] {
        let raw = types::bytes(value, limit)?;
        digest.update((raw.len() as u64).to_be_bytes());
        digest.update(raw);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

pub fn validate_key(encoded: &str) -> Result<ed25519_dalek::VerifyingKey, PermissionError> {
    let key: [u8; 32] = types::bytes(encoded, 32)?
        .try_into()
        .map_err(|_| PermissionError::new("invalid_permission", "签名公钥长度错误"))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| PermissionError::new("invalid_permission", "无效签名公钥"))?;
    check(!key.is_weak(), "invalid_permission", "拒绝弱签名公钥")?;
    Ok(key)
}

pub(crate) fn signature(
    key: &str,
    domain: &[u8],
    raw: &[u8],
    encoded: &str,
) -> Result<(), PermissionError> {
    let sig = ed25519_dalek::Signature::from_slice(&types::bytes(encoded, 64)?)
        .map_err(|_| PermissionError::new("permission_signature", "签名长度错误"))?;
    let mut message = domain.to_vec();
    message.extend(raw);
    validate_key(key)?
        .verify_strict(&message, &sig)
        .map_err(|_| PermissionError::new("permission_signature", "原始声明签名错误"))
}

pub fn authenticate(
    checkpoint: &PermissionCheckpoint,
    proof: &Proof,
) -> Result<Statement, PermissionError> {
    checkpoint.validate()?;
    let raw = types::bytes(&proof.statement_bytes, 16 * 1024)?;
    let statement = Statement::parse(&raw)?;
    check(
        statement.service_id == checkpoint.service_id
            && statement.conversation_id == checkpoint.conversation_id,
        "permission_context",
        "原证明上下文不同",
    )?;
    check(
        types::decimal(&statement.previous_authorization_version)?.checked_add(1)
            == Some(types::decimal(&statement.authorization_version)?)
            && statement.from_state_ref != statement.to_state_ref,
        "permission_version",
        "原证明版本或状态转换无效",
    )?;
    check(
        commit_digest(&types::bytes(&proof.commit_bytes, 512 * 1024)?) == statement.commit_sha256,
        "permission_commit",
        "原证明Commit摘要不同",
    )?;
    let actor = checkpoint
        .members
        .iter()
        .find(|m| m.identity() == statement.actor)
        .ok_or_else(|| PermissionError::new("permission_denied", "原发起设备已无访问权"))?;
    signature(
        &actor.signature_key,
        super::SIGNING_DOMAIN,
        &raw,
        &proof.signature_bytes,
    )?;
    Ok(statement)
}

impl ReceiptStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        check(
            self.protocol_version == "rim-permission-receipt-1",
            "invalid_permission",
            "回执版本不支持",
        )?;
        for value in [
            &self.service_id,
            &self.conversation_id,
            &self.actor.account_id,
            &self.actor.device_id,
            &self.change_id,
        ] {
            types::id(value)?;
        }
        types::hash(&self.proof_sha256)?;
        types::hash(&self.crypto_state_ref)?;
        types::decimal(&self.authorization_version)?;
        Ok(())
    }
}

pub fn verify_receipt(
    key: &str,
    record: &RecoveryRecord,
) -> Result<(ReceiptStatement, Statement), PermissionError> {
    let raw = types::bytes(&record.receipt.statement_bytes, 16 * 1024)?;
    let receipt: ReceiptStatement = serde_json::from_slice(&raw)
        .map_err(|_| PermissionError::new("invalid_permission", "回执字段无效"))?;
    receipt.validate()?;
    signature(key, RECEIPT_DOMAIN, &raw, &record.receipt.signature_bytes)?;
    let proof = Statement::parse(&types::bytes(&record.change.statement_bytes, 16 * 1024)?)?;
    check(
        receipt.service_id == proof.service_id
            && receipt.conversation_id == proof.conversation_id
            && receipt.actor == proof.actor
            && receipt.change_id == proof.change_id
            && receipt.proof_sha256 == proof_digest(&record.change)?,
        "permission_context",
        "回执未绑定精确原证明",
    )?;
    match receipt.outcome {
        Outcome::Accepted => check(
            receipt.authorization_version == proof.authorization_version
                && receipt.crypto_state_ref == proof.to_state_ref,
            "permission_context",
            "接受回执后继与原证明不同",
        )?,
        Outcome::Closed => check(
            types::decimal(&receipt.authorization_version)?
                >= types::decimal(&proof.previous_authorization_version)?,
            "permission_version",
            "封口回执版本早于原候选前驱",
        )?,
    }
    Ok((receipt, proof))
}

pub fn verify_close(
    checkpoint: &PermissionCheckpoint,
    proof: &Proof,
    close: &SignedRecord,
) -> Result<CloseStatement, PermissionError> {
    let original = authenticate(checkpoint, proof)?;
    let raw = types::bytes(&close.statement_bytes, 16 * 1024)?;
    let statement: CloseStatement = serde_json::from_slice(&raw)
        .map_err(|_| PermissionError::new("invalid_permission", "封口声明字段无效"))?;
    check(
        statement.protocol_version == "rim-permission-close-1"
            && statement.service_id == original.service_id
            && statement.conversation_id == original.conversation_id
            && statement.actor == original.actor
            && statement.change_id == original.change_id
            && statement.proof_sha256 == proof_digest(proof)?,
        "permission_context",
        "封口未绑定精确原候选",
    )?;
    let actor = checkpoint
        .members
        .iter()
        .find(|m| m.identity() == statement.actor)
        .ok_or_else(|| PermissionError::new("permission_denied", "封口发起者无访问权"))?;
    signature(
        &actor.signature_key,
        CLOSE_DOMAIN,
        &raw,
        &close.signature_bytes,
    )?;
    Ok(statement)
}
