//! 独立批准的启动配置；启动权威与离线批准根不得与业务/Service/锚根混用。
pub mod authority;
mod storage;
#[cfg(test)]
mod tests;
use crate::{
    identity_source::Roots,
    permission::{
        receipts::{self, SignedRecord},
        types, PermissionError,
    },
    rollback_anchor::Scope,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub const LIMIT: usize = 24 * 1024;
pub const APPROVAL_DOMAIN: &[u8] = b"Rocket-IM/POC/startup-approval/v1\0";
pub const RESPONSE_DOMAIN: &[u8] = b"Rocket-IM/POC/startup-response/v1\0";
pub type Result<T> = std::result::Result<T, PermissionError>;
pub fn check(value: bool, code: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(PermissionError::new(
            code,
            "可信启动配置、批准或当前代次不满足契约",
        ))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub protocol_version: String,
    pub slot: String,
    pub generation: String,
    pub roots: Roots,
    pub scope: Scope,
    pub anchor_public_key: String,
    pub anchor_config_sha256: String,
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        check(
            self.protocol_version == "rim-startup-manifest-1",
            "startup_version",
        )?;
        types::id(&self.slot)?;
        check(types::decimal(&self.generation)? > 0, "startup_generation")?;
        self.roots.validate()?;
        for id in [&self.scope.service, &self.scope.account, &self.scope.device] {
            types::id(id)?;
        }
        check(self.scope.service == self.roots.service_id, "startup_scope")?;
        for hash in [
            &self.scope.identity_key,
            &self.scope.store_id,
            &self.anchor_public_key,
            &self.anchor_config_sha256,
        ] {
            types::hash(hash)?;
        }
        let anchor = STANDARD.encode(
            crate::rollback_anchor::decode_hex(&self.anchor_public_key).map_err(|_| error())?,
        );
        receipts::validate_key(&anchor)?;
        check(
            anchor != self.roots.business_key && anchor != self.roots.receipt_key,
            "startup_root_separation",
        )
    }
    pub fn hash(&self) -> Result<String> {
        self.validate()?;
        hash(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub protocol_version: String,
    pub slot: String,
    pub previous_generation: String,
    pub previous_sha256: String,
    pub action: String,
    pub manifest: Option<Manifest>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub protocol_version: String,
    pub slot: String,
    pub challenge: String,
    pub generation: String,
    pub manifest_sha256: String,
    pub disabled: bool,
}
pub fn error() -> PermissionError {
    PermissionError::new("startup_invalid", "启动对象无效")
}
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(value).map_err(|_| error())?;
    check(raw.len() <= LIMIT, "startup_limit")?;
    Ok(raw)
}
pub fn hash<T: Serialize>(value: &T) -> Result<String> {
    Ok(crate::permission::commit_digest(&encode(value)?))
}
pub fn sign<T: Serialize>(value: &T, domain: &[u8], seed: &str) -> Result<SignedRecord> {
    let seed = crate::rollback_anchor::decode_hex(seed).map_err(|_| error())?;
    let raw = encode(value)?;
    let mut input = domain.to_vec();
    input.extend(&raw);
    Ok(SignedRecord {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(SigningKey::from_bytes(&seed).sign(&input).to_bytes()),
    })
}
pub fn verify<T: Serialize + DeserializeOwned>(
    proof: &SignedRecord,
    domain: &[u8],
    key: &str,
) -> Result<T> {
    let raw = types::bytes(&proof.statement_bytes, LIMIT)?;
    receipts::signature(key, domain, &raw, &proof.signature_bytes)?;
    let value: T = serde_json::from_slice(&raw).map_err(|_| error())?;
    check(encode(&value)? == raw, "startup_encoding")?;
    Ok(value)
}
pub fn public(seed: &str) -> Result<String> {
    let seed = crate::rollback_anchor::decode_hex(seed).map_err(|_| error())?;
    Ok(STANDARD.encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes()))
}
