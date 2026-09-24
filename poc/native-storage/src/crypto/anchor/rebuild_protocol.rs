//! 复用既有 helper 的重建计划与签名域；公开检查点的格式校验不建立信任。
use super::{
    protocol::{self, Scope, Signed, STATEMENT_LIMIT},
    signatures,
};
use crate::{
    crypto::model::Identity,
    model::{Error, Result},
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) const PROTOCOL: &str = "rim-anchor-rebuild-1";
pub(crate) const APPROVAL_DOMAIN: &[u8] = b"Rocket-IM/POC/anchor-rebuild-approval/v1\0";
pub(crate) const ADMISSION_DOMAIN: &[u8] = b"Rocket-IM/native-rebuild-add-admission/v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Member {
    pub account_id: String,
    pub device_id: String,
    pub signature_key: String,
}
impl Member {
    pub(crate) fn from_identity(identity: &Identity) -> Self {
        Self {
            account_id: identity.account.clone(),
            device_id: identity.device.clone(),
            signature_key: identity.identity_key.clone(),
        }
    }
    pub(crate) fn identity_key(&self) -> Result<String> {
        public_key(&self.signature_key)
    }
    pub(crate) fn identity(&self) -> (&str, &str) {
        (&self.account_id, &self.device_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub service_id: String,
    pub conversation_id: String,
    pub authorization_version: String,
    pub crypto_state_ref: String,
    pub owner_account_id: String,
    pub members: Vec<Member>,
}
impl Checkpoint {
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [
            &self.service_id,
            &self.conversation_id,
            &self.owner_account_id,
        ] {
            id(value)?;
        }
        protocol::revision(&self.authorization_version)?;
        protocol::decode_hex(&self.crypto_state_ref)?;
        if !(2..=6).contains(&self.members.len()) {
            return Err(protocol::invalid());
        }
        let mut keys = BTreeSet::new();
        for member in &self.members {
            id(&member.account_id)?;
            id(&member.device_id)?;
            if !keys.insert(member.identity_key()?) {
                return Err(protocol::invalid());
            }
        }
        if !self
            .members
            .windows(2)
            .all(|pair| pair[0].identity() < pair[1].identity())
            || !self
                .members
                .iter()
                .any(|member| member.account_id == self.owner_account_id)
        {
            return Err(protocol::invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RebuildTrust {
    pub authorizer: Member,
    pub checkpoint: Checkpoint,
    pub relay_receipt_key: String,
}
impl RebuildTrust {
    pub(crate) fn validate(&self, old: &Scope) -> Result<()> {
        self.checkpoint.validate()?;
        public_key(&self.relay_receipt_key)?;
        let key = self.authorizer.identity_key()?;
        if self.checkpoint.service_id != old.service
            || self.authorizer.account_id != old.account
            || self.authorizer.device_id == old.device
            || key == old.identity_key
            || !self.checkpoint.members.contains(&self.authorizer)
            || self.checkpoint.members.iter().any(|member| {
                (member.account_id == old.account && member.device_id == old.device)
                    || member.identity_key().ok().as_ref() == Some(&old.identity_key)
            })
        {
            return Err(denied());
        }
        Ok(())
    }
}

// 字段顺序也是 helper 的 JSON 签名与 plan digest 契约，不能按名称重排。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub protocol_version: String,
    pub rebuild_id: String,
    pub old_scope: Scope,
    pub old_head: String,
    pub old_txn: String,
    pub old_revision: String,
    pub old_conversation_id: String,
    pub old_group_id: String,
    pub anchor_public_key: String,
    pub successor_scope: Scope,
    pub successor_head: String,
    pub successor_client_public_key: String,
    pub key_package_sha256: String,
    pub trust: RebuildTrust,
}
impl Plan {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL {
            return Err(protocol::invalid());
        }
        self.old_scope.validate()?;
        self.successor_scope.validate()?;
        for value in [
            &self.successor_scope.service,
            &self.successor_scope.account,
            &self.successor_scope.device,
            &self.old_conversation_id,
        ] {
            id(value)?;
        }
        self.trust.validate(&self.old_scope)?;
        if signatures::decode(&self.old_group_id, 128)?.is_empty()
            || self.old_conversation_id == self.trust.checkpoint.conversation_id
        {
            return Err(denied());
        }
        for value in [
            &self.rebuild_id,
            &self.old_head,
            &self.old_txn,
            &self.anchor_public_key,
            &self.successor_head,
            &self.successor_client_public_key,
            &self.key_package_sha256,
        ] {
            protocol::decode_hex(value)?;
        }
        if protocol::revision(&self.old_revision)? == 0
            || self.old_scope.service != self.successor_scope.service
            || self.old_scope.account != self.successor_scope.account
            || self.old_scope.device == self.successor_scope.device
            || self.old_scope.identity_key == self.successor_scope.identity_key
            || self.old_scope.store_id == self.successor_scope.store_id
            || self.old_head == self.successor_head
            || self.trust.checkpoint.members.iter().any(|member| {
                (member.account_id == self.successor_scope.account
                    && member.device_id == self.successor_scope.device)
                    || member.identity_key().ok().as_ref()
                        == Some(&self.successor_scope.identity_key)
            })
        {
            return Err(denied());
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(protocol::hash(&serialized(self)?))
    }
}

pub(crate) fn approval_signing_bytes(plan: &Plan) -> Result<Vec<u8>> {
    plan.validate()?;
    signing_bytes(plan, APPROVAL_DOMAIN)
}
pub(crate) fn verify_approval(plan: &Plan, signed: &Signed) -> Result<()> {
    plan.validate()?;
    let approved: Plan = signatures::verify(
        signed,
        &plan.trust.authorizer.identity_key()?,
        APPROVAL_DOMAIN,
        STATEMENT_LIMIT,
    )?;
    if approved != *plan {
        return Err(denied());
    }
    Ok(())
}

/// 原生已提交 Add 的设备证明。它不冒充旧 Relay RecoveryRecord。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddAdmission {
    pub plan_sha256: String,
    pub checkpoint_before: Checkpoint,
    pub checkpoint_after: Checkpoint,
    pub successor_identity: Identity,
    pub group_id: String,
    pub welcome_sha256: String,
    pub commit_sha256: String,
    pub history_policy: String,
    pub approver: Member,
}
impl AddAdmission {
    pub(crate) fn validate(&self, plan: &Plan) -> Result<()> {
        let digest = plan.digest()?;
        self.checkpoint_before.validate()?;
        self.checkpoint_after.validate()?;
        protocol::decode_hex(&self.welcome_sha256)?;
        protocol::decode_hex(&self.commit_sha256)?;
        let successor = Member::from_identity(&self.successor_identity);
        let mut expected = self.checkpoint_before.members.clone();
        expected.push(successor.clone());
        expected.sort_by(|left, right| left.identity().cmp(&right.identity()));
        let version = protocol::revision(&self.checkpoint_before.authorization_version)?;
        if self.plan_sha256 != digest
            || self.checkpoint_before != plan.trust.checkpoint
            || self.approver != plan.trust.authorizer
            || self.history_policy != "from_join"
            || self.successor_identity.service != plan.successor_scope.service
            || successor.account_id != plan.successor_scope.account
            || successor.device_id != plan.successor_scope.device
            || successor.identity_key()? != plan.successor_scope.identity_key
            || protocol::hash(&signatures::decode(
                &self.successor_identity.key_package,
                64 * 1024,
            )?) != plan.key_package_sha256
            || self.successor_identity.key_package.is_empty()
            || signatures::decode(&self.group_id, 256)?.is_empty()
            || self.group_id == plan.old_group_id
            || self.checkpoint_after.service_id != self.checkpoint_before.service_id
            || self.checkpoint_after.conversation_id != self.checkpoint_before.conversation_id
            || self.checkpoint_after.owner_account_id != self.checkpoint_before.owner_account_id
            || self.checkpoint_after.crypto_state_ref == self.checkpoint_before.crypto_state_ref
            || version.checked_add(1)
                != Some(protocol::revision(
                    &self.checkpoint_after.authorization_version,
                )?)
            || self.checkpoint_after.members != expected
        {
            return Err(denied());
        }
        Ok(())
    }
}
pub(crate) fn admission_signing_bytes(admission: &AddAdmission, plan: &Plan) -> Result<Vec<u8>> {
    admission.validate(plan)?;
    signing_bytes(admission, ADMISSION_DOMAIN)
}
pub(crate) fn verify_admission(plan: &Plan, signed: &Signed) -> Result<AddAdmission> {
    let admission: AddAdmission = signatures::verify(
        signed,
        &plan.trust.authorizer.identity_key()?,
        ADMISSION_DOMAIN,
        STATEMENT_LIMIT,
    )?;
    admission.validate(plan)?;
    Ok(admission)
}
fn serialized<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(value).map_err(|_| protocol::invalid())?;
    if raw.len() > STATEMENT_LIMIT {
        return Err(protocol::invalid());
    }
    Ok(raw)
}
fn signing_bytes<T: Serialize>(value: &T, domain: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend(serialized(value)?);
    Ok(bytes)
}
fn public_key(value: &str) -> Result<String> {
    let bytes: [u8; 32] = signatures::decode(value, 32)?
        .try_into()
        .map_err(|_| protocol::invalid())?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| protocol::invalid())?;
    if key.is_weak() {
        return Err(protocol::invalid());
    }
    Ok(protocol::encode_hex(&bytes))
}
fn id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(protocol::invalid());
    }
    Ok(())
}
pub(crate) fn denied() -> Error {
    Error::new("anchor_rebuild_denied", true)
}

#[cfg(test)]
#[path = "rebuild_protocol_tests.rs"]
mod tests;
