//! 本机合成恢复批准，不代表健康设备批准、权限检查点或生产恢复授权。
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::protocol::{self, Scope, Signed};
use crate::{
    crypto::model::Identity,
    protocol::{parse_revision, validate_id, ApiError},
};

pub(super) const PROTOCOL: &str = "rim-browser-rebuild-1";
const APPROVAL_DOMAIN: &[u8] = b"Rocket-IM/browser-rebuild-approval/v1\0";
const REQUEST_DOMAIN: &[u8] = b"Rocket-IM/browser-rebuild-request/v1\0";
const RESPONSE_DOMAIN: &[u8] = b"Rocket-IM/browser-rebuild-response/v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub protocol_version: String,
    pub rebuild_id: String,
    pub anchor_public_key: String,
    pub approver_public_key: String,
    pub old_scope: Scope,
    pub old_head: String,
    pub old_txn: String,
    pub old_revision: String,
    pub old_conversation: String,
    pub successor_scope: Scope,
    pub successor_head: String,
    pub successor_client_public_key: String,
    pub successor_key_package_sha256: String,
    pub conversation: String,
    pub peer: Identity,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Action {
    Link,
    Inspect,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Linked,
    Duplicate,
    Unlinked,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub protocol_version: String,
    pub plan_sha256: String,
    pub challenge: String,
    pub action: Action,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Response {
    pub protocol_version: String,
    pub plan_sha256: String,
    pub request_sha256: String,
    pub challenge: String,
    pub action: Action,
    pub status: Status,
    pub old_scope: Scope,
    pub old_head: String,
    pub old_txn: String,
    pub old_revision: String,
    pub successor_scope: Scope,
    pub successor_head: String,
    pub successor_revision: String,
    pub current_head: String,
    pub current_revision: String,
    pub active_txn: Option<String>,
}

fn invalid() -> ApiError {
    ApiError::new(
        "anchor_rebuild_invalid",
        "重建计划字段、范围或编码无效。",
        false,
    )
}

fn binding() -> ApiError {
    ApiError::new(
        "anchor_rebuild_binding",
        "重建批准或响应不属于精确计划和本次请求。",
        false,
    )
}

fn public_key(value: &str) -> Result<(), ApiError> {
    let bytes = protocol::decode_hex(value).map_err(|_| invalid())?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid())?;
    if key.is_weak() {
        return Err(invalid());
    }
    Ok(())
}

fn scope(value: &Scope) -> Result<(), ApiError> {
    for id in [&value.service, &value.account, &value.device] {
        validate_id(id).map_err(|_| invalid())?;
    }
    public_key(&value.identity_key)?;
    protocol::decode_hex(&value.store_id).map_err(|_| invalid())?;
    Ok(())
}

fn bytes(value: &str, limit: usize) -> Result<Vec<u8>, ApiError> {
    if value.is_empty() || value.len() > limit.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let decoded = STANDARD.decode(value).map_err(|_| invalid())?;
    if decoded.len() > limit || STANDARD.encode(&decoded) != value {
        return Err(invalid());
    }
    Ok(decoded)
}

impl Plan {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        if self.protocol_version != PROTOCOL {
            return Err(invalid());
        }
        scope(&self.old_scope)?;
        scope(&self.successor_scope)?;
        for key in [
            &self.anchor_public_key,
            &self.approver_public_key,
            &self.successor_client_public_key,
        ] {
            public_key(key)?;
        }
        for hash in [
            &self.rebuild_id,
            &self.old_head,
            &self.old_txn,
            &self.successor_head,
            &self.successor_key_package_sha256,
        ] {
            protocol::decode_hex(hash).map_err(|_| invalid())?;
        }
        for id in [
            &self.old_conversation,
            &self.conversation,
            &self.peer.service,
            &self.peer.account,
            &self.peer.device,
        ] {
            validate_id(id).map_err(|_| invalid())?;
        }
        let peer_key = bytes(&self.peer.identity_key, 32)?;
        if peer_key.len() != 32 {
            return Err(invalid());
        }
        public_key(&protocol::encode_hex(&peer_key))?;
        if !self.peer.key_package.is_empty() {
            bytes(&self.peer.key_package, 64 * 1024)?;
        }
        if parse_revision(&self.old_revision).map_err(|_| invalid())? == 0
            || self.old_scope.service != self.successor_scope.service
            || self.old_scope.account != self.successor_scope.account
            || self.old_scope.device == self.successor_scope.device
            || self.old_scope.identity_key == self.successor_scope.identity_key
            || self.old_scope.store_id == self.successor_scope.store_id
            || self.old_head == self.successor_head
            || self.old_conversation == self.conversation
            || self.peer.service != self.old_scope.service
            || self.peer.account == self.old_scope.account
            || protocol::encode_hex(&peer_key) == self.successor_scope.identity_key
            || protocol::encode_hex(&peer_key) == self.old_scope.identity_key
            || self.approver_public_key == self.old_scope.identity_key
            || self.approver_public_key == self.successor_scope.identity_key
            || self.approver_public_key == self.anchor_public_key
            || self.approver_public_key == self.successor_client_public_key
        {
            return Err(invalid());
        }
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() > 8 * 1024 {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn digest(&self) -> Result<String, ApiError> {
        self.validate()?;
        Ok(protocol::hash_bytes(
            &serde_json::to_vec(self).map_err(|_| invalid())?,
        ))
    }
}

pub(super) fn verify_approval(plan: &Plan, signed: &Signed) -> Result<(), ApiError> {
    let digest = plan.digest()?;
    let approved: Plan = protocol::verify(signed, &plan.approver_public_key, APPROVAL_DOMAIN)?;
    if approved.digest()? != digest {
        return Err(binding());
    }
    Ok(())
}

pub(super) fn sign_request(
    plan: &Plan,
    key: &SigningKey,
    action: Action,
) -> Result<Signed, ApiError> {
    let plan_sha256 = plan.digest()?;
    if protocol::encode_hex(key.verifying_key().as_bytes()) != plan.successor_client_public_key {
        return Err(binding());
    }
    protocol::sign(
        &Request {
            protocol_version: PROTOCOL.into(),
            plan_sha256,
            challenge: protocol::random_hex()?,
            action,
        },
        key,
        REQUEST_DOMAIN,
    )
}

pub(super) fn verify_response(
    plan: &Plan,
    signed: &Signed,
    request: &Signed,
) -> Result<Response, ApiError> {
    let digest = plan.digest()?;
    let original: Request =
        protocol::verify(request, &plan.successor_client_public_key, REQUEST_DOMAIN)?;
    protocol::decode_hex(&original.challenge).map_err(|_| invalid())?;
    let response: Response = protocol::verify(signed, &plan.anchor_public_key, RESPONSE_DOMAIN)?;
    if original.protocol_version != PROTOCOL
        || original.plan_sha256 != digest
        || response.protocol_version != PROTOCOL
        || response.plan_sha256 != digest
        || response.request_sha256
            != protocol::hash_bytes(&serde_json::to_vec(request).map_err(|_| invalid())?)
        || response.challenge != original.challenge
        || response.action != original.action
        || response.old_scope != plan.old_scope
        || response.old_head != plan.old_head
        || response.old_txn != plan.old_txn
        || response.old_revision != plan.old_revision
        || response.successor_scope != plan.successor_scope
        || response.successor_head != plan.successor_head
        || response.successor_revision != "0"
    {
        return Err(binding());
    }
    let revision = parse_revision(&response.current_revision).map_err(|_| invalid())?;
    if !matches!(
        (response.action, response.status),
        (Action::Link, Status::Linked | Status::Duplicate)
            | (Action::Inspect, Status::Linked | Status::Unlinked)
    ) {
        return Err(binding());
    }
    if response.status == Status::Unlinked {
        if response.current_head != "absent" || revision != 0 || response.active_txn.is_some() {
            return Err(binding());
        }
    } else {
        protocol::decode_hex(&response.current_head).map_err(|_| invalid())?;
        if let Some(txn) = &response.active_txn {
            protocol::decode_hex(txn).map_err(|_| invalid())?;
            if revision == 0 {
                return Err(binding());
            }
        }
    }
    Ok(response)
}
