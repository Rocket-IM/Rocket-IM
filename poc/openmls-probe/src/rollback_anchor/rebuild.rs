//! 单层安全重建契约；授权只绑定新身份和新范围，不释放旧预约或传递 MLS 秘密。
use super::*;
use crate::permission::{Member, PermissionCheckpoint};

mod state;
pub(super) use state::{apply, validate_link, Link};

pub const PROTOCOL: &str = "rim-anchor-rebuild-1";
pub const APPROVAL_DOMAIN: &[u8] = b"Rocket-IM/POC/anchor-rebuild-approval/v1\0";
const CLIENT_DOMAIN: &[u8] = b"Rocket-IM/POC/anchor-rebuild-client/v1\0";
const RESULT_DOMAIN: &[u8] = b"Rocket-IM/POC/anchor-rebuild-response/v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebuildTrust {
    pub authorizer: Member,
    pub checkpoint: PermissionCheckpoint,
    pub relay_receipt_key: String,
}

impl RebuildTrust {
    pub fn validate(&self, old: &Scope) -> Result<(), AnchorError> {
        self.checkpoint.validate().map_err(|_| invalid())?;
        crate::permission::receipts::validate_key(&self.relay_receipt_key)
            .map_err(|_| invalid())?;
        let key = member_key(&self.authorizer)?;
        if self.checkpoint.service_id != old.service
            || self.authorizer.account_id != old.account
            || self.authorizer.device_id == old.device
            || key == old.identity_key
            || !self.checkpoint.members.contains(&self.authorizer)
            || self.checkpoint.members.iter().any(|m| {
                (m.account_id == old.account && m.device_id == old.device)
                    || member_key(m).ok().as_ref() == Some(&old.identity_key)
            })
        {
            return Err(denied());
        }
        Ok(())
    }
}

fn member_key(member: &Member) -> Result<String, AnchorError> {
    let bytes = decode_base64(&member.signature_key, 32)?;
    if bytes.len() != 32 {
        return Err(invalid());
    }
    Ok(encode_hex(&bytes))
}

fn denied() -> AnchorError {
    AnchorError::new("anchor_rebuild_denied", "重建来源、原范围或后继绑定不符")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
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
    pub fn validate(&self) -> Result<(), AnchorError> {
        if self.protocol_version != PROTOCOL {
            return Err(invalid());
        }
        self.old_scope.validate()?;
        self.successor_scope.validate()?;
        // 后继必须能进入已有签名权限协议；不能先永久封存旧范围才发现设备ID不可加入。
        for value in [
            &self.successor_scope.service,
            &self.successor_scope.account,
            &self.successor_scope.device,
        ] {
            crate::permission::types::id(value).map_err(|_| invalid())?;
        }
        self.trust.validate(&self.old_scope)?;
        crate::permission::types::id(&self.old_conversation_id).map_err(|_| invalid())?;
        if decode_base64(&self.old_group_id, 128)?.is_empty()
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
            decode_hex(value)?;
        }
        if validate_revision(&self.old_revision)? == 0
            || self.old_scope.service != self.successor_scope.service
            || self.old_scope.account != self.successor_scope.account
            || self.old_scope.device == self.successor_scope.device
            || self.old_scope.identity_key == self.successor_scope.identity_key
            || self.old_scope.store_id == self.successor_scope.store_id
            || self.old_head == self.successor_head
            || self.trust.checkpoint.members.iter().any(|m| {
                (m.account_id == self.successor_scope.account
                    && m.device_id == self.successor_scope.device)
                    || member_key(m).ok().as_ref() == Some(&self.successor_scope.identity_key)
            })
        {
            return Err(denied());
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, AnchorError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        if bytes.len() > STATEMENT_LIMIT {
            return Err(invalid());
        }
        Ok(hash_bytes(&bytes))
    }
}

/// 供实际持有设备签名；调用前仍须由实验客户端核验独立确认和本机健康状态。
pub fn approval_signing_bytes(plan: &Plan) -> Result<Vec<u8>, AnchorError> {
    plan.digest()?;
    let mut bytes = APPROVAL_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(plan).map_err(|_| invalid())?);
    Ok(bytes)
}

pub fn sign_approval(plan: &Plan, seed: &[u8; 32]) -> Result<Signed, AnchorError> {
    plan.validate()?;
    sign(plan, seed, APPROVAL_DOMAIN)
}

pub fn verify_approval(plan: &Plan, signed: &Signed) -> Result<(), AnchorError> {
    plan.validate()?;
    let approved: Plan = verify(
        signed,
        &member_key(&plan.trust.authorizer)?,
        APPROVAL_DOMAIN,
    )?;
    if approved != *plan {
        return Err(denied());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Link,
    Cancel,
    Inspect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub plan_sha256: String,
    pub challenge: String,
    pub action: Action,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Unlinked,
    Linked,
    Duplicate,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
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
    pub cancelled: bool,
}

pub fn sign_rebuild_request(
    plan: &Plan,
    challenge: &str,
    action: Action,
    seed: &[u8; 32],
) -> Result<Signed, AnchorError> {
    decode_hex(challenge)?;
    sign(
        &Request {
            plan_sha256: plan.digest()?,
            challenge: challenge.to_owned(),
            action,
        },
        seed,
        CLIENT_DOMAIN,
    )
}

fn verify_client(
    plan: &Plan,
    challenge: &str,
    action: Action,
    signed: &Signed,
    key: &str,
) -> Result<(), AnchorError> {
    decode_hex(challenge)?;
    let request: Request = verify(signed, key, CLIENT_DOMAIN)?;
    if request.plan_sha256 != plan.digest()?
        || request.challenge != challenge
        || request.action != action
    {
        return Err(denied());
    }
    Ok(())
}

pub fn verify_rebuild_response(
    signed: &Signed,
    anchor_key: &str,
    plan: &Plan,
    original: &Signed,
) -> Result<Response, AnchorError> {
    let response: Response = verify(signed, anchor_key, RESULT_DOMAIN)?;
    let request: Request =
        serde_json::from_slice(&decode_base64(&original.statement_bytes, STATEMENT_LIMIT)?)
            .map_err(|_| invalid())?;
    let valid_status = matches!(
        (response.action, response.status, response.cancelled),
        (Action::Link, Status::Linked, false)
            | (Action::Link, Status::Duplicate, _)
            | (Action::Cancel, Status::Cancelled, true)
            | (Action::Inspect, Status::Unlinked | Status::Linked, false)
            | (Action::Inspect, Status::Cancelled, true)
    );
    decode_hex(&response.successor_head)?;
    decode_hex(&response.challenge)?;
    validate_revision(&response.successor_revision)?;
    if !valid_status
        || response.protocol_version != PROTOCOL
        || response.plan_sha256 != plan.digest()?
        || response.plan_sha256 != request.plan_sha256
        || response.request_sha256 != request_digest(original)?
        || response.challenge != request.challenge
        || response.action != request.action
        || response.old_scope != plan.old_scope
        || response.old_head != plan.old_head
        || response.old_txn != plan.old_txn
        || response.old_revision != plan.old_revision
        || response.successor_scope != plan.successor_scope
        || anchor_key != plan.anchor_public_key
    {
        return Err(AnchorError::new(
            "anchor_response_binding",
            "重建响应不属于本次请求与固定新旧范围",
        ));
    }
    Ok(response)
}

#[cfg(test)]
#[path = "rebuild_tests.rs"]
mod tests;
