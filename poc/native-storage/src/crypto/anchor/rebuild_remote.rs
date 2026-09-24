//! 有界 helper 调用只交换签名公开材料；调用者不得在 SQLite 事务内调用。
use super::{
    client::Client,
    protocol::{self, Scope, Signed, STATEMENT_LIMIT},
    rebuild_protocol::{self as rebuild, Plan},
    signatures, transport,
};
use crate::model::{Error, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

const CLIENT_DOMAIN: &[u8] = b"Rockets-IM/POC/anchor-rebuild-client/v1\0";
pub(super) const RESULT_DOMAIN: &[u8] = b"Rockets-IM/POC/anchor-rebuild-response/v1\0";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Link,
    Cancel,
    Inspect,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Unlinked,
    Linked,
    Duplicate,
    Cancelled,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub plan_sha256: String,
    pub challenge: String,
    pub action: Action,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub response: Response,
    pub request: Signed,
    pub signed_response: Signed,
}
pub(crate) fn sign_request(
    plan: &Plan,
    challenge: &str,
    action: Action,
    key: &SigningKey,
) -> Result<Signed> {
    protocol::decode_hex(challenge)?;
    signatures::sign(
        &Request {
            plan_sha256: plan.digest()?,
            challenge: challenge.into(),
            action,
        },
        key,
        CLIENT_DOMAIN,
        STATEMENT_LIMIT,
    )
}
pub(crate) fn verify_response(
    signed: &Signed,
    anchor_key: &str,
    plan: &Plan,
    original: &Signed,
) -> Result<Response> {
    let response: Response =
        signatures::verify(signed, anchor_key, RESULT_DOMAIN, STATEMENT_LIMIT)?;
    let request: Request = serde_json::from_slice(&signatures::decode(
        &original.statement_bytes,
        STATEMENT_LIMIT,
    )?)
    .map_err(|_| protocol::invalid())?;
    let digest = plan.digest()?;
    protocol::decode_hex(&request.challenge)?;
    protocol::decode_hex(&response.successor_head)?;
    let revision = protocol::revision(&response.successor_revision)?;
    let valid_status = matches!(
        (response.action, response.status, response.cancelled),
        (Action::Link, Status::Linked, false)
            | (Action::Link, Status::Duplicate, _)
            | (Action::Cancel, Status::Cancelled, true)
            | (Action::Inspect, Status::Unlinked | Status::Linked, false)
            | (Action::Inspect, Status::Cancelled, true)
    );
    if !valid_status
        || response.protocol_version != rebuild::PROTOCOL
        || response.plan_sha256 != digest
        || request.plan_sha256 != digest
        || response.request_sha256
            != protocol::hash(&serde_json::to_vec(original).map_err(|_| protocol::invalid())?)
        || response.challenge != request.challenge
        || response.action != request.action
        || response.old_scope != plan.old_scope
        || response.old_head != plan.old_head
        || response.old_txn != plan.old_txn
        || response.old_revision != plan.old_revision
        || response.successor_scope != plan.successor_scope
        || anchor_key != plan.anchor_public_key
        || (revision == 0 && response.successor_head != plan.successor_head)
        || (matches!(
            (response.action, response.status),
            (_, Status::Unlinked) | (Action::Link, Status::Linked)
        ) && revision != 0)
    {
        return Err(Error::new("anchor_response_binding", true));
    }
    Ok(response)
}

pub(crate) fn rpc(
    client: &Client,
    plan: &Plan,
    approval: &Signed,
    action: Action,
) -> Result<Receipt> {
    rebuild::verify_approval(plan, approval)?;
    if client.scope() != &plan.old_scope
        || client.config.anchor_public_key != plan.anchor_public_key
        || client.config.rebuild_trust.as_ref() != Some(&plan.trust)
    {
        return Err(rebuild::denied());
    }
    let challenge = protocol::random_hex()?;
    let request = sign_request(plan, &challenge, action, &client.signing_key)?;
    let operation = match action {
        Action::Link => "rebuild",
        Action::Cancel => "cancel_rebuild",
        Action::Inspect => "inspect_rebuild",
    };
    let input = serde_json::to_vec(
        &serde_json::json!({"op":operation,"directory":client.config.directory,
        "plan":plan,"approval":approval,"client_proof":request,"challenge":challenge}),
    )
    .map_err(|_| protocol::invalid())?;
    if input.len() > protocol::INPUT_LIMIT {
        return Err(protocol::invalid());
    }
    let output = transport::exchange(&client.config.program, &input)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        ok: bool,
        response: Option<Signed>,
        error: Option<RemoteError>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RemoteError {
        code: String,
        message: String,
    }
    if output.stdout.trim().is_empty() || output.stdout.len() > protocol::INPUT_LIMIT {
        return Err(Error::new("anchor_rpc_failed", true));
    }
    let reply: Reply = serde_json::from_str(&output.stdout).map_err(|_| protocol::invalid())?;
    let signed_response = match (output.success, reply.ok, reply.response, reply.error) {
        (true, true, Some(response), None) => response,
        (_, false, None, Some(error))
            if !error.code.is_empty()
                && error.code.len() <= 1024
                && !error.message.is_empty()
                && error.message.len() <= 1024 =>
        {
            return Err(Error::new("anchor_remote_error", true))
        }
        _ => return Err(Error::new("anchor_rpc_failed", true)),
    };
    let response = verify_response(
        &signed_response,
        &client.config.anchor_public_key,
        plan,
        &request,
    )?;
    Ok(Receipt {
        response,
        request,
        signed_response,
    })
}
