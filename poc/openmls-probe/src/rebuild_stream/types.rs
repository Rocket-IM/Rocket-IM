//! 重建后消息流的公共声明；数字以规范十进制字符串跨语言传递。
use super::{check, invalid};
use crate::{
    permission::{
        receipts::{RecoveryRecord, SignedRecord},
        types, PermissionError,
    },
    rollback_anchor::{self as anchor, rebuild, Scope},
};
use serde::{Deserialize, Serialize};

pub const REQUEST_DOMAIN: &[u8] = b"Rockets-IM/POC/rebuild-stream-request/v1\0";
pub const BINDING_DOMAIN: &[u8] = b"Rockets-IM/POC/rebuild-stream-binding/v1\0";
pub const PULL_DOMAIN: &[u8] = b"Rockets-IM/POC/rebuild-stream-pull/v1\0";
pub const PAGE_DOMAIN: &[u8] = b"Rockets-IM/POC/rebuild-stream-page/v1\0";
pub const SIGNED_DIGEST_DOMAIN: &[u8] = b"Rockets-IM/POC/rebuild-stream-signed-digest/v1\0";
pub const STATEMENT_LIMIT: usize = 16 * 1024;
pub const REGISTRATION_LIMIT: usize = 1024 * 1024;
pub const PAGE_BYTES_LIMIT: usize = 740 * 1024;

/// 必须来自 Relay 或客户端预先固定的独立配置，不能从注册输入自建信任。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub old_scope: Scope,
    pub anchor_public_key: String,
    pub trust: rebuild::RebuildTrust,
}

impl Trust {
    pub fn validate(&self) -> Result<(), PermissionError> {
        self.old_scope.validate().map_err(super::anchor_error)?;
        anchor::decode_hex(&self.anchor_public_key).map_err(super::anchor_error)?;
        self.trust
            .validate(&self.old_scope)
            .map_err(super::anchor_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub plan: rebuild::Plan,
    pub approval: anchor::Signed,
    pub anchor_request: anchor::Signed,
    pub anchor_response: anchor::Signed,
    pub request: SignedRecord,
    pub join_record: RecoveryRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestStatement {
    pub protocol_version: String,
    pub plan_sha256: String,
    pub successor_scope: Scope,
    pub conversation_id: String,
    pub stream_id: String,
    pub initial_cursor: String,
    pub join_proof_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingStatement {
    pub protocol_version: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub successor_scope: Scope,
    pub conversation_id: String,
    pub stream_id: String,
    pub initial_cursor: String,
    pub join_proof_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullStatement {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub successor_scope: Scope,
    pub stream_id: String,
    pub binding_sha256: String,
    pub after_seq: String,
    pub limit: String,
    pub challenge: String,
}

/// 只签精确分页原字节摘要；事件不进入签名器请求。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageStatement {
    pub protocol_version: String,
    pub binding_sha256: String,
    pub request_sha256: String,
    pub service_id: String,
    pub conversation_id: String,
    pub successor_scope: Scope,
    pub stream_id: String,
    pub after_seq: String,
    pub limit: String,
    pub challenge: String,
    pub page_sha256: String,
}

fn scope(scope: &Scope, conversation: &str, stream: &str) -> Result<(), PermissionError> {
    scope.validate().map_err(super::anchor_error)?;
    for value in [&scope.service, &scope.account, &scope.device, conversation] {
        types::id(value)?;
    }
    types::hash(stream)
}

fn origin(
    successor: &Scope,
    conversation: &str,
    stream: &str,
    plan: &str,
    cursor: &str,
    proof: &str,
) -> Result<(), PermissionError> {
    scope(successor, conversation, stream)?;
    types::hash(plan)?;
    types::hash(proof)?;
    check(
        cursor == "0",
        "rebuild_stream_invalid",
        "新流游标必须从零开始",
    )
}

fn page_window(after_seq: &str, limit: &str, challenge: &str) -> Result<(), PermissionError> {
    types::decimal(after_seq)?;
    check(
        (1..=100).contains(&types::decimal(limit)?),
        "rebuild_stream_invalid",
        "分页上限必须是1—100",
    )?;
    types::hash(challenge)
}

impl RequestStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-rebuild-stream-request-1" {
            return Err(invalid());
        }
        origin(
            &self.successor_scope,
            &self.conversation_id,
            &self.stream_id,
            &self.plan_sha256,
            &self.initial_cursor,
            &self.join_proof_sha256,
        )
    }
}

impl BindingStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-rebuild-stream-binding-1" {
            return Err(invalid());
        }
        types::hash(&self.request_sha256)?;
        origin(
            &self.successor_scope,
            &self.conversation_id,
            &self.stream_id,
            &self.plan_sha256,
            &self.initial_cursor,
            &self.join_proof_sha256,
        )
    }
}

impl PullStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-rebuild-stream-pull-1" {
            return Err(invalid());
        }
        scope(
            &self.successor_scope,
            &self.conversation_id,
            &self.stream_id,
        )?;
        check(
            self.service_id == self.successor_scope.service,
            "rebuild_stream_context",
            "请求实例与新设备范围不符",
        )?;
        types::hash(&self.binding_sha256)?;
        page_window(&self.after_seq, &self.limit, &self.challenge)
    }
}

impl PageStatement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.protocol_version != "rim-rebuild-stream-page-1" {
            return Err(invalid());
        }
        scope(
            &self.successor_scope,
            &self.conversation_id,
            &self.stream_id,
        )?;
        check(
            self.service_id == self.successor_scope.service,
            "rebuild_stream_context",
            "分页实例与新设备范围不符",
        )?;
        for hash in [
            &self.binding_sha256,
            &self.request_sha256,
            &self.page_sha256,
        ] {
            types::hash(hash)?;
        }
        page_window(&self.after_seq, &self.limit, &self.challenge)
    }
}
