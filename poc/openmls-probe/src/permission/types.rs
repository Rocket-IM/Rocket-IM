//! 签名权限记录的公共字段；这里不含设备私密状态或存储入口。

use super::{check, PermissionError};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SIGNING_DOMAIN: &[u8] = b"Rockets-IM/POC/permission-change/v1\0";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub account_id: String,
    pub device_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub account_id: String,
    pub device_id: String,
    pub signature_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionCheckpoint {
    pub service_id: String,
    pub conversation_id: String,
    pub authorization_version: String,
    pub crypto_state_ref: String,
    pub owner_account_id: String,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    AddMember {
        member: Member,
        key_package_sha256: String,
        welcome_sha256: String,
        history_policy: String,
    },
    AddDevice {
        member: Member,
        key_package_sha256: String,
        welcome_sha256: String,
        history_policy: String,
    },
    RemoveMember {
        account_id: String,
    },
    RevokeDevice {
        account_id: String,
        device_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub protocol_version: String,
    pub change_id: String,
    pub service_id: String,
    pub conversation_id: String,
    pub actor: Identity,
    pub previous_authorization_version: String,
    pub authorization_version: String,
    pub from_state_ref: String,
    pub to_state_ref: String,
    pub action: Action,
    pub commit_sha256: String,
    pub nonce: String,
    pub issued_at_unix_secs: String,
    pub expires_at_unix_secs: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub statement_bytes: String,
    pub signature_bytes: String,
    pub commit_bytes: String,
}

pub(crate) fn id(value: &str) -> Result<(), PermissionError> {
    check(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid_permission",
        "标识必须是 1—64 个 ASCII 字母、数字、下划线或连字符",
    )
}

pub(crate) fn decimal(value: &str) -> Result<u64, PermissionError> {
    check(
        !value.is_empty()
            && (value == "0" || !value.starts_with('0'))
            && value.bytes().all(|b| b.is_ascii_digit()),
        "invalid_permission",
        "整数必须是规范十进制字符串",
    )?;
    value
        .parse()
        .map_err(|_| PermissionError::new("invalid_permission", "整数超出 u64"))
}

pub(crate) fn hash(value: &str) -> Result<(), PermissionError> {
    check(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_permission",
        "摘要或随机挑战必须是 64 位小写十六进制",
    )
}

pub(crate) fn bytes(value: &str, limit: usize) -> Result<Vec<u8>, PermissionError> {
    check(
        !value.is_empty() && value.len() <= limit.div_ceil(3) * 4,
        "invalid_permission",
        "字节字段为空或超限",
    )?;
    let raw = STANDARD
        .decode(value)
        .map_err(|_| PermissionError::new("invalid_permission", "Base64 无效"))?;
    check(
        !raw.is_empty() && raw.len() <= limit && STANDARD.encode(&raw) == value,
        "invalid_permission",
        "字节字段必须是规范 Base64",
    )?;
    Ok(raw)
}

impl Member {
    pub fn identity(&self) -> Identity {
        Identity {
            account_id: self.account_id.clone(),
            device_id: self.device_id.clone(),
        }
    }
}

impl PermissionCheckpoint {
    pub fn validate(&self) -> Result<(), PermissionError> {
        for value in [
            &self.service_id,
            &self.conversation_id,
            &self.owner_account_id,
        ] {
            id(value)?;
        }
        decimal(&self.authorization_version)?;
        hash(&self.crypto_state_ref)?;
        check(
            (2..=6).contains(&self.members.len()),
            "invalid_permission",
            "检查点需 2—6 个设备",
        )?;
        let mut keys = BTreeSet::new();
        for member in &self.members {
            id(&member.account_id)?;
            id(&member.device_id)?;
            let raw = bytes(&member.signature_key, 32)?;
            check(
                raw.len() == 32 && keys.insert(raw.clone()),
                "invalid_permission",
                "公钥必须是独立 32 字节",
            )?;
            let key: [u8; 32] = raw
                .try_into()
                .map_err(|_| PermissionError::new("invalid_permission", "公钥长度错误"))?;
            let verifier = ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map_err(|_| PermissionError::new("invalid_permission", "无效 Ed25519 公钥"))?;
            check(
                !verifier.is_weak(),
                "invalid_permission",
                "不接受弱 Ed25519 公钥",
            )?;
        }
        check(
            self.members
                .windows(2)
                .all(|pair| pair[0].identity() < pair[1].identity())
                && self
                    .members
                    .iter()
                    .any(|member| member.account_id == self.owner_account_id),
            "invalid_permission",
            "成员须排序、唯一且包含群主",
        )
    }

    pub fn remaining(
        &self,
        actor: &Identity,
        action: &Action,
    ) -> Result<Vec<Member>, PermissionError> {
        check(
            self.members
                .iter()
                .any(|member| member.identity() == *actor),
            "permission_denied",
            "发起设备不在可信检查点",
        )?;
        match action {
            Action::AddMember { member, .. } => {
                check(
                    actor.account_id == self.owner_account_id
                        && !self
                            .members
                            .iter()
                            .any(|old| old.account_id == member.account_id),
                    "permission_denied",
                    "仅群主可邀请尚不在群中的新账号",
                )?;
                let mut next = self.clone();
                next.members.push(member.clone());
                next.members.sort_by_key(Member::identity);
                next.validate()?;
                return Ok(next.members);
            }
            Action::AddDevice { member, .. } => {
                check(
                    actor.account_id == member.account_id
                        && actor.device_id != member.device_id
                        && !self
                            .members
                            .iter()
                            .any(|old| old.identity() == member.identity()),
                    "permission_denied",
                    "只能由同账号当前有效旧设备授权全新的其他设备",
                )?;
                let mut next = self.clone();
                next.members.push(member.clone());
                next.members.sort_by_key(Member::identity);
                next.validate()?;
                return Ok(next.members);
            }
            Action::RemoveMember { account_id } => {
                id(account_id)?;
                check(
                    actor.account_id == self.owner_account_id
                        && *account_id != self.owner_account_id,
                    "permission_denied",
                    "仅群主设备可移除非群主账号",
                )?;
            }
            Action::RevokeDevice {
                account_id,
                device_id,
            } => {
                id(account_id)?;
                id(device_id)?;
                check(
                    actor.account_id == *account_id && actor.device_id != *device_id,
                    "permission_denied",
                    "只能撤销同账号其他设备",
                )?;
            }
        }
        let remaining: Vec<_> = self
            .members
            .iter()
            .filter(|member| !action.removes(member))
            .cloned()
            .collect();
        check(
            remaining.len() < self.members.len()
                && remaining.len() >= 2
                && remaining.iter().any(|member| member.identity() == *actor),
            "permission_denied",
            "目标不存在、自移除或变更后不足两个设备",
        )?;
        Ok(remaining)
    }
}

impl Statement {
    pub fn parse(raw: &[u8]) -> Result<Self, PermissionError> {
        check(
            raw.len() <= 16 * 1024,
            "invalid_permission",
            "声明超过 16 KiB",
        )?;
        let statement: Self = serde_json::from_slice(raw)
            .map_err(|_| PermissionError::new("invalid_permission", "声明字段或 JSON 无效"))?;
        check(
            statement.protocol_version == "rim-permission-1",
            "invalid_permission",
            "权限协议版本不支持",
        )?;
        for value in [
            &statement.change_id,
            &statement.service_id,
            &statement.conversation_id,
            &statement.actor.account_id,
            &statement.actor.device_id,
        ] {
            id(value)?;
        }
        for value in [
            &statement.from_state_ref,
            &statement.to_state_ref,
            &statement.commit_sha256,
            &statement.nonce,
        ] {
            hash(value)?;
        }
        match &statement.action {
            Action::AddMember {
                member,
                key_package_sha256,
                welcome_sha256,
                history_policy,
            }
            | Action::AddDevice {
                member,
                key_package_sha256,
                welcome_sha256,
                history_policy,
            } => {
                id(&member.account_id)?;
                id(&member.device_id)?;
                super::receipts::validate_key(&member.signature_key)?;
                hash(key_package_sha256)?;
                hash(welcome_sha256)?;
                check(
                    history_policy == "from_join",
                    "invalid_permission",
                    "只支持入群后历史策略",
                )?;
            }
            Action::RemoveMember { account_id } => id(account_id)?,
            Action::RevokeDevice {
                account_id,
                device_id,
            } => {
                id(account_id)?;
                id(device_id)?;
            }
        }
        decimal(&statement.previous_authorization_version)?;
        decimal(&statement.authorization_version)?;
        let issued = decimal(&statement.issued_at_unix_secs)?;
        let expires = decimal(&statement.expires_at_unix_secs)?;
        check(
            expires
                .checked_sub(issued)
                .is_some_and(|span| (1..=300).contains(&span)),
            "invalid_permission",
            "权限声明有效窗口必须是 1—300 秒",
        )?;
        Ok(statement)
    }
}
