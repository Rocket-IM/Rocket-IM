//! rim-poc-1 的实验类型；只由 state-lab 与可信合成调度器使用。

use super::{checked, codec, ensure, LabError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Device {
    pub account_id: String,
    pub device_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub protocol_version: String,
    pub service_id: String,
    pub conversation_id: String,
    pub sender: Device,
    pub logical_message_id: String,
    pub attempt_id: String,
    pub security_mode: String,
    pub crypto_profile: String,
    pub authorization_version: String,
    pub crypto_state_ref: String,
    pub recipients: Vec<Device>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub header_bytes: String,
    pub payload_bytes: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    pub conversation_id: String,
    pub authorization_version: String,
    pub crypto_state_ref: String,
    pub members: Vec<Device>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Outbound {
    pub logical_key: String,
    pub attempt_id: String,
    pub payload: String,
    pub envelope: Envelope,
    pub replaces_attempt_id: Option<String>,
    pub closure_id: Option<String>,
    #[serde(default)]
    pub acceptance_receipt: Option<crate::permission::receipts::SignedRecord>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Inbound {
    pub logical_key: String,
    pub attempt_id: String,
    pub envelope: Envelope,
    pub payload_digest: [u8; 32],
    #[serde(default)]
    pub acceptance_id: Option<String>,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub acceptance_receipt: Option<crate::permission::receipts::SignedRecord>,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct WireState {
    pub configuration: Option<Configuration>,
    pub outbox: BTreeMap<String, Outbound>,
    pub inbox: BTreeMap<String, Inbound>,
    pub tails: BTreeMap<String, String>,
}

pub(super) fn id(value: &str) -> Result<(), LabError> {
    ensure(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid_envelope",
        "标识必须是 1—64 个 ASCII 字母、数字、下划线或连字符",
    )
}

pub(super) fn decimal(value: &str) -> Result<u64, LabError> {
    ensure(
        !value.is_empty()
            && (value == "0" || !value.starts_with('0'))
            && value.bytes().all(|b| b.is_ascii_digit()),
        "invalid_envelope",
        "整数必须是无前导零的十进制字符串",
    )?;
    checked("invalid_envelope", value.parse())
}

pub(super) fn bytes(value: &str, limit: usize) -> Result<Vec<u8>, LabError> {
    ensure(
        !value.is_empty() && value.len() <= limit.div_ceil(3) * 4,
        "invalid_envelope",
        "字节字段超过上限",
    )?;
    let raw = codec::decode(value).map_err(|_| LabError::new("invalid_envelope", "无效 Base64"))?;
    ensure(
        !raw.is_empty() && raw.len() <= limit && codec::encode(&raw) == value,
        "invalid_envelope",
        "Base64 必须规范且带填充",
    )?;
    Ok(raw)
}

pub(super) fn reference(value: &str) -> Result<(), LabError> {
    ensure(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_envelope",
        "密码状态引用必须是 64 位小写十六进制摘要",
    )
}

impl Header {
    pub fn parse(raw: &[u8]) -> Result<Self, LabError> {
        // 派生的结构反序列化拒绝重复、未知和缺失键，不先经过 Value 丢失重复信息。
        let header: Self = checked("invalid_envelope", serde_json::from_slice(raw))?;
        ensure(
            header.protocol_version == "rim-poc-1",
            "unsupported_version",
            "协议版本不支持",
        )?;
        ensure(
            header.security_mode == "e2ee",
            "unsupported_mode",
            "本实验只支持 MLS E2EE",
        )?;
        ensure(
            header.crypto_profile == "mls-poc",
            "unsupported_crypto_profile",
            "不支持此密码实验配置",
        )?;
        for value in [
            &header.service_id,
            &header.conversation_id,
            &header.sender.account_id,
            &header.sender.device_id,
            &header.logical_message_id,
            &header.attempt_id,
        ] {
            id(value)?;
        }
        decimal(&header.authorization_version)?;
        reference(&header.crypto_state_ref)?;
        ensure(
            !header.recipients.is_empty() && header.recipients.len() <= 5,
            "invalid_envelope",
            "目标数量不合法",
        )?;
        for target in &header.recipients {
            id(&target.account_id)?;
            id(&target.device_id)?;
        }
        ensure(
            header.recipients.windows(2).all(|pair| pair[0] < pair[1])
                && !header.recipients.contains(&header.sender),
            "invalid_envelope",
            "目标必须排序、唯一且不含发送设备",
        )?;
        Ok(header)
    }

    pub fn logical_key(&self) -> Result<String, LabError> {
        logical_key(
            &self.service_id,
            &self.conversation_id,
            &self.sender,
            &self.logical_message_id,
        )
    }

    pub fn attempt_key(&self) -> Result<String, LabError> {
        checked(
            "key_encoding",
            serde_json::to_string(&(self.logical_key()?, &self.attempt_id)),
        )
    }
}

pub(super) fn logical_key(
    service: &str,
    conversation: &str,
    sender: &Device,
    message: &str,
) -> Result<String, LabError> {
    checked(
        "key_encoding",
        serde_json::to_string(&(
            service,
            conversation,
            &sender.account_id,
            &sender.device_id,
            message,
        )),
    )
}

// 外部可选字段只允许省略，显式null不当成缺失。
pub(super) fn present_receipt<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<crate::permission::receipts::SignedRecord>, D::Error> {
    crate::permission::receipts::SignedRecord::deserialize(d).map(Some)
}
pub(super) fn present_id<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
