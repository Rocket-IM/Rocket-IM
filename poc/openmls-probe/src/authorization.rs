//! 合成设备授权 POC：应用层授权声明，不是 MLS 协议扩展或正式身份系统。
//!
//! 首个设备公钥来自独立可信 fixture；Service 的 token、目录或响应均无权替代它。
//! 反序列化的 roster 必须来自受信端侧存储，不能从 Relay 导入。完整存储回滚、
//! 独立视图分叉及真实用户确认不在本模块内解决。

use ed25519_dalek::{Signature, VerifyingKey};
use openmls_traits::{signatures::Signer, types::SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const SIGNING_DOMAIN: &[u8] = b"Rocket-IM/POC/device-authorization/v1\0";
const MAX_VALIDITY_SECONDS: u64 = 300;
const MAX_DEVICES: usize = 64;
const MAX_CONSUMED_NONCES: usize = 4096;

/// 时间均为 UTC Unix 秒；nonce 由调用者使用安全随机源生成。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub service: String,
    pub account: String,
    pub signer_device: String,
    pub new_device: String,
    pub new_signature_key: [u8; 32],
    pub key_package_sha256: [u8; 32],
    pub expected_roster_version: u64,
    pub nonce: [u8; 32],
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorization {
    pub request: AuthorizationRequest,
    pub signature: Vec<u8>,
}

impl DeviceAuthorization {
    /// 仅签应用层声明；调用前须由旧设备确认新设备身份及 KeyPackage 指纹。
    pub fn sign(
        request: AuthorizationRequest,
        signer: &impl Signer,
    ) -> Result<Self, AuthorizationError> {
        if signer.signature_scheme() != SignatureScheme::ED25519 {
            return Err(AuthorizationError::UnsupportedSignatureScheme);
        }
        validate_request_shape(&request)?;
        let signature = signer
            .sign(&signing_bytes(&request)?)
            .map_err(|_| AuthorizationError::SigningFailed)?;
        Ok(Self { request, signature })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedDevice {
    signature_key: [u8; 32],
    is_revoked: bool,
}

/// 单一调用者拥有的可信检查点。apply 成功后，调用者需与 MLS 状态一致持久化。
/// serde 只供受信端侧快照；格式可解析不代表快照完整性、新鲜度或来源可信。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRoster {
    service: String,
    account: String,
    version: u64,
    devices: BTreeMap<String, TrustedDevice>,
    consumed_nonces: BTreeSet<[u8; 32]>,
}

impl TrustedRoster {
    pub fn new(
        service: String,
        account: String,
        pinned_device: String,
        pinned_key: [u8; 32],
    ) -> Result<Self, AuthorizationError> {
        if [&service, &account, &pinned_device]
            .iter()
            .any(|value| !valid_id(value))
        {
            return Err(AuthorizationError::InvalidRequest);
        }
        validating_key(&pinned_key)?;
        Ok(Self {
            service,
            account,
            version: 0,
            devices: BTreeMap::from([(
                pinned_device,
                TrustedDevice {
                    signature_key: pinned_key,
                    is_revoked: false,
                },
            )]),
            consumed_nonces: BTreeSet::new(),
        })
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn is_trusted(&self, device: &str) -> bool {
        self.devices
            .get(device)
            .is_some_and(|entry| !entry.is_revoked)
    }

    /// 用于将已授权设备与真实 MLS KeyPackage 的签名公钥核对。
    pub fn trusted_signature_key(&self, device: &str) -> Option<[u8; 32]> {
        self.devices
            .get(device)
            .filter(|entry| !entry.is_revoked)
            .map(|entry| entry.signature_key)
    }

    /// 仅供本机独立核验排除公钥复用；撤销不删除既有设备绑定事实。
    pub(crate) fn key_bound_to_other_device(&self, device: &str, key: &[u8; 32]) -> bool {
        self.devices
            .iter()
            .any(|(id, entry)| id != device && entry.signature_key == *key)
    }

    /// 调用者先用 OpenMLS 验证 KeyPackage，传入其原始序列化字节和实际签名公钥。
    /// 所有验证结束前不改状态；成功消耗 nonce 并推进版本，失败保持原检查点。
    /// now 必须来自调用者可信时钟；本模块没有网络、磁盘、token 或隐式授权入口。
    pub fn apply(
        &mut self,
        authorization: &DeviceAuthorization,
        raw_key_package: &[u8],
        actual_mls_signature_key: &[u8],
        now_unix_secs: u64,
    ) -> Result<(), AuthorizationError> {
        let request = &authorization.request;
        validate_request_shape(request)?;
        if request.service != self.service || request.account != self.account {
            return Err(AuthorizationError::WrongContext);
        }
        if request.issued_at_unix_secs > now_unix_secs
            || now_unix_secs >= request.expires_at_unix_secs
        {
            return Err(AuthorizationError::OutsideValidity);
        }
        if self.consumed_nonces.contains(&request.nonce) {
            return Err(AuthorizationError::NonceConsumed);
        }
        if request.expected_roster_version != self.version {
            return Err(AuthorizationError::WrongVersion);
        }
        let signer = self
            .devices
            .get(&request.signer_device)
            .filter(|entry| !entry.is_revoked)
            .ok_or(AuthorizationError::SignerNotTrusted)?;
        let signature = Signature::from_slice(&authorization.signature)
            .map_err(|_| AuthorizationError::InvalidSignature)?;
        validating_key(&signer.signature_key)?
            .verify_strict(&signing_bytes(request)?, &signature)
            .map_err(|_| AuthorizationError::InvalidSignature)?;
        if request.key_package_sha256 != key_package_sha256(raw_key_package)
            || request.new_signature_key.as_slice() != actual_mls_signature_key
        {
            return Err(AuthorizationError::KeyPackageMismatch);
        }
        if self.devices.contains_key(&request.new_device) {
            return Err(AuthorizationError::DeviceAlreadyKnown);
        }
        if self
            .devices
            .values()
            .any(|entry| entry.signature_key == request.new_signature_key)
        {
            return Err(AuthorizationError::ReusedDeviceKey);
        }
        if self.devices.len() >= MAX_DEVICES || self.consumed_nonces.len() >= MAX_CONSUMED_NONCES {
            return Err(AuthorizationError::ResourceLimit);
        }
        let next_version = self
            .version
            .checked_add(1)
            .ok_or(AuthorizationError::ResourceLimit)?;
        self.devices.insert(
            request.new_device.clone(),
            TrustedDevice {
                signature_key: request.new_signature_key,
                is_revoked: false,
            },
        );
        self.consumed_nonces.insert(request.nonce);
        self.version = next_version;
        Ok(())
    }

    /// 测试装置注入已验证的撤销检查点；不是对外管理 API，也不验证撤销请求授权。
    /// 已撤销 ID/公钥保留，后续授权不能悄悄复活同一身份。
    pub fn revoke(
        &mut self,
        device: &str,
        expected_version: u64,
    ) -> Result<(), AuthorizationError> {
        if expected_version != self.version {
            return Err(AuthorizationError::WrongVersion);
        }
        let next_version = self
            .version
            .checked_add(1)
            .ok_or(AuthorizationError::ResourceLimit)?;
        let entry = self
            .devices
            .get_mut(device)
            .filter(|entry| !entry.is_revoked)
            .ok_or(AuthorizationError::SignerNotTrusted)?;
        entry.is_revoked = true;
        self.version = next_version;
        Ok(())
    }
}

pub fn key_package_sha256(raw_key_package: &[u8]) -> [u8; 32] {
    Sha256::digest(raw_key_package).into()
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn validate_request_shape(request: &AuthorizationRequest) -> Result<(), AuthorizationError> {
    let lifetime = request
        .expires_at_unix_secs
        .checked_sub(request.issued_at_unix_secs);
    if [
        &request.service,
        &request.account,
        &request.signer_device,
        &request.new_device,
    ]
    .iter()
    .any(|value| !valid_id(value))
        || !matches!(lifetime, Some(1..=MAX_VALIDITY_SECONDS))
        || request.nonce == [0; 32]
    {
        return Err(AuthorizationError::InvalidRequest);
    }
    validating_key(&request.new_signature_key)?;
    Ok(())
}

fn validating_key(bytes: &[u8; 32]) -> Result<VerifyingKey, AuthorizationError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| AuthorizationError::InvalidPublicKey)?;
    if key.is_weak() {
        return Err(AuthorizationError::InvalidPublicKey);
    }
    Ok(key)
}

fn signing_bytes(request: &AuthorizationRequest) -> Result<Vec<u8>, AuthorizationError> {
    // 签固定结构序列化结果，避免签收包 JSON 的空格/字段顺序。域前缀隔离 MLS 用途。
    // 这只是锁定 serde_json 版本的 POC 编码，尚不是跨语言正式协议或规范化标准。
    let mut bytes = SIGNING_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(request).map_err(|_| AuthorizationError::InvalidRequest)?);
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidRequest,
    InvalidPublicKey,
    UnsupportedSignatureScheme,
    SigningFailed,
    WrongContext,
    OutsideValidity,
    NonceConsumed,
    WrongVersion,
    SignerNotTrusted,
    InvalidSignature,
    KeyPackageMismatch,
    DeviceAlreadyKnown,
    ReusedDeviceKey,
    ResourceLimit,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "device authorization rejected: {self:?}")
    }
}

impl std::error::Error for AuthorizationError {}

#[cfg(test)]
#[path = "authorization_tests.rs"]
mod tests;
