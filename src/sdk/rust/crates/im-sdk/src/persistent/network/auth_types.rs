//! 宿主只提供业务认证结果；期限、关联和重试均由Rust持有，秘密不序列化到数据库。
use super::super::types::Scope;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationOptions {
    /// 单次宿主认证最长等待毫秒数，100..30000；不占SQLite线程。
    pub timeout_ms: u64,
    /// 含首次尝试，1..3；仅暂时失败/超时重试。
    pub max_attempts: u8,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCredential {
    pub scope: Scope,
    pub token: String,
    /// UTC Unix毫秒，十进制字符串；Service独立验证真实到期和授权。
    pub expires_at_unix_ms: String,
}
impl Drop for DeviceCredential {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticationResult {
    Credential { credential: DeviceCredential },
    Failure { code: AuthenticationFailure },
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationFailure {
    Unavailable,
    LoginRequired,
    Forbidden,
    Cancelled,
    InvalidCredential,
    ProviderFailed,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthenticationEvent {
    CredentialRequest {
        scope: Scope,
        request_id: String,
        reason: String,
        attempt: u8,
        timeout_ms: u64,
    },
    CredentialCancel {
        scope: Scope,
        request_id: String,
    },
}
