//! 固定错误码；不透传第三方调试信息、明文或密钥。
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidArgument,
    InvalidEncoding,
    IdentityMismatch,
    ScopeMismatch,
    AlreadyGrouped,
    GroupRequired,
    Closed,
    Poisoned,
    CryptoFailure,
    LimitExceeded,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidEncoding => "invalid_encoding",
            Self::IdentityMismatch => "identity_mismatch",
            Self::ScopeMismatch => "scope_mismatch",
            Self::AlreadyGrouped => "already_grouped",
            Self::GroupRequired => "group_required",
            Self::Closed => "closed",
            Self::Poisoned => "poisoned",
            Self::CryptoFailure => "crypto_failure",
            Self::LimitExceeded => "limit_exceeded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: ErrorCode,
    /// true 表示可能已消耗密码状态，本设备实例只能关闭，不能重试密码操作。
    pub device_poisoned: bool,
}

impl Error {
    pub const fn new(code: ErrorCode) -> Self {
        Self {
            code,
            device_poisoned: false,
        }
    }
    pub const fn poisoned(code: ErrorCode) -> Self {
        Self {
            code,
            device_poisoned: true,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; device_poisoned={}",
            self.code.as_str(),
            self.device_poisoned
        )
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn require(condition: bool, code: ErrorCode) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::new(code))
    }
}
