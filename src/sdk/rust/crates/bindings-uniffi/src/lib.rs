//! Swift/Kotlin共享生成绑定；密码和状态规则只由im-sdk持有。
use rocket_im_sdk::Device;
use std::{fmt, sync::Arc};

uniffi::setup_scaffolding!();

#[derive(Debug, uniffi::Error)]
pub enum DeviceError {
    Failure { code: String, device_poisoned: bool },
}
impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failure {
                code,
                device_poisoned,
            } => write!(f, "{code};device_poisoned={device_poisoned}"),
        }
    }
}
impl std::error::Error for DeviceError {}
impl From<rocket_im_sdk::Error> for DeviceError {
    fn from(error: rocket_im_sdk::Error) -> Self {
        Self::Failure {
            code: error.code.as_str().to_owned(),
            device_poisoned: error.device_poisoned,
        }
    }
}

#[uniffi::export]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// 仅内存的阶段0双设备组；方法同步且串行，调用方应避免阻塞UI线程。
/// close幂等；对象释放不导出秘密，也不提供崩溃恢复。
#[derive(uniffi::Object)]
pub struct NativeDevice {
    inner: Device,
}

#[uniffi::export]
impl NativeDevice {
    #[uniffi::constructor]
    pub fn new(
        service_id: String,
        account_id: String,
        device_id: String,
    ) -> Result<Arc<Self>, DeviceError> {
        Ok(Arc::new(Self {
            inner: Device::new(service_id, account_id, device_id)?,
        }))
    }
    pub fn identity_key(&self) -> Result<Vec<u8>, DeviceError> {
        self.inner.identity_key().map_err(Into::into)
    }
    pub fn key_package(&self) -> Result<Vec<u8>, DeviceError> {
        self.inner.key_package().map_err(Into::into)
    }
    pub fn create_group(
        &self,
        conversation_id: String,
        peer_account_id: String,
        peer_device_id: String,
        peer_identity_key: Vec<u8>,
        key_package: Vec<u8>,
    ) -> Result<Vec<u8>, DeviceError> {
        self.inner
            .create_group(
                conversation_id,
                peer_account_id,
                peer_device_id,
                peer_identity_key,
                key_package,
            )
            .map_err(Into::into)
    }
    pub fn join_group(
        &self,
        conversation_id: String,
        creator_account_id: String,
        creator_device_id: String,
        creator_identity_key: Vec<u8>,
        welcome: Vec<u8>,
    ) -> Result<(), DeviceError> {
        self.inner
            .join_group(
                conversation_id,
                creator_account_id,
                creator_device_id,
                creator_identity_key,
                welcome,
            )
            .map_err(Into::into)
    }
    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, DeviceError> {
        self.inner.encrypt(plaintext).map_err(Into::into)
    }
    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, DeviceError> {
        self.inner.decrypt(ciphertext).map_err(Into::into)
    }
    pub fn close_device(&self) -> Result<(), DeviceError> {
        self.inner.close().map_err(Into::into)
    }
}
