//! 阶段0发布验证的薄公共边界：每个设备单独串行访问密码核心，无UI、网络及持久恢复。
//! 所有操作同步完成；平台桥接应放在工作线程或浏览器Worker，避免阻塞UI。
use rockets_crypto_core::Device as CoreDevice;
pub use rockets_crypto_core::{Error, ErrorCode, MAX_MESSAGE_BYTES, MAX_PROTOCOL_BYTES, VERSION};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Mutex,
};
pub type Result<T> = std::result::Result<T, Error>;

pub struct Device {
    inner: Mutex<CoreDevice>,
}

impl Device {
    pub fn new(service_id: String, account_id: String, device_id: String) -> Result<Self> {
        let core = catch_unwind(AssertUnwindSafe(|| {
            CoreDevice::new(service_id, account_id, device_id)
        }))
        .map_err(|_| Error::poisoned(ErrorCode::Poisoned))??;
        Ok(Self {
            inner: Mutex::new(core),
        })
    }

    fn with<T>(&self, operation: impl FnOnce(&mut CoreDevice) -> Result<T>) -> Result<T> {
        let mut device = self
            .inner
            .lock()
            .map_err(|_| Error::poisoned(ErrorCode::Poisoned))?;
        match catch_unwind(AssertUnwindSafe(|| operation(&mut device))) {
            Ok(result) => result,
            Err(_) => {
                // 意外panic只使当前实例失效，不再暴露可能处于中间状态的核心。
                let _ = device.close();
                Err(Error::poisoned(ErrorCode::Poisoned))
            }
        }
    }

    pub fn identity_key(&self) -> Result<Vec<u8>> {
        self.with(|d| d.identity_key())
    }
    pub fn key_package(&self) -> Result<Vec<u8>> {
        self.with(|d| d.key_package())
    }

    pub fn create_group(
        &self,
        conversation_id: String,
        peer_account_id: String,
        peer_device_id: String,
        peer_identity_key: Vec<u8>,
        key_package: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.with(|d| {
            d.create_group(
                conversation_id,
                peer_account_id,
                peer_device_id,
                peer_identity_key,
                key_package,
            )
        })
    }

    pub fn join_group(
        &self,
        conversation_id: String,
        creator_account_id: String,
        creator_device_id: String,
        creator_identity_key: Vec<u8>,
        welcome: Vec<u8>,
    ) -> Result<()> {
        self.with(|d| {
            d.join_group(
                conversation_id,
                creator_account_id,
                creator_device_id,
                creator_identity_key,
                welcome,
            )
        })
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>> {
        self.with(|d| d.encrypt(plaintext))
    }
    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        self.with(|d| d.decrypt(ciphertext))
    }
    pub fn close(&self) -> Result<()> {
        self.with(|d| d.close())
    }
}

#[cfg(test)]
mod tests;
