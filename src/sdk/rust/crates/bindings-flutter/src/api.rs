//! Flutter公开边界，不执行网络或持久化操作。
use flutter_rust_bridge::frb;
use rocket_im_sdk::Device;

#[frb(sync)]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[frb(opaque)]
pub struct Stage0Device {
    inner: Device,
}

pub fn new_device(
    service_id: String,
    account_id: String,
    device_id: String,
) -> Result<Stage0Device, String> {
    Device::new(service_id, account_id, device_id)
        .map(|inner| Stage0Device { inner })
        .map_err(|e| e.to_string())
}
impl Stage0Device {
    pub fn identity_key(&self) -> Result<Vec<u8>, String> {
        self.inner.identity_key().map_err(|e| e.to_string())
    }
    pub fn key_package(&self) -> Result<Vec<u8>, String> {
        self.inner.key_package().map_err(|e| e.to_string())
    }
    pub fn create_group(
        &self,
        conversation_id: String,
        peer_account_id: String,
        peer_device_id: String,
        peer_identity_key: Vec<u8>,
        key_package: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.inner
            .create_group(
                conversation_id,
                peer_account_id,
                peer_device_id,
                peer_identity_key,
                key_package,
            )
            .map_err(|e| e.to_string())
    }
    pub fn join_group(
        &self,
        conversation_id: String,
        creator_account_id: String,
        creator_device_id: String,
        creator_identity_key: Vec<u8>,
        welcome: Vec<u8>,
    ) -> Result<(), String> {
        self.inner
            .join_group(
                conversation_id,
                creator_account_id,
                creator_device_id,
                creator_identity_key,
                welcome,
            )
            .map_err(|e| e.to_string())
    }
    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
        self.inner.encrypt(plaintext).map_err(|e| e.to_string())
    }
    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, String> {
        self.inner.decrypt(ciphertext).map_err(|e| e.to_string())
    }
    pub fn close(&self) -> Result<(), String> {
        self.inner.close().map_err(|e| e.to_string())
    }
}
