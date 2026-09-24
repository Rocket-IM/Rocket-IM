//! Web与Node共用的同步WASM边界；调用方工作线程调度，存储不在本次最小发布范围。
use rocket_im_sdk::Device;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = sdkVersion)]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[wasm_bindgen]
pub struct Stage0Device {
    inner: Device,
}

#[wasm_bindgen]
impl Stage0Device {
    #[wasm_bindgen(constructor)]
    pub fn new(
        service_id: String,
        account_id: String,
        device_id: String,
    ) -> Result<Stage0Device, JsError> {
        Device::new(service_id, account_id, device_id)
            .map(|inner| Self { inner })
            .map_err(|e| JsError::new(&e.to_string()))
    }
    #[wasm_bindgen(js_name = identityKey)]
    pub fn identity_key(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .identity_key()
            .map_err(|e| JsError::new(&e.to_string()))
    }
    #[wasm_bindgen(js_name = keyPackage)]
    pub fn key_package(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .key_package()
            .map_err(|e| JsError::new(&e.to_string()))
    }
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(
        &self,
        conversation_id: String,
        peer_account_id: String,
        peer_device_id: String,
        peer_identity_key: Vec<u8>,
        key_package: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        self.inner
            .create_group(
                conversation_id,
                peer_account_id,
                peer_device_id,
                peer_identity_key,
                key_package,
            )
            .map_err(|e| JsError::new(&e.to_string()))
    }
    #[wasm_bindgen(js_name = joinGroup)]
    pub fn join_group(
        &self,
        conversation_id: String,
        creator_account_id: String,
        creator_device_id: String,
        creator_identity_key: Vec<u8>,
        welcome: Vec<u8>,
    ) -> Result<(), JsError> {
        self.inner
            .join_group(
                conversation_id,
                creator_account_id,
                creator_device_id,
                creator_identity_key,
                welcome,
            )
            .map_err(|e| JsError::new(&e.to_string()))
    }
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, JsError> {
        self.inner
            .encrypt(plaintext)
            .map_err(|e| JsError::new(&e.to_string()))
    }
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, JsError> {
        self.inner
            .decrypt(ciphertext)
            .map_err(|e| JsError::new(&e.to_string()))
    }
    #[wasm_bindgen(js_name = close)]
    pub fn close(&self) -> Result<(), JsError> {
        self.inner.close().map_err(|e| JsError::new(&e.to_string()))
    }
}
