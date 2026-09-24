//! 合成本地独立锚；秘密保护与真实独立故障域仍不属于本实验保证。
mod client;
pub(crate) mod commitment;
mod coordinator;
pub(crate) mod database;
mod protocol;
mod rebuild;
mod rebuild_basis;
mod rebuild_options;
mod rebuild_protocol;
mod rebuild_store;

use crate::{
    crypto::store,
    protocol::{ApiError, Scope},
    StorageProbe,
};
use client::Client;
use js_sys::Function;
use serde_json::json;
use wasm_bindgen::prelude::*;

pub(super) fn error(code: &'static str) -> ApiError {
    ApiError::new(code, "独立锚未许可当前操作；请核对诊断并显式恢复。", false)
}

#[wasm_bindgen]
pub struct AnchorProbe {
    storage: StorageProbe,
    client: Client,
}

#[wasm_bindgen]
impl AnchorProbe {
    /// 配置来自浏览器备份范围之外的可信测试控制器；没有自动注册或身份创建。
    pub async fn open(
        service: String,
        account: String,
        test_mode: bool,
        config_json: String,
        rpc: Function,
    ) -> Result<AnchorProbe, JsValue> {
        let scope = Scope::new(service.clone(), account.clone()).map_err(ApiError::into_js)?;
        let client = Client::new(&config_json, &scope, rpc).map_err(ApiError::into_js)?;
        let mut storage = StorageProbe::open_existing(service, account, test_mode)
            .await
            .map_err(ApiError::into_js)?;
        let result = (|| {
            let connection = storage.connection.as_mut().ok_or_else(ApiError::closed)?;
            // 已有密码结构也只能核验，不把缺失密码表集当作首次使用。
            commitment::read(connection)?;
            store::initialize_schema(connection, &storage.scope)?;
            database::initialize(connection, &client)
        })();
        if let Err(error) = result {
            storage.close_inner().map_err(ApiError::into_js)?;
            return Err(error.into_js());
        }
        Ok(Self { storage, client })
    }

    /// 持久串行所有权跨网络等待保留，SQLite 事务和活动游标不跨 await。
    pub async fn execute(&mut self, request_json: String) -> String {
        let result = coordinator::execute(&mut self.storage, &self.client, &request_json).await;
        let value = match result {
            Ok(value) => json!({"ok":true,"result":value}),
            Err(error) => {
                self.storage.paused |= error.paused;
                json!({"ok":false,"error":error})
            }
        };
        serde_json::to_string(&value).unwrap_or_else(|_| {
            self.storage.paused = true;
            r#"{"ok":false,"error":{"code":"encoding_failed","message":"结果编码失败。","paused":true}}"#.into()
        })
    }

    pub fn close(&mut self) -> Result<(), JsValue> {
        self.storage.close_inner().map_err(ApiError::into_js)
    }

    #[wasm_bindgen(js_name = setCheckpointHook)]
    pub fn set_checkpoint_hook(&mut self, callback: Function) -> Result<(), JsValue> {
        self.storage.set_checkpoint_hook(callback)
    }
}
