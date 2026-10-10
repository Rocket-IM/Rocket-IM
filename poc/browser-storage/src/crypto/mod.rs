//! 用本轮生成的实验身份验证密码状态与消息的原子提交。
//! SQLite 同库预约不防整库回滚；OPFS 不等于秘密保护或旧钥安全擦除。

mod engine;
pub(crate) mod model;
mod operations;
pub(crate) mod preflight;
mod query;
pub(crate) mod requests;
mod schema;
pub(crate) mod store;

use js_sys::Function;
use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::{protocol::ApiError, StorageProbe};
use requests::{Action, Request};

/// 一个测试设备、一个双成员群；复用既有 Rust SQLite 所有者和范围占用。
#[wasm_bindgen]
pub struct CryptoProbe {
    storage: StorageProbe,
}

#[wasm_bindgen]
impl CryptoProbe {
    /// 打开只建立空实验结构；身份必须显式 initialize，不自动替换丢失的旧身份。
    pub async fn open(
        service: String,
        account: String,
        test_mode: bool,
    ) -> Result<CryptoProbe, JsValue> {
        let mut storage = StorageProbe::open_inner(service, account, test_mode, false, false)
            .await
            .map_err(ApiError::into_js)?;
        let connection = storage
            .connection
            .as_mut()
            .ok_or_else(|| ApiError::closed().into_js())?;
        if let Err(error) = crate::anchor::database::reject_bound(connection) {
            storage.close_inner().map_err(ApiError::into_js)?;
            return Err(error.into_js());
        }
        if let Err(error) = store::initialize_schema(connection, &storage.scope) {
            storage.close_inner().map_err(ApiError::into_js)?;
            return Err(error.into_js());
        }
        Ok(Self { storage })
    }

    /// 所有输出均为拥有所有权的公开值；完整 provider 和私钥不穿过 FFI。
    pub fn execute(&mut self, request_json: String) -> String {
        let result = self.execute_inner(&request_json);
        let value = match result {
            Ok(value) => json!({"ok": true, "result": value}),
            Err(error) => {
                self.storage.paused |= error.paused;
                json!({"ok": false, "error": error})
            }
        };
        match serde_json::to_string(&value) {
            Ok(value) => value,
            Err(_) => {
                self.storage.paused = true;
                r#"{"ok":false,"error":{"code":"encoding_failed","message":"结果编码失败，请关闭实例。","paused":true}}"#.into()
            }
        }
    }

    /// 关闭不会解除未决密码预约；重开也只能检查已提交状态。
    pub fn close(&mut self) -> Result<(), JsValue> {
        self.storage.close_inner().map_err(ApiError::into_js)
    }

    #[wasm_bindgen(js_name = setCheckpointHook)]
    pub fn set_checkpoint_hook(&mut self, callback: Function) -> Result<(), JsValue> {
        self.storage.set_checkpoint_hook(callback)
    }
}

impl CryptoProbe {
    fn execute_inner(&mut self, json: &str) -> Result<serde_json::Value, ApiError> {
        let request = Request::parse(json, self.storage.test_mode)?;
        // 暂停后仍可检查已提交记录；检查路径不导入或调用密码引擎。
        if !matches!(&request.action, Action::Inspect) {
            self.storage.ensure_available()?;
        }
        let connection = self
            .storage
            .connection
            .as_mut()
            .ok_or_else(ApiError::closed)?;
        let mut value = store::execute(
            connection,
            &self.storage.scope,
            request,
            self.storage.checkpoint.as_ref(),
        )?;
        if self.storage.test_mode {
            value["commitment"] = crate::anchor::commitment::read(connection)?.into();
        }
        Ok(value)
    }
}
