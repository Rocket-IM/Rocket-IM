use ed25519_dalek::{SigningKey, VerifyingKey};
use js_sys::{Function, Promise};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use super::protocol::{self, Action, Request, Response, Scope, Signed, INPUT_LIMIT, PROTOCOL};
use crate::protocol::ApiError;

const JOURNAL_DOMAIN: &[u8] = b"Rocket-IM/browser-anchor-journal/v1\0";

/// 仅适用于合成本地锚实验；此可信配置必须保存在被回滚的浏览器数据库之外。
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Config {
    pub endpoint: String,
    pub scope: Scope,
    pub anchor_public_key: String,
    pub client_seed: String,
}

pub(super) struct Client {
    pub(super) config: Config,
    rpc: Function,
    signing_key: SigningKey,
    client_public_key: String,
    fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReply {
    ok: bool,
    response: Option<Signed>,
    error: Option<WireError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    code: String,
    message: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal<T> {
    fingerprint: String,
    value: T,
}

impl Client {
    pub(super) fn new(
        config_json: &str,
        scope: &crate::protocol::Scope,
        rpc: Function,
    ) -> Result<Self, ApiError> {
        if config_json.len() > 8 * 1024 {
            return Err(config_error());
        }
        let config: Config = serde_json::from_str(config_json).map_err(|_| config_error())?;
        config.scope.validate().map_err(|_| config_error())?;
        if config.scope.service != scope.service
            || config.scope.account != scope.account
            || config.scope.device != scope.device
        {
            return Err(config_error());
        }
        validate_endpoint(&config.endpoint)?;
        let key_bytes =
            protocol::decode_hex(&config.anchor_public_key).map_err(|_| config_error())?;
        let anchor_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| config_error())?;
        if anchor_key.is_weak() {
            return Err(config_error());
        }
        let seed = protocol::decode_hex(&config.client_seed).map_err(|_| config_error())?;
        let signing_key = SigningKey::from_bytes(&seed);
        let client_public_key = protocol::encode_hex(signing_key.verifying_key().as_bytes());
        // 不含认证 seed；固定域与数组位置使配置指纹无拼接歧义。
        let fingerprint = protocol::hash_bytes(
            &serde_json::to_vec(&(
                "Rocket-IM/browser-anchor-config/v1",
                &config.endpoint,
                &config.scope,
                &config.anchor_public_key,
                &client_public_key,
            ))
            .map_err(|_| config_error())?,
        );
        Ok(Self {
            config,
            rpc,
            signing_key,
            client_public_key,
            fingerprint,
        })
    }

    pub(super) fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    pub(super) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub(super) async fn rpc(
        &self,
        action: Action,
        txn: &str,
        head: &str,
        target: &str,
        expected_revision: &str,
    ) -> Result<Response, ApiError> {
        let request = Request {
            protocol_version: PROTOCOL.into(),
            scope: self.config.scope.clone(),
            challenge: protocol::random_hex()?,
            action,
            expected_revision: expected_revision.into(),
            txn: txn.into(),
            head: head.into(),
            target: target.into(),
        };
        let signed = protocol::sign_request(&request, &self.signing_key)?;
        let response = self.exchange(&signed).await?;
        protocol::verify_response(&response, &self.config.anchor_public_key, &signed)
    }

    pub(super) async fn exchange<T: Serialize>(&self, request: &T) -> Result<Signed, ApiError> {
        let request_json = serde_json::to_string(request).map_err(|_| protocol::invalid())?;
        if request_json.len() > INPUT_LIMIT {
            return Err(protocol::invalid());
        }
        // JS 只向相同配置的回环端点转发字节；即使伪造返回也须经过 Rust 验签。
        let promise = self
            .rpc
            .call1(&JsValue::UNDEFINED, &JsValue::from_str(&request_json))
            .map_err(|error| rpc_error().with_js(error))?
            .dyn_into::<Promise>()
            .map_err(|_| rpc_error())?;
        let returned = JsFuture::from(promise)
            .await
            .map_err(|error| rpc_error().with_js(error))?;
        let json = returned.as_string().ok_or_else(rpc_error)?;
        if json.len() > INPUT_LIMIT {
            return Err(protocol::invalid());
        }
        let reply: WireReply = serde_json::from_str(&json).map_err(|_| protocol::invalid())?;
        match (reply.ok, reply.response, reply.error) {
            (true, Some(response), None) => Ok(response),
            (false, None, Some(error)) if !error.code.is_empty() && !error.message.is_empty() => {
                // 远端原始文本不进入公开错误，避免它携带用户数据或诊断秘密。
                Err(ApiError::new(
                    "anchor_remote_error",
                    "独立锚明确拒绝请求。",
                    false,
                ))
            }
            _ => Err(protocol::invalid()),
        }
    }

    pub(super) fn sign_journal<T: Serialize>(&self, value: &T) -> Result<Signed, ApiError> {
        protocol::sign(
            &Journal {
                fingerprint: self.fingerprint(),
                value,
            },
            &self.signing_key,
            JOURNAL_DOMAIN,
        )
    }

    pub(super) fn verify_journal<T: DeserializeOwned>(
        &self,
        signed: &Signed,
    ) -> Result<T, ApiError> {
        let journal: Journal<T> =
            protocol::verify(signed, &self.client_public_key, JOURNAL_DOMAIN)?;
        if journal.fingerprint != self.fingerprint {
            return Err(ApiError::new(
                "anchor_journal_binding",
                "恢复日志不属于当前锚配置。",
                false,
            ));
        }
        Ok(journal.value)
    }
}

fn config_error() -> ApiError {
    ApiError::new("anchor_config", "锚可信实验配置无效或范围不匹配。", false)
}

fn rpc_error() -> ApiError {
    ApiError::new(
        "anchor_rpc_failed",
        "锚请求结果未知，请检查锚状态后恢复。",
        false,
    )
}

pub(super) fn validate_endpoint(endpoint: &str) -> Result<(), ApiError> {
    let port_text = endpoint
        .strip_prefix("http://127.0.0.1:")
        .and_then(|value| value.strip_suffix("/anchor"))
        .ok_or_else(config_error)?;
    let port: u16 = port_text.parse().map_err(|_| config_error())?;
    if port == 0 || port.to_string() != port_text {
        return Err(config_error());
    }
    Ok(())
}
