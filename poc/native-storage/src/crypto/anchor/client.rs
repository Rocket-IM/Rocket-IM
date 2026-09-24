//! 可信配置来自设备数据库之外；不自动注册、替换身份、重试或降级到普通入口。
use super::{protocol, signatures, transport};
use crate::model::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use protocol::{Action, Request, Response, Scope, Signed};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub program: PathBuf,
    pub directory: PathBuf,
    pub scope: Scope,
    pub anchor_public_key: String,
    pub client_seed: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuild_trust: Option<super::rebuild_protocol::RebuildTrust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuild_origin: Option<ControlTrust>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlTrust {
    pub client_public_key: String,
    pub fingerprint: String,
}

#[derive(Clone)]
pub(crate) struct Client {
    pub(crate) config: Config,
    pub(crate) signing_key: SigningKey,
    pub(crate) client_public_key: String,
    fingerprint: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Local<T> {
    fingerprint: String,
    value: T,
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

impl Client {
    pub(crate) fn new(config: Config) -> Result<Self> {
        config.scope.validate().map_err(|_| config_error())?;
        validate_path(&config.program, false)?;
        validate_path(&config.directory, true)?;
        let anchor_key = VerifyingKey::from_bytes(
            &protocol::decode_hex(&config.anchor_public_key).map_err(|_| config_error())?,
        )
        .map_err(|_| config_error())?;
        if anchor_key.is_weak() {
            return Err(config_error());
        }
        let signing_key = SigningKey::from_bytes(
            &protocol::decode_hex(&config.client_seed).map_err(|_| config_error())?,
        );
        let client_public_key = protocol::encode_hex(signing_key.verifying_key().as_bytes());
        let mut fingerprint = protocol::hash(
            &serde_json::to_vec(&(
                "Rockets-IM/native-anchor-config/v1",
                &config.program,
                &config.directory,
                &config.scope,
                &config.anchor_public_key,
                &client_public_key,
            ))
            .map_err(|_| config_error())?,
        );
        if let Some(trust) = &config.rebuild_trust {
            trust.validate(&config.scope)?;
            fingerprint = protocol::hash(
                &serde_json::to_vec(&(
                    "Rockets-IM/native-anchor-rebuild-trust/v1",
                    &fingerprint,
                    trust,
                ))
                .map_err(|_| config_error())?,
            );
        }
        if let Some(origin) = &config.rebuild_origin {
            protocol::decode_hex(&origin.client_public_key)?;
            protocol::decode_hex(&origin.fingerprint)?;
            fingerprint = protocol::hash(
                &serde_json::to_vec(&("Rockets-IM/native-rebuild-origin/v1", &fingerprint, origin))
                    .map_err(|_| config_error())?,
            );
        }
        Ok(Self {
            config,
            signing_key,
            client_public_key,
            fingerprint,
        })
    }

    pub(crate) fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    pub(crate) fn scope(&self) -> &Scope {
        &self.config.scope
    }

    pub(crate) fn sign_local<T: Serialize>(&self, value: &T) -> Result<String> {
        let signed = signatures::sign(
            &Local {
                fingerprint: self.fingerprint(),
                value,
            },
            &self.signing_key,
            signatures::LOCAL_DOMAIN,
            signatures::LOCAL_LIMIT,
        )?;
        let json = serde_json::to_string(&signed).map_err(|_| protocol::invalid())?;
        if json.len() > signatures::LOCAL_JSON_LIMIT {
            return Err(protocol::invalid());
        }
        Ok(json)
    }

    pub(crate) fn verify_local<T: DeserializeOwned>(&self, text: &str) -> Result<T> {
        if text.len() > signatures::LOCAL_JSON_LIMIT {
            return Err(protocol::invalid());
        }
        let signed: Signed = serde_json::from_str(text).map_err(|_| protocol::invalid())?;
        let local: Local<T> = signatures::verify(
            &signed,
            &self.client_public_key,
            signatures::LOCAL_DOMAIN,
            signatures::LOCAL_LIMIT,
        )?;
        if local.fingerprint != self.fingerprint {
            return Err(Error::new("anchor_journal_binding", true));
        }
        Ok(local.value)
    }

    /// 后继的控制记录沿用原可信客户端签名；新配置固定其公开验证材料。
    pub(crate) fn verify_control<T: DeserializeOwned>(&self, text: &str) -> Result<T> {
        let Some(origin) = &self.config.rebuild_origin else {
            return self.verify_local(text);
        };
        if text.len() > signatures::LOCAL_JSON_LIMIT {
            return Err(protocol::invalid());
        }
        let signed: Signed = serde_json::from_str(text).map_err(|_| protocol::invalid())?;
        let local: Local<T> = signatures::verify(
            &signed,
            &origin.client_public_key,
            signatures::LOCAL_DOMAIN,
            signatures::LOCAL_LIMIT,
        )?;
        if local.fingerprint != origin.fingerprint {
            return Err(Error::new("rebuild_control_binding", true));
        }
        Ok(local.value)
    }

    pub(crate) fn rpc(
        &self,
        action: Action,
        txn: &str,
        head: &str,
        target: &str,
        expected_revision: &str,
    ) -> Result<Response> {
        let request = Request {
            protocol_version: protocol::PROTOCOL.into(),
            scope: self.config.scope.clone(),
            challenge: protocol::random_hex()?,
            action,
            expected_revision: expected_revision.into(),
            txn: txn.into(),
            head: head.into(),
            target: target.into(),
        };
        let signed = signatures::sign_request(&request, &self.signing_key)?;
        // 配置中的 client seed 从不发送给 helper；只交付签名请求和既定锚路径。
        let input = serde_json::to_vec(&serde_json::json!({
            "op":"request", "directory":self.config.directory, "request":signed,
        }))
        .map_err(|_| protocol::invalid())?;
        if input.len() > protocol::INPUT_LIMIT {
            return Err(protocol::invalid());
        }
        let output = transport::exchange(&self.config.program, &input)?;
        if output.stdout.trim().is_empty() {
            return Err(Error::new("anchor_rpc_failed", true));
        }
        if output.stdout.len() > protocol::INPUT_LIMIT {
            return Err(protocol::invalid());
        }
        let reply: WireReply =
            serde_json::from_str(&output.stdout).map_err(|_| protocol::invalid())?;
        let response = match (output.success, reply.ok, reply.response, reply.error) {
            (true, true, Some(response), None) => response,
            (_, false, None, Some(error))
                if !error.code.is_empty()
                    && error.code.len() <= 1024
                    && !error.message.is_empty()
                    && error.message.len() <= 1024 =>
            {
                return Err(Error::new("anchor_remote_error", true));
            }
            _ => return Err(Error::new("anchor_rpc_failed", true)),
        };
        signatures::verify_response(&response, &self.config.anchor_public_key, &signed)
    }
}

fn config_error() -> Error {
    Error::new("anchor_config", true)
}

fn validate_path(path: &Path, directory: bool) -> Result<()> {
    let text = path.to_str().ok_or_else(config_error)?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.contains('\0')
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(config_error());
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if directory && error.kind() == std::io::ErrorKind::NotFound => {
            // 首次绑定先取得 head，再由独立夹具创建锚；本入口绝不自动建目录。
            let parent = path.parent().ok_or_else(config_error)?;
            let metadata = fs::symlink_metadata(parent).map_err(|_| config_error())?;
            return if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(config_error())
            };
        }
        Err(_) => return Err(config_error()),
    };
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(config_error());
    }
    #[cfg(unix)]
    if !directory {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(config_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn local_records_bind_configuration_and_reject_secret_config_fields() {
        let directory = std::env::current_dir().unwrap();
        let program = std::env::current_exe().unwrap();
        let key = SigningKey::from_bytes(&[43; 32]);
        let mut config = Config {
            program,
            directory,
            scope: protocol::tests::request().scope,
            anchor_public_key: protocol::encode_hex(key.verifying_key().as_bytes()),
            client_seed: "2a".repeat(32),
            rebuild_trust: None,
            rebuild_origin: None,
        };
        let client = Client::new(config.clone()).unwrap();
        let absent = config
            .directory
            .join(format!("absent-anchor-{}", protocol::random_hex().unwrap()));
        let mut bootstrap = config.clone();
        bootstrap.directory = absent.clone();
        assert!(Client::new(bootstrap.clone()).is_ok());
        assert!(!absent.exists());
        bootstrap.directory = absent.join("missing-parent");
        assert!(Client::new(bootstrap).is_err());
        let signed = client.sign_local(&json!({"outcome":"saved"})).unwrap();
        assert_eq!(
            client.verify_local::<Value>(&signed).unwrap()["outcome"],
            "saved"
        );
        config.scope.store_id = "ff".repeat(32);
        let other = Client::new(config.clone()).unwrap();
        assert_eq!(
            other.verify_local::<Value>(&signed).unwrap_err().code,
            "anchor_journal_binding"
        );
        assert!(client
            .verify_local::<Value>(&" ".repeat(signatures::LOCAL_JSON_LIMIT + 1))
            .is_err());
        config.anchor_public_key = "00".repeat(32);
        assert!(Client::new(config).is_err());
        assert!(serde_json::from_value::<Config>(json!({"unexpected":true})).is_err());
    }
}
