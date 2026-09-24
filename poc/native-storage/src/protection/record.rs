//! 固定路径、账号空间、可信helper字节与不可变配置，不以数据库自报公钥引导信任。
use super::error;
use crate::{
    crypto::{
        anchor::client::{Client, Config},
        contract::{validate_id, Scope},
    },
    model::Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Locator {
    pub keychain: PathBuf,
    pub item: String,
    pub service: String,
    pub account: String,
    pub device: String,
}
impl Locator {
    pub fn parse(database: &Path, json: &str) -> Result<Self> {
        if json.len() > 16384 {
            return Err(error("protected_locator_invalid"));
        }
        let this: Self =
            serde_json::from_str(json).map_err(|_| error("protected_locator_invalid"))?;
        for value in [&this.item, &this.service, &this.account, &this.device] {
            validate_id(value).map_err(|_| error("protected_locator_invalid"))?;
        }
        if !this.item.starts_with("lab-") || this.item.ends_with(".trust") {
            return Err(error("protected_lab_item_required"));
        }
        checked_path(database)?;
        checked_path(&this.keychain)?;
        if !this
            .keychain
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|name| name.starts_with("lab-") && name.ends_with(".keychain-db"))
        {
            return Err(error("protected_lab_keychain_required"));
        }
        Ok(this)
    }
    pub fn trust_item(&self) -> String {
        format!("{}.trust", self.item)
    }
    pub fn scope(&self) -> Scope {
        Scope {
            service: self.service.clone(),
            account: self.account.clone(),
            device: self.device.clone(),
        }
    }
    pub fn check_scope(&self, scope: &Scope) -> Result<()> {
        if self.service != scope.service
            || self.account != scope.account
            || self.device != scope.device
        {
            Err(error("protected_scope_mismatch"))
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u32,
    pub database: PathBuf,
    pub locator: Locator,
    pub purpose: Option<String>,
    pub key: Zeroizing<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Trust {
    pub version: u32,
    pub database: PathBuf,
    pub key_id: String,
    pub config: Config,
    pub program_sha256: String,
}
impl Trust {
    pub fn new(json: &str, record: &Record) -> Result<Self> {
        if json.len() > 16384 {
            return Err(error("protected_trust_invalid"));
        }
        let config: Config =
            serde_json::from_str(json).map_err(|_| error("protected_trust_invalid"))?;
        let this = Self {
            version: 1,
            database: record.database.clone(),
            key_id: super::super::crypto::anchor::protocol::hash(record.key.as_bytes()),
            program_sha256: program_hash(&config.program)?,
            config,
        };
        this.check(record)?;
        Ok(this)
    }
    pub fn parse(bytes: &[u8], record: &Record) -> Result<Self> {
        let this: Self =
            serde_json::from_slice(bytes).map_err(|_| error("protected_trust_invalid"))?;
        this.check(record)?;
        Ok(this)
    }
    pub fn check(&self, record: &Record) -> Result<()> {
        let client = Client::new(self.config.clone())?;
        if self.version != 1
            || self.database != record.database
            || self.key_id != crate::crypto::anchor::protocol::hash(record.key.as_bytes())
            || client.config.scope.service != record.locator.service
            || client.config.scope.account != record.locator.account
            || client.config.scope.device != record.locator.device
        {
            return Err(error("protected_trust_binding"));
        }
        if program_hash(&self.config.program)? != self.program_sha256 {
            return Err(error("protected_program_changed"));
        }
        Ok(())
    }
}
fn program_hash(path: &Path) -> Result<String> {
    checked_path(path)?;
    let mut file = fs::File::open(path).map_err(|_| error("protected_program_unavailable"))?;
    let length = file
        .metadata()
        .map_err(|_| error("protected_program_unavailable"))?
        .len();
    if length == 0 || length > 128 * 1024 * 1024 {
        return Err(error("protected_program_invalid"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0;
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| error("protected_program_unavailable"))?;
        if n == 0 {
            break;
        }
        count += n;
        if count > 128 * 1024 * 1024 {
            return Err(error("protected_program_invalid"));
        }
        hash.update(&buffer[..n]);
    }
    Ok(crate::crypto::anchor::protocol::encode_hex(
        &hash.finalize(),
    ))
}
pub(super) fn checked_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(error("protected_path_invalid"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| error("protected_path_invalid"))?;
    if fs::canonicalize(parent).map_err(|_| error("protected_path_invalid"))? != parent {
        return Err(error("protected_path_invalid"));
    }
    match fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => Err(error("protected_path_invalid")),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(error("protected_path_invalid")),
    }
}
