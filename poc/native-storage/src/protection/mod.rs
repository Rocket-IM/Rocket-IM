//! macOS 合成实验的系统秘密边界；公开 locator 仅定位，信任来自指定钥匙串项。
pub mod control;
mod keychain;
mod record;
mod sqlcipher;
#[cfg(test)]
mod tests;

use crate::{crypto::anchor::client::Config, crypto::contract::Scope, model::Result};
use record::{Locator, Record, Trust};
use std::path::Path;
use zeroize::Zeroizing;

const SERVICE: &str = "org.rocket-im.native-protected.v1";

#[derive(Clone)]
pub(crate) struct Guard {
    record: Record,
    saved: Zeroizing<Vec<u8>>,
    trust: Option<Trust>,
    saved_trust: Option<Zeroizing<Vec<u8>>>,
    parent: Option<Box<Guard>>,
}

impl Guard {
    pub(crate) fn create(
        path: &Path,
        scope: &Scope,
        locator: &str,
        purpose: Option<String>,
    ) -> Result<Self> {
        let location = Locator::parse(path, locator)?;
        location.check_scope(scope)?;
        if path.exists() {
            return Err(error("protected_store_exists"));
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(raw.as_mut()).map_err(|_| error("protected_random_failed"))?;
        let record = Record {
            version: 1,
            database: path.to_owned(),
            locator: location,
            purpose,
            key: Zeroizing::new(crate::crypto::anchor::protocol::encode_hex(raw.as_ref())),
        };
        let saved =
            Zeroizing::new(serde_json::to_vec(&record).map_err(|_| error("protected_encoding"))?);
        keychain::add(
            &record.locator.keychain,
            SERVICE,
            &record.locator.item,
            &saved,
        )?;
        // 此确认点之后失败留下孤立项，重试create必须拒绝，不能生成第二把钥。
        let this = Self {
            record,
            saved,
            trust: None,
            saved_trust: None,
            parent: None,
        };
        this.check()?;
        Ok(this)
    }
    pub(crate) fn open(
        path: &Path,
        scope: &Scope,
        locator: &str,
        purpose: Option<String>,
    ) -> Result<Self> {
        let this = Self::load(path, locator, purpose)?;
        this.record.locator.check_scope(scope)?;
        Ok(this)
    }
    pub(crate) fn load(path: &Path, locator: &str, purpose: Option<String>) -> Result<Self> {
        let location = Locator::parse(path, locator)?;
        let saved = Zeroizing::new(keychain::read(&location.keychain, SERVICE, &location.item)?);
        if saved.len() > 32768 {
            return Err(error("protected_record_invalid"));
        }
        let record: Record =
            serde_json::from_slice(&saved).map_err(|_| error("protected_record_invalid"))?;
        if record.version != 1
            || record.database != path
            || record.locator != location
            || record.purpose != purpose
        {
            return Err(error("protected_binding_mismatch"));
        }
        crate::crypto::anchor::protocol::decode_hex(&record.key)
            .map_err(|_| error("protected_key_invalid"))?;
        let saved_trust = read_trust(&record.locator)?;
        let trust = saved_trust
            .as_ref()
            .map(|bytes| Trust::parse(bytes, &record))
            .transpose()?;
        let this = Self {
            record,
            saved,
            trust,
            saved_trust,
            parent: None,
        };
        this.check()?;
        Ok(this)
    }
    pub(crate) fn scope(&self) -> Scope {
        self.record.locator.scope()
    }
    pub(crate) fn has_config(&self) -> bool {
        self.trust.is_some()
    }
    pub(crate) fn is_bootstrap(&self) -> bool {
        self.record.purpose.is_none() && !self.has_config()
    }
    pub(crate) fn config(&self) -> Result<Config> {
        self.trust
            .as_ref()
            .map(|trust| trust.config.clone())
            .ok_or_else(|| error("protected_trust_missing"))
    }
    pub(crate) fn pin_config(&self, json: &str) -> Result<Self> {
        self.check()?;
        let trust = Trust::new(json, &self.record)?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(&trust).map_err(|_| error("protected_encoding"))?);
        if let Some(old) = &self.saved_trust {
            if **old != *bytes {
                return Err(error("protected_trust_conflict"));
            }
            return Ok(self.clone());
        }
        keychain::add(
            &self.record.locator.keychain,
            SERVICE,
            &self.record.locator.trust_item(),
            &bytes,
        )?;
        let mut next = self.clone();
        next.trust = Some(trust);
        next.saved_trust = Some(bytes);
        next.check()?;
        Ok(next)
    }
    pub(crate) fn with_parent(mut self, parent: Self) -> Self {
        self.parent = Some(Box::new(parent));
        self
    }
    pub(crate) fn check(&self) -> Result<()> {
        if let Some(parent) = &self.parent {
            parent.check()?;
        }
        let current = Zeroizing::new(keychain::read(
            &self.record.locator.keychain,
            SERVICE,
            &self.record.locator.item,
        )?);
        if *current != *self.saved {
            return Err(error("protected_record_changed"));
        }
        if read_trust(&self.record.locator)? != self.saved_trust {
            return Err(error("protected_trust_changed"));
        }
        if let Some(trust) = &self.trust {
            trust.check(&self.record)?;
        }
        Ok(())
    }
    pub(crate) fn install(&self, connection: &rusqlite::Connection) -> Result<()> {
        sqlcipher::install(connection, &self.record.key)
    }
}

fn read_trust(location: &Locator) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match keychain::read(&location.keychain, SERVICE, &location.trust_item()) {
        Ok(bytes) if bytes.len() <= 32768 => Ok(Some(Zeroizing::new(bytes))),
        Ok(_) => Err(error("protected_trust_invalid")),
        Err(e) if e.code == "keychain_item_missing" => Ok(None),
        Err(e) => Err(e),
    }
}
pub(super) fn error(code: &str) -> crate::model::Error {
    crate::model::Error::new(code, true)
}
