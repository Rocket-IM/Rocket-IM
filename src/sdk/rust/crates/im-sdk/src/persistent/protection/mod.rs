//! macOS 文件钥匙串 + SQLCipher。文件钥匙串是显式测试边界，不使用默认登录钥匙串。
#[cfg(feature = "persistent-test-hooks")]
mod audit;
mod keychain;
mod lease;
mod progress;
use super::types::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::PathBuf,
};
use zeroize::Zeroizing;

const PURPOSE: &str = "org.rocket-im.sdk.sqlcipher.v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    purpose: String,
    scope: Scope,
    path: PathBuf,
    key: Option<String>,
}
impl Drop for Record {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}
pub(super) struct Protection {
    path: PathBuf,
    keychain: PathBuf,
    scope: Scope,
    item: String,
    fingerprint: String,
}
impl Protection {
    pub fn lease(&self, exclusive: bool) -> Result<File> {
        lease::acquire(&self.path.with_extension("db.lease"), exclusive)
    }
    pub fn database_path(&self) -> &std::path::Path {
        &self.path
    }
    pub fn encryption_key(&self) -> Result<Zeroizing<String>> {
        self.check()?;
        let (mut record, _) = self.record()?;
        Ok(Zeroizing::new(
            record
                .key
                .take()
                .ok_or_else(|| Error::paused("logged_out"))?,
        ))
    }
    pub fn locator(path: PathBuf, scope: Scope, keychain: PathBuf) -> Result<Self> {
        scope.validate()?;
        let parent = path.parent().ok_or_else(|| Error::new("invalid_path"))?;
        if !path.is_absolute()
            || fs::canonicalize(parent).ok().as_deref() != Some(parent)
            || path.file_name().is_none()
        {
            return Err(Error::new("canonical_path_required"));
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if !meta.is_file() {
                return Err(Error::new("store_invalid"));
            }
        }
        let item = hash(&encode(&(PURPOSE, &scope, &path))?);
        Ok(Self {
            path,
            keychain,
            scope,
            item,
            fingerprint: String::new(),
        })
    }
    /// 每个数据库空间的跨进程短作业锁。锁文件无秘密，退出后保留，防止 inode 换代绕过互斥。
    pub fn lock(&self) -> Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.path.with_extension("db.access");
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file()) {
            return Err(Error::paused("protection_lock_failed"));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|_| Error::paused("protection_lock_failed"))?;
        if !fs::symlink_metadata(&path)
            .map_err(|_| Error::paused("protection_lock_failed"))?
            .is_file()
        {
            return Err(Error::paused("protection_lock_failed"));
        }
        let start = std::time::Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) if start.elapsed().as_millis() < 100 => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(fs::TryLockError::WouldBlock) => return Err(Error::paused("protection_busy")),
                Err(_) => return Err(Error::paused("protection_lock_failed")),
            }
        }
        Ok(file)
    }
    fn record(&self) -> Result<(Record, Zeroizing<Vec<u8>>)> {
        let bytes = Zeroizing::new(keychain::read(&self.keychain, PURPOSE, &self.item)?);
        let record: Record = decode(&bytes)?;
        if record.version != 1
            || record.purpose != PURPOSE
            || record.scope != self.scope
            || record.path != self.path
        {
            return Err(Error::paused("protection_binding_mismatch"));
        }
        Ok((record, bytes))
    }
    pub fn prepare(&mut self, create: bool) -> Result<Zeroizing<String>> {
        if create {
            if self.path.exists() {
                return Err(Error::new("store_exists"));
            }
            let mut random = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(random.as_mut())
                .map_err(|_| Error::paused("random_unavailable"))?;
            let mut record = Record {
                version: 1,
                purpose: PURPOSE.into(),
                scope: self.scope.clone(),
                path: self.path.clone(),
                key: Some(hex(&*random)),
            };
            let bytes = Zeroizing::new(encode(&record)?);
            keychain::add(&self.keychain, PURPOSE, &self.item, &bytes)?;
            if let Some(key) = record.key.as_mut() {
                use zeroize::Zeroize;
                key.zeroize();
            }
            super::checkpoint("after_protection_create");
        } else {
            let mut header = [0; 16];
            if let Ok(mut file) = File::open(&self.path) {
                if file.read_exact(&mut header).is_ok() && &header == b"SQLite format 3\0" {
                    return Err(Error::paused("plaintext_migration_required"));
                }
            }
        }
        let (mut record, bytes) = self.record()?;
        let key = Zeroizing::new(
            record
                .key
                .take()
                .ok_or_else(|| Error::paused("logged_out"))?,
        );
        if key.len() != 64
            || !key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::paused("protection_key_invalid"));
        }
        self.fingerprint = hash(&bytes);
        Ok(key)
    }
    pub fn check(&self) -> Result<()> {
        let (mut record, bytes) = self.record()?;
        let _key = Zeroizing::new(
            record
                .key
                .take()
                .ok_or_else(|| Error::paused("logged_out"))?,
        );
        if hash(&bytes) != self.fingerprint {
            return Err(Error::paused("protection_key_replaced"));
        }
        Ok(())
    }
    pub fn logout(&self) -> Result<()> {
        let (mut record, bytes) = self.record()?;
        if record.key.is_none() {
            return Ok(());
        }
        let _key = Zeroizing::new(record.key.take());
        if !self.fingerprint.is_empty() && hash(&bytes) != self.fingerprint {
            return Err(Error::paused("protection_key_replaced"));
        }
        super::checkpoint("before_logout_replace");
        keychain::replace(&self.keychain, PURPOSE, &self.item, &encode(&record)?)?;
        super::checkpoint("after_logout_replace");
        let (record, _) = self.record()?;
        if record.key.is_some() {
            return Err(Error::paused("logout_unconfirmed"));
        }
        Ok(())
    }
    pub fn confirm_logout(&self) -> Result<()> {
        let (mut record, _) = self.record()?;
        let key = Zeroizing::new(record.key.take());
        if key.is_some() {
            return Err(Error::paused("logout_required"));
        }
        Ok(())
    }
}
pub(super) fn install(connection: &rusqlite::Connection, key: &str) -> Result<()> {
    let raw = Zeroizing::new(format!("x'{key}'"));
    // SAFETY: 当前数据库线程独占有效连接，输入字节存活到 SQLCipher 同步复制完毕。
    let status = unsafe {
        rusqlite::ffi::sqlite3_key_v2(
            connection.handle(),
            c"main".as_ptr(),
            raw.as_ptr().cast(),
            raw.len() as i32,
        )
    };
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(Error::paused("protection_key_rejected"));
    }
    // 连接配置不读取业务数据或结构；实际 codec/schema 验证在显式事务中。
    connection.execute_batch("PRAGMA cipher_log_level=NONE; PRAGMA cipher_memory_security=ON; PRAGMA temp_store=MEMORY; PRAGMA synchronous=FULL;")?;
    Ok(())
}
