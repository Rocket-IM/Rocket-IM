//! SQLite 只在专属线程打开；所有结构/数据读取写入均使用显式事务。
use super::{
    data::{Data, Saved, MAX_DATA},
    types::*,
};
use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};
use std::{fs, path::Path, time::Duration};
pub(super) const MAX_META: usize = 32 * 1024 * 1024;
pub(super) const APP_ID: i64 = 0x52495031;
pub(super) const SCHEMA: &str = "CREATE TABLE sdk_state (id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL, crypto BLOB NOT NULL, digest TEXT NOT NULL, recovery BLOB NOT NULL);";

pub(super) struct Store {
    pub(super) connection: Connection,
    pub(super) scope: Scope,
    history_space: String,
    #[cfg(feature = "protected-storage")]
    pub(super) protection: Option<super::protection::Protection>,
    #[cfg(feature = "protected-storage")]
    _lease: Option<fs::File>,
}
impl Store {
    pub fn open(
        path: &Path,
        scope: Scope,
        create: bool,
        migrate: bool,
        keychain: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        scope.validate()?;
        if !path.is_absolute() || path.as_os_str().is_empty() {
            return Err(Error::new("invalid_path"));
        }
        #[cfg(feature = "protected-storage")]
        let mut protection = keychain
            .map(|k| super::protection::Protection::locator(path.to_path_buf(), scope.clone(), k))
            .transpose()?;
        #[cfg(feature = "protected-storage")]
        let lease = protection.as_ref().map(|p| p.lease(false)).transpose()?;
        #[cfg(feature = "protected-storage")]
        let _access_lock = protection.as_ref().map(|p| p.lock()).transpose()?;
        #[cfg(feature = "protected-storage")]
        let key = protection.as_mut().map(|p| p.prepare(create)).transpose()?;
        #[cfg(not(feature = "protected-storage"))]
        if keychain.is_some() {
            return Err(Error::paused("protection_unavailable"));
        }
        #[cfg(feature = "protected-storage")]
        let protected = protection.is_some();
        #[cfg(not(feature = "protected-storage"))]
        let protected = false;
        if create {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path).map_err(|e| {
                Error::new(if e.kind() == std::io::ErrorKind::AlreadyExists {
                    "store_exists"
                } else {
                    "store_create_failed"
                })
            })?;
        } else {
            let meta = fs::symlink_metadata(path).map_err(|_| Error::new("store_missing"))?;
            if !meta.is_file() || meta.len() == 0 {
                return Err(Error::paused("store_invalid"));
            }
        }
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        #[cfg(feature = "protected-storage")]
        if let Some(key) = key {
            super::protection::install(&connection, &key)?;
        }
        connection.busy_timeout(Duration::from_millis(100))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if protected {
            let version: String = tx.query_row("PRAGMA cipher_version", [], |r| r.get(0))?;
            let mode: String = tx.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
            let temp: i64 = tx.query_row("PRAGMA temp_store", [], |r| r.get(0))?;
            let memory: String = tx.query_row("PRAGMA cipher_memory_security", [], |r| r.get(0))?;
            if !version.starts_with("4.14.0")
                || mode != "delete"
                || temp != 2
                || !matches!(memory.as_str(), "1" | "on" | "ON")
            {
                return Err(Error::paused("protected_configuration_invalid"));
            }
        }
        if create {
            tx.execute_batch("PRAGMA application_id=1380536369; PRAGMA user_version=2; CREATE TABLE sdk_state (id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL, crypto BLOB NOT NULL, digest TEXT NOT NULL, recovery BLOB NOT NULL);")?;
            if protected {
                tx.execute_batch("PRAGMA user_version=3;")?;
            }
            let saved = Saved {
                data: Data::empty(scope.clone()),
                crypto: vec![],
                meta: super::recovery_types::Meta::default(),
            };
            write(&tx, &saved)?;
        } else {
            let app: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
            let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if app != APP_ID
                || (if protected {
                    !matches!(version, 3..=5)
                } else {
                    !matches!(version, 1 | 2 | 5)
                })
            {
                return Err(Error::paused("store_format_unsupported"));
            }
            let names: String = tx.query_row(
                "SELECT group_concat(name, ',') FROM sqlite_schema WHERE type='table'",
                [],
                |r| r.get(0),
            )?;
            if names != "sdk_state" {
                return Err(Error::paused("store_invalid"));
            }
            if version == 1 {
                if !migrate {
                    return Err(Error::paused("migration_required"));
                }
                let (data, crypto, digest): (Vec<u8>, Vec<u8>, String) = tx.query_row(
                    "SELECT data,crypto,digest FROM sdk_state WHERE id=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                if data.len() > MAX_DATA
                    || crypto.len() > 4 * 1024 * 1024
                    || digest != hash(&[data.as_slice(), crypto.as_slice()].concat())
                {
                    return Err(Error::paused("store_invalid"));
                }
                let parsed: Data = decode(&data)?;
                parsed.validate(&crypto)?;
                if parsed.state.scope != scope {
                    return Err(Error::new("scope_mismatch"));
                }
                let saved = Saved {
                    data: parsed,
                    crypto: crypto.clone(),
                    meta: super::recovery_types::Meta {
                        legacy: Some(super::recovery_types::Legacy {
                            data,
                            crypto,
                            digest,
                        }),
                        ..Default::default()
                    },
                };
                tx.execute_batch("ALTER TABLE sdk_state ADD COLUMN recovery BLOB NOT NULL DEFAULT X''; PRAGMA user_version=2;")?;
                write(&tx, &saved)?;
                super::checkpoint("before_migration_commit");
            }
            let saved = load(&tx, &scope)?;
            if (version == 5) != saved.data.has_rejections()
                || (!protected && saved.meta.backup_guard.is_some())
                || (version != 5 && (version == 4) != saved.meta.backup_guard.is_some())
            {
                return Err(Error::paused("store_invalid"));
            }
            #[cfg(feature = "protected-storage")]
            if let Some(p) = &protection {
                let mut saved = saved;
                if p.resume_activation(&mut saved)? {
                    tx.execute_batch("PRAGMA user_version=4;")?;
                    write(&tx, &saved)?;
                }
            }
        }
        tx.commit()?;
        if migrate {
            super::checkpoint("after_migration_commit");
        }
        #[cfg(feature = "protected-storage")]
        if let Some(p) = &protection {
            p.check()?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            p.check_progress(&load(&tx, &scope)?)?;
            tx.commit()?;
        }
        Ok(Self {
            connection,
            scope,
            history_space: hash(&encode(
                &fs::canonicalize(path).map_err(|_| Error::new("invalid_path"))?,
            )?),
            #[cfg(feature = "protected-storage")]
            protection,
            #[cfg(feature = "protected-storage")]
            _lease: lease,
        })
    }
    pub fn lock_access(&self) -> Result<Option<fs::File>> {
        #[cfg(feature = "protected-storage")]
        if let Some(p) = &self.protection {
            return p.lock().map(Some);
        }
        Ok(None)
    }
    pub fn history_space(&self) -> &str {
        &self.history_space
    }
    pub fn check_access(&self) -> Result<()> {
        #[cfg(feature = "protected-storage")]
        if let Some(p) = &self.protection {
            return p.check();
        }
        Ok(())
    }
    #[cfg(all(feature = "protected-storage", feature = "persistent-test-hooks"))]
    pub fn audit_protection(&mut self) -> Result<serde_json::Value> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let saved = load(&tx, &self.scope)?;
        let cipher: String = tx.query_row("PRAGMA cipher_version", [], |r| r.get(0))?;
        let sqlite: String = tx.query_row("SELECT sqlite_version()", [], |r| r.get(0))?;
        let mode: String = tx.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        let temp: i64 = tx.query_row("PRAGMA temp_store", [], |r| r.get(0))?;
        tx.commit()?;
        let mut result = self
            .protection
            .as_ref()
            .ok_or_else(|| Error::new("protection_required"))?
            .audit(&saved, true)?;
        result["configuration"] =
            serde_json::json!({"cipher":cipher,"sqlite":sqlite,"journal":mode,"temp_store":temp});
        Ok(result)
    }
    #[cfg(feature = "protected-storage")]
    pub fn logout(&self) -> Result<()> {
        let _lock = self.lock_access()?;
        self.protection
            .as_ref()
            .ok_or_else(|| Error::new("protection_required"))?
            .logout()
    }
    pub fn read<T>(&mut self, f: impl FnOnce(Saved) -> Result<T>) -> Result<T> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let saved = load(&tx, &self.scope)?;
        #[cfg(feature = "protected-storage")]
        if let Some(p) = &self.protection {
            p.check_progress(&saved)?;
        }
        let value = f(saved)?;
        tx.commit()?;
        Ok(value)
    }
    pub fn update<T>(
        &mut self,
        committing: bool,
        f: impl FnOnce(&mut Saved) -> Result<T>,
    ) -> Result<T> {
        #[cfg(feature = "persistent-test-hooks")]
        if committing
            && std::env::var("ROCKET_IM_TEST_COMMIT_FAILURE")
                .ok()
                .as_deref()
                == Some("1")
        {
            self.connection.commit_hook(Some(|| true))?;
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut saved = load(&tx, &self.scope)?;
        #[cfg(feature = "protected-storage")]
        let before = saved.clone();
        #[cfg(feature = "protected-storage")]
        if let Some(p) = &self.protection {
            p.check_progress(&saved)?;
        }
        let value = f(&mut saved)?;
        write(&tx, &saved)?;
        #[cfg(feature = "protected-storage")]
        if let Some(p) = &self.protection {
            p.prepare_progress(&before, &saved)?;
        }
        #[cfg(all(feature = "protected-storage", feature = "persistent-test-hooks"))]
        if let (Some(protection), Ok(path)) =
            (&self.protection, std::env::var("ROCKET_IM_TEST_AUDIT"))
        {
            // 在实际写事务内扫描真实回滚日志；只有测试程序具有此观察器。
            let audit = protection.audit(&saved, false)?;
            fs::write(path, encode(&audit)?).map_err(|_| Error::new("audit_write_failed"))?;
        }
        #[cfg(feature = "persistent-test-hooks")]
        if std::env::var("ROCKET_IM_TEST_JOURNAL_FAILURE")
            .ok()
            .as_deref()
            == Some("1")
            && saved
                .meta
                .journal
                .as_ref()
                .is_some_and(|j| j.candidate.is_some())
        {
            tx.commit_hook(Some(|| true))?;
        }
        #[cfg(feature = "persistent-test-hooks")]
        if let (Ok(phase), Some(session)) = (
            std::env::var("ROCKET_IM_TEST_RECOVERY_FAILURE"),
            &saved.meta.session,
        ) {
            if encode(&session.phase)? == encode(&phase)? {
                tx.commit_hook(Some(|| true))?;
            }
        }
        if committing {
            super::checkpoint("before_commit");
        }
        tx.commit()?;
        #[cfg(feature = "protected-storage")]
        if let Some(p) = &self.protection {
            super::checkpoint("backup_after_sql_commit");
            p.check_progress(&saved)?;
            super::checkpoint("backup_after_progress_confirm");
        }
        if committing {
            super::checkpoint("after_commit");
        }
        Ok(value)
    }
}
pub(super) fn load(tx: &Transaction<'_>, scope: &Scope) -> Result<Saved> {
    let (data, crypto, digest, meta): (Vec<u8>, Vec<u8>, String, Vec<u8>) = tx.query_row(
        "SELECT data, crypto, digest, recovery FROM sdk_state WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    if data.len() > MAX_DATA
        || crypto.len() > 4 * 1024 * 1024
        || meta.len() > MAX_META
        || digest != hash(&[data.as_slice(), crypto.as_slice(), meta.as_slice()].concat())
    {
        return Err(Error::paused("store_invalid"));
    }
    let data: Data = decode(&data)?;
    if &data.state.scope != scope {
        return Err(Error::new("scope_mismatch"));
    }
    data.validate(&crypto)?;
    let meta: super::recovery_types::Meta = decode(&meta)?;
    meta.validate(&data, &crypto)?;
    Ok(Saved { data, crypto, meta })
}
pub(super) fn digest(saved: &Saved) -> Result<String> {
    Ok(hash(
        &[
            encode(&saved.data)?.as_slice(),
            saved.crypto.as_slice(),
            encode(&saved.meta)?.as_slice(),
        ]
        .concat(),
    ))
}
pub(super) fn write(tx: &Transaction<'_>, saved: &Saved) -> Result<()> {
    saved.data.validate(&saved.crypto)?;
    saved.meta.validate(&saved.data, &saved.crypto)?;
    let meta = encode(&saved.meta)?;
    if meta.len() > MAX_META {
        return Err(Error::new("storage_limit"));
    }
    let data = encode(&saved.data)?;
    if data.len() > MAX_DATA {
        return Err(Error::new("storage_limit"));
    }
    let digest = hash(&[data.as_slice(), saved.crypto.as_slice(), meta.as_slice()].concat());
    // 首个终态和格式门禁在同一提交中生效；旧包必须拒绝，不能误读已压缩的消息投影。
    if saved.data.has_rejections() {
        let app: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        if app == APP_ID {
            tx.execute_batch("PRAGMA user_version=5;")?;
        }
    }
    tx.execute("INSERT INTO sdk_state(id,data,crypto,digest,recovery) VALUES(1,?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET data=excluded.data,crypto=excluded.crypto,digest=excluded.digest,recovery=excluded.recovery", params![data, saved.crypto, digest, meta])?;
    Ok(())
}
