//! 外置定位器只选择钥匙串项；固定配置与数据库钥必须来自同一受保护记录。
use super::{client::Client as Remote, crypto_scope, error, parse_config, AnchoredClient};
use crate::{crypto::db_thread::Database, model::Result, protection::Guard};
use serde_json::{json, Value};
use std::path::PathBuf;

impl AnchoredClient {
    /// 首次绑定先固定不可变配置，再提交SQLite绑定。中断只允许同配置显式重试。
    pub fn bind_protected(path: PathBuf, locator: &str, config_json: &str) -> Result<Value> {
        let requested = Remote::new(parse_config(config_json)?)?;
        let scope = crypto_scope(&requested);
        let guard = Guard::open(&path, &scope, locator, None)?.pin_config(config_json)?;
        let remote = Remote::new(guard.config()?)?;
        if remote.fingerprint() != requested.fingerprint() || crypto_scope(&remote) != scope {
            return Err(error("anchor_config"));
        }
        // 只在准确的“尚未绑定”状态进入一次绑定；其他失败不尝试另一种开库方式。
        let (mut database, already_bound) = match Database::open_protected_bound(
            path.clone(),
            scope.clone(),
            remote.clone(),
            guard.clone(),
        ) {
            Ok(database) => (database, true),
            Err(error) if error.code == "anchor_binding_missing" => {
                (Database::open_protected(path, scope, false, guard)?, false)
            }
            Err(error) => return Err(error),
        };
        let local = if already_bound {
            database.call(|store| store.anchor_local())?
        } else {
            let owned = remote.clone();
            database.call(move |store| store.bind_anchor(&owned))?
        };
        if local.gate.is_some() || local.journal.is_some() {
            return Err(error("anchor_local_unresolved"));
        }
        database.close()?;
        Ok(
            json!({"head":local.head,"scope":remote.scope(),"binding":remote.fingerprint(),
            "already_bound":already_bound}),
        )
    }

    /// 每次重开从钥匙串重新验证固定配置，不接受数据库或旁文件自报的信任材料。
    pub fn open_protected(path: PathBuf, locator: &str) -> Result<Self> {
        let guard = Guard::load(&path, locator, None)?;
        let remote = Remote::new(guard.config()?)?;
        let scope = crypto_scope(&remote);
        if guard.scope() != scope {
            return Err(error("anchor_config"));
        }
        let database = Database::open_protected_bound(path, scope.clone(), remote.clone(), guard)?;
        Ok(Self {
            inner: crate::crypto::Client { database, scope },
            remote,
        })
    }
}
