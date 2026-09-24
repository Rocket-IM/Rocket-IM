//! 绑定前初始化也从第一个SQLite页起加密；缺失钥匙或已固定锚配置时不降级。
use super::{contract::Scope, db_thread::Database, Client};
use crate::{
    model::{Error, Result},
    protection::Guard,
};
use std::path::PathBuf;

impl Client {
    /// 只用于本项新建合成空间的初始化及公开摘要；业务命令必须使用受保护锚入口。
    pub fn open_protected(
        path: PathBuf,
        scope: Scope,
        locator: &str,
        create: bool,
    ) -> Result<Self> {
        let guard = if create {
            Guard::create(&path, &scope, locator, None)?
        } else {
            Guard::open(&path, &scope, locator, None)?
        };
        if guard.has_config() {
            return Err(Error::new("anchor_required", true));
        }
        Ok(Self {
            database: Database::open_protected(path, scope.clone(), create, guard)?,
            scope,
        })
    }
}
