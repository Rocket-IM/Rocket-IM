//! 隔离浏览器持久化实验：普通记录及真实 OpenMLS 共同提交，非正式 IM SDK。

mod anchor;
mod crypto;
mod database;
mod diagnostics;
mod lifecycle;
mod protocol;
mod transaction;

use js_sys::Function;
use rusqlite::{Connection, OpenFlags};
use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfg, OpfsSAHPoolUtil};
use wasm_bindgen::prelude::*;

use protocol::{ApiError, Request, Scope, Snapshot};

/// 一个 Worker 中、一个服务实例与账号的唯一 SQLite 所有者。
/// 调用方必须显式关闭；平台不得直接访问连接、SQL 或 OPFS 池文件。
#[wasm_bindgen]
pub struct StorageProbe {
    connection: Option<Connection>,
    pool: Option<OpfsSAHPoolUtil>,
    scope: Scope,
    lease: Option<lifecycle::ScopeLease>,
    test_mode: bool,
    paused: bool,
    checkpoint: Option<Function>,
}

#[wasm_bindgen]
impl StorageProbe {
    /// 只能在 Dedicated Worker 中打开真正的 OPFS 数据空间，不降级到内存。
    /// 测试 v1 种子仅在空库创建；已有 v1 只校验，已有 v2 则拒绝。
    pub async fn open(
        service: String,
        account: String,
        test_mode: bool,
        seed_v1: bool,
        fail_migration: bool,
    ) -> Result<StorageProbe, JsValue> {
        Self::open_inner(service, account, test_mode, seed_v1, fail_migration)
            .await
            .map_err(ApiError::into_js)
    }

    /// 每次命令独立完成事务；结果只包含拥有所有权的值。
    pub fn execute(&mut self, request_json: String) -> String {
        let result = self.execute_inner(&request_json);
        if let Err(error) = &result {
            self.paused |= error.paused;
        }
        protocol::encode(result)
    }

    /// 先关闭连接，再释放 SAH；重复正常关闭幂等，失败须销毁 Worker。
    pub fn close(&mut self) -> Result<(), JsValue> {
        self.close_inner().map_err(ApiError::into_js)
    }

    /// 仅供中断验收。phase 是测试诊断，不是已提交数据成功事件。
    #[wasm_bindgen(js_name = setCheckpointHook)]
    pub fn set_checkpoint_hook(&mut self, callback: Function) -> Result<(), JsValue> {
        if !self.test_mode {
            return Err(ApiError::test_only().into_js());
        }
        self.ensure_available().map_err(ApiError::into_js)?;
        self.checkpoint = Some(callback);
        Ok(())
    }
}

impl StorageProbe {
    async fn open_inner(
        service: String,
        account: String,
        test_mode: bool,
        seed_v1: bool,
        fail_migration: bool,
    ) -> Result<Self, ApiError> {
        Self::open_with_mode(service, account, test_mode, seed_v1, fail_migration, false).await
    }

    async fn open_existing(
        service: String,
        account: String,
        test_mode: bool,
    ) -> Result<Self, ApiError> {
        Self::open_with_mode(service, account, test_mode, false, false, true).await
    }

    async fn open_with_mode(
        service: String,
        account: String,
        test_mode: bool,
        seed_v1: bool,
        fail_migration: bool,
        require_existing: bool,
    ) -> Result<Self, ApiError> {
        let scope = Scope::new(service, account)?;
        Self::open_scope(scope, test_mode, seed_v1, fail_migration, require_existing).await
    }

    async fn open_scope(
        scope: Scope,
        test_mode: bool,
        seed_v1: bool,
        fail_migration: bool,
        require_existing: bool,
    ) -> Result<Self, ApiError> {
        if (seed_v1 || fail_migration) && !test_mode {
            return Err(ApiError::test_only());
        }
        if seed_v1 && fail_migration {
            return Err(ApiError::invalid());
        }
        let lease = lifecycle::ScopeLease::acquire(&scope.storage_name())?;
        let cfg = OpfsSAHPoolCfg {
            vfs_name: scope.storage_name(),
            directory: format!(".{}", scope.storage_name()),
            clear_on_init: false,
            initial_capacity: 6,
        };
        let pool = install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, false)
            .await
            .map_err(|error| {
                ApiError::new("storage_unavailable", "OPFS 初始化失败。", true).with_opfs(error)
            })?;
        let mut probe = Self {
            connection: None,
            pool: Some(pool),
            scope,
            lease: Some(lease),
            test_mode,
            paused: false,
            checkpoint: None,
        };
        let result = (|| {
            let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            if !require_existing {
                flags |= OpenFlags::SQLITE_OPEN_CREATE;
            }
            let connection = Connection::open_with_flags_and_vfs(
                "records.sqlite3",
                flags,
                cfg.vfs_name.as_str(),
            )
            .map_err(ApiError::database)?;
            probe.connection = Some(connection);
            let connection = probe.connection.as_mut().ok_or_else(ApiError::closed)?;
            if require_existing {
                transaction::run(
                    connection,
                    rusqlite::TransactionBehavior::Deferred,
                    protocol::Fault::None,
                    protocol::Checkpoint::None,
                    None,
                    |tx| {
                        let version: u32 = tx
                            .query_row("PRAGMA user_version", [], |row| row.get(0))
                            .map_err(ApiError::database)?;
                        if version != 2 {
                            return Err(anchor::error("anchor_existing_store_required"));
                        }
                        Ok(())
                    },
                )?;
            }
            database::initialize(connection, &probe.scope, seed_v1, fail_migration)
        })();
        if let Err(error) = result {
            probe.close_inner()?;
            return Err(error);
        }
        Ok(probe)
    }

    fn ensure_available(&self) -> Result<(), ApiError> {
        if self.connection.is_none() {
            return Err(ApiError::closed());
        }
        if self.paused {
            return Err(ApiError::new(
                "storage_paused",
                "数据空间已暂停，请关闭后重新打开。",
                true,
            ));
        }
        Ok(())
    }

    fn execute_inner(&mut self, json: &str) -> Result<Snapshot, ApiError> {
        self.ensure_available()?;
        let request = Request::parse(json, self.test_mode, self.checkpoint.is_some())?;
        let connection = self.connection.as_mut().ok_or_else(ApiError::closed)?;
        match request {
            Request::Snapshot => database::snapshot(connection, &self.scope),
            Request::ReadFault => database::read_fault(connection, &self.scope),
            Request::Put(put) => {
                database::put(connection, &self.scope, put, self.checkpoint.as_ref())
            }
        }
    }

    fn close_inner(&mut self) -> Result<(), ApiError> {
        self.paused = true;
        self.checkpoint = None;
        if let Some(connection) = self.connection.take() {
            if let Err((connection, error)) = connection.close() {
                self.connection = Some(connection);
                return Err(
                    ApiError::new("close_failed", "SQLite 连接关闭失败。", true).with_sqlite(error)
                );
            }
        }
        if let Some(pool) = &self.pool {
            pool.pause_vfs().map_err(|error| {
                ApiError::new("close_failed", "OPFS 句柄释放失败。", true).with_opfs(error)
            })?;
        }
        self.pool = None;
        if let Some(lease) = &mut self.lease {
            lease.release()?;
        }
        self.lease = None;
        Ok(())
    }
}

impl Drop for StorageProbe {
    fn drop(&mut self) {
        // 析构无法交付错误；公开 close 已提供可观察的释放结果。
        // 失败时租约不释放，调用方必须结束 Worker，不能继续复用此数据空间。
        let _ = self.close_inner();
    }
}

#[wasm_bindgen]
pub fn sqlite_version() -> String {
    rusqlite::version().into()
}

#[wasm_bindgen]
pub fn probe_version() -> String {
    "0.1.0-q05.4".into()
}
