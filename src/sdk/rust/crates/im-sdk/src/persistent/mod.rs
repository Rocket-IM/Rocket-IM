//! 固定双成员、测试身份的持久SDK。可选network连接Go Alpha；protected-storage启用本机系统保护。
//! 每实例一个数据库线程；调用方在工作线程串行调用本同步接口。只有提交成功才返回成功。
//! 进程中断若留下 Pending，库保留有效前态并拒绝新密码操作，不自动重置/重放秘密状态。
mod candidate;
mod capacity;
mod capacity_types;
mod metering;
pub use capacity_types::*;
mod journal;
pub mod network;
mod recovery;
mod recovery_finish;
mod recovery_reject;
mod recovery_types;
mod recovery_wire;
pub use recovery_types::{RecoveryCommand, RecoveryPhase, RecoveryResult};
mod data;
mod database;
mod history;
mod message_projection;
pub use history::{HistoryDirection, HistoryItem, HistoryPage, HistoryQuery};
#[cfg(feature = "protected-storage")]
mod backup;
mod operations;
#[cfg(feature = "protected-storage")]
mod protection;
mod store;
#[cfg(feature = "protected-storage")]
pub use backup::BackupInfo;
mod types;
use database::Database;
use std::path::PathBuf;
use types::*;
pub use types::{
    Action, Envelope, Error, Identity, JoiningMaterial, Message, Outcome, RequestState, Result,
    Scope, State, Value,
};

/// 单一所有者串行使用；不能在 UI 线程运行。Drop/close 等待数据库线程退出。
pub struct PersistentDevice {
    database: Database,
}
impl PersistentDevice {
    /// create=true 只允许全新绝对路径；false 只打开匹配 scope 的有效 v2 SDK 库；旧 v1 需显式 upgrade。
    pub fn open(path: PathBuf, scope: Scope, create: bool) -> Result<Self> {
        Ok(Self {
            database: Database::open(path, scope, create, false, None)?,
        })
    }
    /// 显式升级旧 v1 原库；原行原件保留，旧 Pending 不自动重新执行。
    pub fn upgrade(path: PathBuf, scope: Scope) -> Result<Self> {
        Ok(Self {
            database: Database::open(path, scope, false, true, None)?,
        })
    }
    /// 显式文件钥匙串，只创建加密 v3 或打开同一绑定；不接受旧明文库或隐式迁移。
    #[cfg(feature = "protected-storage")]
    pub fn open_protected(
        path: PathBuf,
        scope: Scope,
        create: bool,
        keychain: PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            database: Database::open(path, scope, create, false, Some(keychain)).map_err(
                |error| {
                    if error.code == "storage_failure" {
                        Error::paused("protected_store_invalid")
                    } else {
                        error
                    }
                },
            )?,
        })
    }
    /// 作业/结果门禁。不能撤回已交付数据，也不能与 OS 锁定形成原子关系。
    pub fn check_access(&self) -> Result<()> {
        self.database.call(|_| Ok(()))
    }
    #[cfg(all(feature = "protected-storage", feature = "persistent-test-hooks"))]
    pub fn audit_protection(&self) -> Result<serde_json::Value> {
        self.database.call(|store| store.audit_protection())
    }
    /// 销毁该空间的解密钥，保留无密钥墓碑及加密文件；始终关闭当前实例。
    #[cfg(feature = "protected-storage")]
    pub fn logout(&mut self) -> Result<()> {
        let result = self.database.logout();
        let closed = self.database.close();
        result.and(closed)
    }
    /// 进程中断后只确认原空间已退出；不会读取数据库或重新生成钥。
    #[cfg(feature = "protected-storage")]
    pub fn confirm_logout(path: PathBuf, scope: Scope, keychain: PathBuf) -> Result<()> {
        let protection = protection::Protection::locator(path, scope, keychain)?;
        let _lock = protection.lock()?;
        protection.confirm_logout()
    }
    /// 单库同快照只读观察；没有持久预留。所有访问门禁成功后交付，不能作为下一次执行许可。
    pub fn capacity(&self) -> Result<Capacity> {
        self.database.call(|db| {
            let snapshot = db.read(capacity::snapshot)?;
            checkpoint("capacity_after_read");
            Ok(snapshot)
        })
    }
    pub fn state(&self) -> Result<State> {
        self.database.call(|db| db.read(|s| Ok(s.data.state)))
    }
    /// 查询原请求的持久状态；Missing 不等于网络拒绝，Pending 不能自动重做密码处理。
    pub fn request(&self, request_id: String) -> Result<RequestState> {
        id(&request_id)?;
        self.database.call(move |db| {
            db.read(|s| {
                Ok(s.data
                    .requests
                    .get(&request_id)
                    .map_or(RequestState::Missing, |r| r.result.clone()))
            })
        })
    }
    pub fn message(
        &self,
        sender_account: String,
        sender_device: String,
        message_id: String,
    ) -> Result<Option<Message>> {
        for value in [&sender_account, &sender_device, &message_id] {
            id(value)?;
        }
        self.database.call(move |db| {
            db.read(|s| {
                Ok(s.data
                    .history_messages()?
                    .into_iter()
                    .find(|m| {
                        (
                            &m.message.sender_account,
                            &m.message.sender_device,
                            &m.message.message_id,
                        ) == (&sender_account, &sender_device, &message_id)
                    })
                    .map(|m| m.message))
            })
        })
    }
    /// 已提交收发消息的本地顺序分页；固定上界可跨重启续读。
    /// 每页读事务结束后返回；无活动事务/游标跨调用。游标不授予访问权限。
    pub fn history(&self, query: HistoryQuery) -> Result<HistoryPage> {
        self.database.call(move |db| {
            let space = db.history_space().to_string();
            let page = db.read(|saved| history::page(saved.data, &space, query))?;
            checkpoint("history_after_read");
            Ok(page)
        })
    }
    /// 导出本实例已持久化的公开身份和一次性加入材料；公钥必须由测试消费方独立核验。
    pub fn joining_material(&self) -> Result<JoiningMaterial> {
        let saved = self.database.call(|db| db.read(Ok))?;
        if saved.data.state.pending_request.is_some() || saved.meta.blocks_operations() {
            return Err(Error::paused("operation_pending"));
        }
        let device = candidate::restore(&saved)?;
        let result = JoiningMaterial {
            identity: saved
                .data
                .state
                .identity
                .ok_or_else(|| Error::new("initialize_required"))?,
            key_package: hex(&device.key_package()?),
        };
        self.check_access()?;
        Ok(result)
    }
    /// 稳定 request_id + 完全相同 Action 可取回原提交结果；不同输入复用 ID 明确拒绝。
    pub fn execute(&mut self, request_id: String, action: Action) -> Result<Outcome> {
        id(&request_id)?;
        action.validate()?;
        let rid = request_id.clone();
        let input = action.clone();
        // 身份种子在任何可见预约之前生成；事务竞争败者未导出材料，直接丢弃。
        let seed = if matches!(action, Action::Initialize) {
            let scope = self.state()?.scope;
            Some(encode(
                &rocket_crypto_core::Device::new(scope.service, scope.account, scope.device)?
                    .snapshot()?,
            )?)
        } else {
            None
        };
        let prepared = self.database.call(move |db| {
            db.update(false, |s| {
                let prepared = operations::prepare(s, &rid, &input)?;
                if matches!(prepared, operations::Preparation::Ready(_)) {
                    s.meta.journal = Some(journal::Journal {
                        request: rid,
                        input,
                        phase: journal::Phase::Reserved,
                        seed,
                        candidate: None,
                    });
                    Ok(operations::Preparation::Ready(Box::new(s.clone())))
                } else {
                    Ok(prepared)
                }
            })
        })?;
        let saved = match prepared {
            operations::Preparation::Ready(saved) => saved,
            operations::Preparation::Cached(outcome) => return Ok(*outcome),
        };
        checkpoint("after_reserve");
        self.run_reserved(*saved, &request_id)
    }
    pub fn close(&mut self) -> Result<()> {
        self.database.close()
    }
}

// 只进入另行编译的测试程序；交付程序没有环境故障入口或控制命令。
fn checkpoint(_phase: &str) {
    #[cfg(feature = "persistent-test-hooks")]
    {
        if std::env::var("ROCKET_IM_TEST_EXIT_PHASE").ok().as_deref() == Some(_phase) {
            std::process::exit(86);
        }
        if std::env::var("ROCKET_IM_TEST_BARRIER_PHASE")
            .ok()
            .as_deref()
            == Some(_phase)
        {
            if let Ok(path) = std::env::var("ROCKET_IM_TEST_BARRIER") {
                if std::fs::write(format!("{path}.ready"), b"ready").is_err() {
                    std::process::exit(87);
                }
                let start = std::time::Instant::now();
                while !std::path::Path::new(&format!("{path}.release")).exists() {
                    if start.elapsed().as_secs() > 15 {
                        std::process::exit(88);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod recovery_tests;

#[cfg(test)]
mod history_tests;

#[cfg(test)]
mod budget_tests;

#[cfg(test)]
mod recovery_budget_tests;

#[cfg(test)]
mod capacity_tests;
