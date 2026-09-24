//! 合成独立锚入口：配置和锚数据必须位于设备备份范围之外，不能退回普通入口。
pub(crate) mod client;
pub(crate) mod commitment;
pub mod contract;
mod coordinator;
pub(crate) mod database;
#[cfg(feature = "protected-storage")]
mod protected;
pub(crate) mod protocol;
mod rebuild;
pub(crate) mod rebuild_protocol;
pub(crate) mod rebuild_remote;
mod rebuild_source;
pub(crate) mod rebuild_store;
mod signatures;
mod transport;
pub use rebuild::RebuildClient;

use super::{
    contract::{DownloadRequest, Fault, Request, Scope},
    db_thread::Database,
    Metrics, Reply,
};
use crate::model::{Error, Result};
use client::{Client as Remote, Config};
use contract::{AnchorFault, Local};
use protocol::{Action, Response, Status};
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct AnchoredClient {
    inner: super::Client,
    remote: Remote,
}
impl AnchoredClient {
    /// 配置仅从可信外置文件读取；JSON大小及未知字段严格校验。
    pub fn bind_json(path: PathBuf, config_json: &str) -> Result<Value> {
        Self::bind(path, parse_config(config_json)?)
    }
    pub fn open_json(path: PathBuf, config_json: &str) -> Result<Self> {
        Self::open(path, parse_config(config_json)?)
    }

    /// 只对显式提供的干净实验身份绑定一次；日常 open 不调用该入口。
    pub(crate) fn bind(path: PathBuf, config: Config) -> Result<Value> {
        let remote = Remote::new(config)?;
        let scope = crypto_scope(&remote);
        let mut database = Database::open(path, scope, false)?;
        let owned = remote.clone();
        let local = database.call(move |store| store.bind_anchor(&owned))?;
        database.close()?;
        Ok(json!({"head":local.head,"scope":remote.scope(),"binding":remote.fingerprint()}))
    }
    pub(crate) fn open(path: PathBuf, config: Config) -> Result<Self> {
        let remote = Remote::new(config)?;
        let scope = crypto_scope(&remote);
        let database = Database::open_bound(path, scope.clone(), remote.clone())?;
        Ok(Self {
            inner: super::Client { database, scope },
            remote,
        })
    }
    pub fn startup(&mut self) -> (String, Vec<String>) {
        self.inner.startup()
    }
    pub fn execute(&mut self, request: Request, fault: AnchorFault) -> Reply {
        if matches!(request.action, super::contract::Action::RebuildAdd { .. }) {
            return self.inner.reply(
                Err(error("rebuild_approval_required")),
                Metrics::default(),
                vec![],
            );
        }
        let validation = super::contract::validate_id(&request.request_id)
            .and_then(|()| request.action.validate());
        if let Err(error) = validation {
            return self.inner.reply(Err(error), Metrics::default(), vec![]);
        }
        let input = json!({"execute":request});
        self.run(input, "execute", fault, move |client| {
            client.execute(request)
        })
    }
    pub fn download(&mut self, request: DownloadRequest, fault: AnchorFault) -> Reply {
        if let Err(error) = request.validate() {
            return self.inner.reply(Err(error), Metrics::default(), vec![]);
        }
        let input = json!({"download":request});
        self.run(input, "download", fault, move |client| {
            client.download(request)
        })
    }
    pub fn process(
        &mut self,
        request_id: &str,
        sequence: &str,
        fault: Fault,
        anchor_fault: AnchorFault,
    ) -> Reply {
        let validation = super::contract::validate_id(request_id)
            .and_then(|()| super::contract::receive_sequence(sequence));
        if let Err(error) = validation {
            return self.inner.reply(Err(error), Metrics::default(), vec![]);
        }
        self.run(
            json!({"process":{"request_id":request_id,"sequence":sequence,"fault":fault}}),
            "execute",
            anchor_fault,
            |client| client.process(request_id, sequence, fault),
        )
    }
    pub fn status(&mut self) -> Reply {
        let result = self
            .state()
            .map(|(local, remote)| describe(&local, &remote));
        self.inner.reply(result, Metrics::default(), vec![])
    }
    /// 只交付公开摘要，暂停时仍可诊断；没有候选正文或私密 provider。
    pub fn inspect(&mut self) -> Reply {
        let state = self.state();
        let result = state.and_then(|(local, remote)| {
            self.inner
                .database
                .call(|store| store.inspect())
                .map(|snapshot| json!({"snapshot":snapshot,"anchor":describe(&local,&remote)}))
        });
        self.inner.reply(result, Metrics::default(), vec![])
    }
    pub fn received(&mut self, sequence: &str) -> Reply {
        let sequence = sequence.to_owned();
        let result = self
            .state()
            .and_then(|(local, remote)| {
                healthy(&local, &remote)?;
                self.inner
                    .database
                    .call(move |store| store.received_anchored(&sequence, &local.head))
            })
            .and_then(|value| serde_json::to_value(value).map_err(|_| error("encoding_failed")));
        self.inner.reply(result, Metrics::default(), vec![])
    }
    pub fn close(&mut self) -> Reply {
        self.inner.close()
    }
    fn state(&mut self) -> Result<(Local, Response)> {
        let local = self.inner.database.call(|store| store.anchor_local())?;
        let remote = self.remote.rpc(
            Action::Inspect,
            &protocol::random_hex()?,
            &local.head,
            "absent",
            "0",
        )?;
        if remote.status != Status::Inspected {
            return Err(error("anchor_response"));
        }
        Ok((local, remote))
    }
}
fn crypto_scope(remote: &Remote) -> Scope {
    let scope = remote.scope();
    Scope {
        service: scope.service.clone(),
        account: scope.account.clone(),
        device: scope.device.clone(),
    }
}
fn reason(local: &Local, remote: &Response) -> Option<&'static str> {
    if remote.closure.is_some() {
        Some("anchor_closed")
    } else if local.journal.is_some() {
        Some("anchor_recovery_required")
    } else if local.head != remote.head {
        Some("anchor_head_mismatch")
    } else if local.gate.is_some() || remote.active_txn.is_some() {
        Some("anchor_unresolved")
    } else {
        None
    }
}
fn healthy(local: &Local, remote: &Response) -> Result<()> {
    reason(local, remote).map_or(Ok(()), |code| Err(error(code)))
}
fn describe(local: &Local, remote: &Response) -> Value {
    json!({"assurance":"synthetic_local","local_head":local.head,"remote_head":remote.head,
        "remote_revision":remote.revision,"remote_pending":remote.active_txn,
        "local_pending":local.gate.is_some(),"reason":reason(local,remote)})
}
pub(crate) fn error(code: &str) -> Error {
    Error::new(code, true)
}

fn parse_config(json: &str) -> Result<Config> {
    if json.len() > 16384 {
        return Err(error("anchor_config"));
    }
    serde_json::from_str(json).map_err(|_| error("anchor_config"))
}
