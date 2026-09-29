//! 仅合成身份的原生密码事务 POC；独立锚走单独入口，没有生产秘密保护或正式 SDK 接口。
pub mod anchor;
pub mod contract;
mod db_thread;
mod engine;
pub mod model;
mod operations;
mod preflight;
#[cfg(feature = "protected-storage")]
mod protected;
mod query;
mod schema;
mod store;

use crate::model::{Error, Result};
use contract::{DownloadRequest, Fault, Preparation, Request, Scope};
use db_thread::Database;
use engine::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use std::{io::Write, path::PathBuf, thread, time::Duration};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Metrics {
    pub provider_news: u32,
    pub provider_restores: u32,
    pub candidate_sends: u32,
    pub candidate_receives: u32,
    #[serde(skip_serializing_if = "is_zero")]
    pub candidate_joins: u32,
}
fn is_zero(value: &u32) -> bool {
    *value == 0
}

#[derive(Serialize)]
pub struct Reply {
    pub ok: bool,
    pub result: Option<Value>,
    pub error: Option<Error>,
    pub events: Vec<Value>,
    pub metrics: Metrics,
    pub trace: Vec<String>,
    pub worker_thread: String,
    pub crypto_thread: String,
}

/// 同步实验调用方执行密码计算；专用数据库线程仅处理事务，不等待宿主回调。
pub struct Client {
    database: Database,
    scope: Scope,
}
impl Client {
    pub fn open(path: PathBuf, scope: Scope, create: bool) -> Result<Self> {
        Ok(Self {
            database: Database::open(path, scope.clone(), create)?,
            scope,
        })
    }
    pub fn startup(&mut self) -> (String, Vec<String>) {
        (
            self.database.thread_id.clone(),
            std::mem::take(&mut self.database.trace),
        )
    }
    pub fn inspect(&mut self) -> Reply {
        let result = self
            .database
            .call(|store| store.inspect())
            .and_then(|snapshot| {
                serde_json::to_value(snapshot).map_err(|_| Error::new("encoding_failed", true))
            });
        self.reply(result, Metrics::default(), vec![])
    }
    /// 仅查询已提交接收结果；未决状态不影响旧消息读取，不读取临时候选。
    pub fn received(&mut self, sequence: &str) -> Reply {
        let sequence = sequence.to_owned();
        let result = self
            .require_business_access()
            .and_then(|()| contract::receive_sequence(&sequence))
            .and_then(|_| self.database.call(move |store| store.received(&sequence)))
            .and_then(|value| {
                serde_json::to_value(value).map_err(|_| Error::new("encoding_failed", true))
            });
        self.reply(result, Metrics::default(), vec![])
    }
    /// 一批原始密文与下载游标共同提交；成功事件不含正文，也不代表处理成功。
    pub fn download(&mut self, request: DownloadRequest) -> Reply {
        let result = self
            .require_business_access()
            .and_then(|()| request.validate())
            .and_then(|()| self.database.call(move |store| store.download(&request)));
        let events = match &result {
            Ok(outcome) if outcome.added > 0 => vec![json!({
                "scope":self.scope,"kind":"download","download_cursor":outcome.download_cursor,
                "processed_cursor":outcome.processed_cursor
            })],
            _ => vec![],
        };
        let result = result.and_then(|outcome| {
            serde_json::to_value(outcome).map_err(|_| Error::new("encoding_failed", true))
        });
        self.reply(result, Metrics::default(), events)
    }
    /// 从 Rust 已保存的不可变密文处理指定序号；未决预约不能通过重试解除。
    pub fn process(&mut self, request_id: &str, sequence: &str, fault: Fault) -> Reply {
        let request_id = request_id.to_owned();
        let sequence = sequence.to_owned();
        let result = self
            .require_business_access()
            .and_then(|()| contract::validate_id(&request_id))
            .and_then(|()| contract::receive_sequence(&sequence))
            .and_then(|_| {
                self.database
                    .call(move |store| store.process_request(&request_id, &sequence, fault))
            });
        match result {
            Ok(request) => self.execute(request),
            Err(error) => self.reply(Err(error), Metrics::default(), vec![]),
        }
    }
    pub fn execute(&mut self, request: Request) -> Reply {
        if let Err(error) = self.require_action_access(&request) {
            return self.reply(Err(error), Metrics::default(), vec![]);
        }
        if matches!(request.action, contract::Action::RebuildAdd { .. }) {
            return self.reply(
                Err(Error::new("rebuild_approval_required", true)),
                Metrics::default(),
                vec![],
            );
        }
        self.execute_authorized(request)
    }
    pub(crate) fn execute_authorized(&mut self, request: Request) -> Reply {
        if let Err(error) = self.require_action_access(&request) {
            return self.reply(Err(error), Metrics::default(), vec![]);
        }
        let mut metrics = Metrics::default();
        let result = self.execute_inner(&request, &mut metrics);
        let events = match &result {
            Ok(outcome)
                if !outcome.cached
                    && !(outcome.kind == "receive"
                        && outcome.value.get("duplicate") == Some(&Value::Bool(true))) =>
            {
                vec![json!({"scope":self.scope,"revision":outcome.revision,"kind":outcome.kind})]
            }
            _ => vec![],
        };
        let result = result.and_then(|outcome| {
            serde_json::to_value(outcome).map_err(|_| Error::new("encoding_failed", true))
        });
        self.reply(result, metrics, events)
    }
    fn require_business_access(&self) -> Result<()> {
        if self.database.is_protected_bootstrap() {
            Err(Error::new("anchor_required", true))
        } else {
            Ok(())
        }
    }
    fn require_action_access(&self, request: &Request) -> Result<()> {
        if matches!(request.action, contract::Action::Initialize {}) {
            Ok(())
        } else {
            self.require_business_access()
        }
    }
    fn execute_inner(
        &mut self,
        request: &Request,
        metrics: &mut Metrics,
    ) -> Result<contract::Outcome> {
        contract::validate_id(&request.request_id)?;
        request.action.validate()?;
        let owned = request.clone();
        let prepared = match self.database.call(move |store| store.prepare(&owned))? {
            Preparation::Cached(outcome) => return Ok(outcome),
            Preparation::Reserved(prepared) => *prepared,
        };
        if request.fault == Fault::AfterReserve {
            return Err(Error::new("crypto_injected_failure", true));
        }
        if request.fault == Fault::PauseAfterReserve {
            checkpoint("after_reserve", metrics)?;
        }
        let (reservation, candidate) =
            operations::compute(&self.scope, request, prepared, metrics)?;
        if request.fault == Fault::AfterCrypto {
            return Err(Error::new("crypto_injected_failure", true));
        }
        if request.fault == Fault::PauseAfterCrypto {
            checkpoint("after_crypto", metrics)?;
        }
        if matches!(request.fault, Fault::BeforeCommit | Fault::AfterCommit) {
            diagnostic("candidate_ready", metrics)?;
        }
        let owned = request.clone();
        self.database
            .call(move |store| store.commit(&owned, &reservation, candidate))
    }
    fn reply(&mut self, result: Result<Value>, metrics: Metrics, events: Vec<Value>) -> Reply {
        let (result, error) = match result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        };
        Reply {
            ok: error.is_none(),
            result,
            error,
            events,
            metrics,
            trace: std::mem::take(&mut self.database.trace),
            worker_thread: self.database.thread_id.clone(),
            crypto_thread: format!("{:?}", thread::current().id()),
        }
    }
    pub fn close(&mut self) -> Reply {
        let result = self.database.close().map(|_| Value::Null);
        self.reply(result, Metrics::default(), vec![])
    }
}

fn diagnostic(stage: &str, metrics: &Metrics) -> Result<()> {
    let mut stderr = std::io::stderr().lock();
    writeln!(
        stderr,
        "{}",
        json!({"checkpoint":stage,"pid":std::process::id(),"metrics":metrics})
    )
    .and_then(|()| stderr.flush())
    .map_err(|_| Error::new("checkpoint_output_failed", true))
}
fn checkpoint(stage: &str, metrics: &Metrics) -> Result<()> {
    diagnostic(stage, metrics)?;
    thread::sleep(Duration::from_secs(10));
    Err(Error::new("checkpoint_timeout", true))
}

/// 仅供进程验收的内存对端：不宣称该夹具持久化、恢复或发布 SDK 能力。
pub struct MemoryPeer {
    engine: Engine,
}
impl MemoryPeer {
    pub fn new(scope: &Scope) -> Result<Self> {
        Ok(Self {
            engine: Engine::new(scope)?,
        })
    }
    pub fn identity(&self) -> model::Identity {
        self.engine.identity()
    }
    pub fn join(
        &mut self,
        conversation: &str,
        peer: &model::Identity,
        welcome: &str,
    ) -> Result<()> {
        self.engine.join_group(conversation, peer, welcome)
    }
    pub fn send(&mut self, message_id: &str, text: &str) -> Result<model::Envelope> {
        self.engine.send(message_id, text)
    }
    pub fn receive(&mut self, envelope: &model::Envelope) -> Result<model::PlainMessage> {
        self.engine.receive(envelope)
    }
}
