//! 只有本线程持有 SQLite；有界作业只允许本模块协调器调用固定 Store 操作。
use super::{
    anchor::{client::Client as AnchorClient, rebuild_store::State as RebuildState},
    contract::Scope,
    store::Store,
};
use crate::{
    diagnostics,
    model::{Error, Result},
};
use std::{
    path::PathBuf,
    sync::mpsc::{self, SyncSender},
    thread::{self, JoinHandle},
};

type Job = Box<dyn FnOnce(&mut Option<Store>) -> bool + Send>;

pub(super) struct Database {
    sender: SyncSender<Job>,
    join: Option<JoinHandle<()>>,
    pub thread_id: String,
    pub trace: Vec<String>,
    #[cfg(feature = "protected-storage")]
    protection: Option<crate::protection::Guard>,
    #[cfg(feature = "protected-storage")]
    protection_error: Option<Error>,
}
impl Database {
    pub fn open(path: PathBuf, scope: Scope, create: bool) -> Result<Self> {
        Self::start(move || Store::open(&path, scope, create))
    }
    pub fn open_bound(path: PathBuf, scope: Scope, client: AnchorClient) -> Result<Self> {
        Self::start(move || Store::open_bound(&path, scope, client))
    }
    pub fn open_rebuild(
        path: PathBuf,
        scope: Scope,
        client: AnchorClient,
        slot: Option<RebuildState>,
    ) -> Result<Self> {
        Self::start(move || Store::open_rebuild(&path, scope, client, slot))
    }
    #[cfg(feature = "protected-storage")]
    pub fn open_protected(
        path: PathBuf,
        scope: Scope,
        create: bool,
        protection: crate::protection::Guard,
    ) -> Result<Self> {
        let install = protection.clone();
        Self::start_protected(protection, move || {
            Store::open_protected(&path, scope, create, install)
        })
    }
    #[cfg(feature = "protected-storage")]
    pub fn open_protected_bound(
        path: PathBuf,
        scope: Scope,
        client: AnchorClient,
        protection: crate::protection::Guard,
    ) -> Result<Self> {
        let install = protection.clone();
        Self::start_protected(protection, move || {
            Store::open_protected_bound(&path, scope, client, install)
        })
    }
    #[cfg(feature = "protected-storage")]
    pub fn open_protected_rebuild(
        path: PathBuf,
        scope: Scope,
        client: AnchorClient,
        slot: Option<RebuildState>,
        protection: crate::protection::Guard,
    ) -> Result<Self> {
        let install = protection.clone();
        Self::start_protected(protection, move || {
            Store::open_protected_rebuild(&path, scope, client, slot, install)
        })
    }
    #[cfg(feature = "protected-storage")]
    fn start_protected(
        protection: crate::protection::Guard,
        open: impl FnOnce() -> Result<Store> + Send + 'static,
    ) -> Result<Self> {
        // 钥匙串访问只在协调线程执行；数据库线程仅安装已取得的数据库钥。
        protection.check()?;
        let mut database = Self::start(open).map_err(|mut error| {
            error.paused = true;
            error
        })?;
        database.protection = Some(protection);
        database.check_protection()?;
        Ok(database)
    }
    #[cfg(feature = "protected-storage")]
    pub(super) fn protection(&self) -> Option<crate::protection::Guard> {
        self.protection.clone()
    }
    pub(super) fn is_protected_bootstrap(&self) -> bool {
        #[cfg(feature = "protected-storage")]
        {
            self.protection
                .as_ref()
                .is_some_and(|guard| guard.is_bootstrap())
        }
        #[cfg(not(feature = "protected-storage"))]
        {
            false
        }
    }
    #[cfg(feature = "protected-storage")]
    fn check_protection(&mut self) -> Result<()> {
        if let Some(error) = &self.protection_error {
            return Err(error.clone());
        }
        if let Some(protection) = &self.protection {
            if let Err(mut error) = protection.check() {
                // 发生过保护失效的实例永久暂停；解锁后须重开并沿原预约/日志恢复。
                error.paused = true;
                self.protection_error = Some(error.clone());
                return Err(error);
            }
        }
        Ok(())
    }
    fn start(open: impl FnOnce() -> Result<Store> + Send + 'static) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(8);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name("native-crypto-sqlite".into())
            .spawn(move || {
                let opened = open();
                let ready = opened
                    .as_ref()
                    .map(|_| {
                        (
                            format!("{:?}", thread::current().id()),
                            diagnostics::take_trace(),
                        )
                    })
                    .map_err(Clone::clone);
                if ready_tx.send(ready).is_err() {
                    return;
                }
                let Ok(store) = opened else {
                    return;
                };
                let mut store = Some(store);
                for job in receiver {
                    if job(&mut store) {
                        break;
                    }
                }
                if let Some(store) = store {
                    let _ = store.close();
                }
            })
            .map_err(|_| Error::new("worker_start_failed", true))?;
        let (thread_id, trace) = match ready_rx.recv() {
            Ok(Ok(ready)) => ready,
            Ok(Err(error)) => {
                let _ = join.join();
                return Err(error);
            }
            Err(_) => {
                let _ = join.join();
                return Err(Error::new("worker_start_failed", true));
            }
        };
        Ok(Self {
            sender,
            join: Some(join),
            thread_id,
            trace,
            #[cfg(feature = "protected-storage")]
            protection: None,
            #[cfg(feature = "protected-storage")]
            protection_error: None,
        })
    }
    pub fn call<T: Send + 'static>(
        &mut self,
        action: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        #[cfg(feature = "protected-storage")]
        self.check_protection()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(Box::new(move |store| {
                let result = match store {
                    Some(store) => action(store),
                    None => Err(Error::new("closed", true)),
                };
                let _ = sender.send((result, diagnostics::take_trace()));
                false
            }))
            .map_err(|_| Error::new("worker_stopped", true))?;
        let (result, trace) = receiver
            .recv()
            .map_err(|_| Error::new("worker_stopped", true))?;
        self.trace.extend(trace);
        #[cfg(feature = "protected-storage")]
        self.check_protection()?;
        result
    }
    pub fn close(&mut self) -> Result<()> {
        if self.join.is_none() {
            return Ok(());
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let sent = self.sender.send(Box::new(move |store| {
            let result = store.take().map_or(Ok(()), Store::close);
            let _ = sender.send(result);
            true
        }));
        let result = if sent.is_ok() {
            receiver
                .recv()
                .unwrap_or_else(|_| Err(Error::new("worker_stopped", true)))
        } else {
            Err(Error::new("worker_stopped", true))
        };
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| Error::new("worker_panicked", true))?;
        }
        result
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
