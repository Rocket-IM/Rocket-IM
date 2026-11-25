//! 有界内部作业队列；连接、事务及活动游标不离开此线程。
use super::{store::Store, types::*};
use std::{
    path::PathBuf,
    sync::mpsc::{self, SyncSender},
    thread::{self, JoinHandle},
};
type Job = Box<dyn FnOnce(&mut Store) + Send>;
pub(super) struct Database {
    sender: Option<SyncSender<Job>>,
    thread: Option<JoinHandle<()>>,
}
impl Database {
    pub fn open(
        path: PathBuf,
        scope: Scope,
        create: bool,
        migrate: bool,
        keychain: Option<PathBuf>,
    ) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(8);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("rocket-sdk-sqlite".into())
            .spawn(move || {
                let store = Store::open(&path, scope, create, migrate, keychain);
                let ready = store.as_ref().map(|_| ()).map_err(Clone::clone);
                if ready_tx.send(ready).is_err() {
                    return;
                }
                if let Ok(mut store) = store {
                    for job in receiver {
                        job(&mut store);
                    }
                }
            })
            .map_err(|_| Error::paused("worker_start_failed"))?;
        let ready = ready_rx
            .recv()
            .map_err(|_| Error::paused("worker_stopped"))
            .and_then(|r| r);
        if let Err(e) = ready {
            drop(sender);
            let _ = thread.join();
            return Err(e);
        }
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
        })
    }
    pub fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| Error::new("closed"))?
            .send(Box::new(move |store| {
                let result = (|| {
                    let _guard = store.lock_access()?;
                    store.check_access()?;
                    let result = f(store)?;
                    super::checkpoint("before_result");
                    store.check_access()?;
                    Ok(result)
                })();
                let _ = tx.send(result);
            }))
            .map_err(|_| Error::paused("worker_stopped"))?;
        rx.recv().map_err(|_| Error::paused("worker_stopped"))?
    }
    #[cfg(feature = "protected-storage")]
    pub fn logout(&self) -> Result<()> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| Error::new("closed"))?
            .send(Box::new(move |store| {
                let _ = tx.send(store.logout());
            }))
            .map_err(|_| Error::paused("worker_stopped"))?;
        rx.recv().map_err(|_| Error::paused("worker_stopped"))?
    }
    pub fn close(&mut self) -> Result<()> {
        self.sender.take();
        if let Some(t) = self.thread.take() {
            t.join().map_err(|_| Error::paused("worker_stopped"))?;
        }
        Ok(())
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
