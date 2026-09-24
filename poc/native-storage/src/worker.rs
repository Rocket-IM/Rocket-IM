use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver, SyncSender, TrySendError},
    thread::{self, JoinHandle},
};

use serde::Serialize;

use crate::{
    database::Store,
    diagnostics,
    model::{Error, Fault, OpenOptions, Put, Result, Scope, Snapshot},
};

const COMMAND_CAPACITY: usize = 32;
const EVENT_CAPACITY: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Change {
    pub service: String,
    pub account: String,
    pub revision: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Notification {
    Idle,
    Delivered,
    Lagged,
}

#[derive(Debug)]
pub struct Reply {
    pub result: Result<Option<Snapshot>>,
    pub trace: Vec<String>,
    pub worker_thread: String,
    pub notification: Notification,
}

impl Reply {
    fn failure(code: &str, worker_thread: &str) -> Self {
        Self {
            result: Err(Error::new(code, false)),
            trace: vec![],
            worker_thread: worker_thread.into(),
            notification: Notification::Idle,
        }
    }
}

enum Action {
    Snapshot(Fault),
    Put(Put),
    Subscribe(SyncSender<Change>),
    Unsubscribe,
    Close,
}

struct Request {
    action: Action,
    reply: SyncSender<Reply>,
}

/// 同步实验客户端；等待只发生在调用线程，不适合作为 UI 线程上的正式 API。
#[derive(Clone)]
pub struct Client {
    sender: SyncSender<Request>,
    worker_thread: String,
}

impl Client {
    pub fn snapshot(&self, fault: Fault) -> Reply {
        self.call(Action::Snapshot(fault), false)
    }

    pub fn put(&self, put: Put) -> Reply {
        self.call(Action::Put(put), false)
    }

    /// 注册与基线查询在同一串行命令中完成，避免两次调用之间漏掉变更。
    /// 只保留一个订阅；替换或取消后旧接收端可能还有已排队事件，必须丢弃。
    pub fn subscribe(&self) -> (Reply, Receiver<Change>) {
        let (sender, receiver) = mpsc::sync_channel(EVENT_CAPACITY);
        (self.call(Action::Subscribe(sender), false), receiver)
    }

    pub fn unsubscribe(&self) -> Reply {
        self.call(Action::Unsubscribe, false)
    }

    /// 停止所有已排队工作后关闭连接；后续旧 Client 调用明确返回 closed。
    pub fn close(&self) -> Reply {
        self.call(Action::Close, true)
    }

    fn call(&self, action: Action, closing: bool) -> Reply {
        let (sender, receiver) = mpsc::sync_channel(1);
        let request = Request {
            action,
            reply: sender,
        };
        if closing {
            // 关闭必须进入有界队列；不因暂时排满遗留仍持有连接的线程。
            if self.sender.send(request).is_err() {
                return Reply::failure("closed", &self.worker_thread);
            }
        } else if let Err(error) = self.sender.try_send(request) {
            return Reply::failure(
                match error {
                    TrySendError::Full(_) => "queue_full",
                    TrySendError::Disconnected(_) => "closed",
                },
                &self.worker_thread,
            );
        }
        receiver
            .recv()
            .unwrap_or_else(|_| Reply::failure("worker_stopped", &self.worker_thread))
    }
}

/// 一个实验实例一个数据库线程。此局部选择不锁定正式 SDK 的线程配置。
pub struct Engine {
    client: Client,
    join: Option<JoinHandle<()>>,
    pub startup: Reply,
}

impl Engine {
    pub fn open(path: PathBuf, scope: Scope, options: OpenOptions) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(COMMAND_CAPACITY);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name("native-storage".into())
            .spawn(move || serve(path, scope, options, receiver, ready_sender))
            .map_err(|_| Error::new("worker_start_failed", false))?;
        let startup = match ready_receiver.recv() {
            Ok(reply) => reply,
            Err(_) => {
                let _ = join.join();
                return Err(Error::new("worker_start_failed", false));
            }
        };
        if let Err(error) = startup.result {
            if join.join().is_err() {
                return Err(Error::new("worker_panicked", true));
            }
            return Err(error);
        }
        let client = Client {
            sender,
            worker_thread: startup.worker_thread.clone(),
        };
        Ok(Self {
            client,
            join: Some(join),
            startup,
        })
    }

    pub fn client(&self) -> Client {
        self.client.clone()
    }

    pub fn close(mut self) -> Result<()> {
        let result = self.client.close().result;
        self.join_worker()?;
        match result {
            Err(error) if error.code != "closed" => Err(error),
            _ => Ok(()),
        }
    }

    fn join_worker(&mut self) -> Result<()> {
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| Error::new("worker_panicked", true))?;
        }
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if self.join.is_some() {
            let _ = self.client.close();
            let _ = self.join_worker();
        }
    }
}

fn serve(
    path: PathBuf,
    scope: Scope,
    options: OpenOptions,
    receiver: Receiver<Request>,
    ready: SyncSender<Reply>,
) {
    let worker_thread = format!("{:?}", thread::current().id());
    let opened = Store::open(&path, scope, options);
    let initial = Reply {
        result: opened.as_ref().map(|_| None).map_err(Clone::clone),
        trace: diagnostics::take_trace(),
        worker_thread: worker_thread.clone(),
        notification: Notification::Idle,
    };
    if ready.send(initial).is_err() {
        return;
    }
    let Ok(mut store) = opened else { return };
    let mut subscriber: Option<SyncSender<Change>> = None;
    let mut notification = Notification::Idle;
    for request in receiver {
        // Delivered 只描述本条命令；Lagged 保留到显式重新订阅。
        if notification == Notification::Delivered {
            notification = Notification::Idle;
        }
        let result = match request.action {
            Action::Snapshot(fault) => store.snapshot(fault).map(Some),
            Action::Put(put) => store.put(put).map(|snapshot| {
                if let Some(sender) = &subscriber {
                    // 此时 Store 已结束事务；只排队，不执行或等待任何宿主代码。
                    match sender.try_send(Change {
                        service: snapshot.service.clone(),
                        account: snapshot.account.clone(),
                        revision: snapshot.revision.clone(),
                    }) {
                        Ok(()) => notification = Notification::Delivered,
                        Err(TrySendError::Full(_)) => {
                            subscriber = None;
                            notification = Notification::Lagged;
                        }
                        Err(TrySendError::Disconnected(_)) => {
                            subscriber = None;
                            notification = Notification::Idle;
                        }
                    }
                }
                Some(snapshot)
            }),
            Action::Subscribe(sender) => store.snapshot(Fault::None).map(|snapshot| {
                subscriber = Some(sender);
                notification = Notification::Idle;
                Some(snapshot)
            }),
            Action::Unsubscribe => {
                subscriber = None;
                notification = Notification::Idle;
                Ok(None)
            }
            Action::Close => {
                let result = store.close().map(|_| None);
                let _ = request.reply.send(Reply {
                    result,
                    trace: diagnostics::take_trace(),
                    worker_thread,
                    notification: Notification::Idle,
                });
                return;
            }
        };
        let _ = request.reply.send(Reply {
            result,
            trace: diagnostics::take_trace(),
            worker_thread: worker_thread.clone(),
            notification,
        });
    }
    // Engine 的正常关闭会走 Action::Close；通道异常断开也释放本线程独占连接。
    let _ = store.close();
}
