use rockets_native_storage_probe::crypto::{
    contract::{Action, Fault, Request, Scope},
    model::{Envelope, Identity},
    Client, MemoryPeer, Reply,
};
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);

pub struct Files(pub PathBuf);
impl Files {
    pub fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "native-receive-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
    pub fn db(&self) -> PathBuf {
        self.0.join("receive.sqlite")
    }
    pub fn open(&self, create: bool) -> Client {
        Client::open(self.db(), scope("alice"), create).unwrap()
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
pub fn scope(account: &str) -> Scope {
    Scope {
        service: "local".into(),
        account: account.into(),
        device: format!("{account}-device"),
    }
}
pub fn execute(client: &mut Client, id: &str, action: Action, fault: Fault) -> Reply {
    client.execute(Request {
        request_id: id.into(),
        action,
        fault,
    })
}
pub fn receive(
    client: &mut Client,
    id: &str,
    sequence: &str,
    envelope: &Envelope,
    fault: Fault,
) -> Reply {
    execute(
        client,
        id,
        Action::Receive {
            sequence: sequence.into(),
            envelope: envelope.clone(),
        },
        fault,
    )
}
pub fn value(reply: Reply) -> Value {
    assert!(reply.ok, "{}", serde_json::to_string(&reply).unwrap());
    reply.result.unwrap()
}
pub fn inspect(client: &mut Client) -> Value {
    value(client.inspect())
}
pub fn no_crypto(reply: &Reply) {
    assert_eq!(
        reply.metrics.provider_news
            + reply.metrics.provider_restores
            + reply.metrics.candidate_sends
            + reply.metrics.candidate_receives,
        0
    );
}
pub fn failed(reply: Reply, code: &str) {
    assert!(!reply.ok);
    assert!(reply.result.is_none());
    assert!(reply.events.is_empty());
    assert_eq!(reply.error.unwrap().code, code);
}
pub fn group(client: &mut Client) -> MemoryPeer {
    let identity: Identity = serde_json::from_value(
        value(execute(client, "init", Action::Initialize {}, Fault::None))["value"].clone(),
    )
    .unwrap();
    let mut peer = MemoryPeer::new(&scope("bob")).unwrap();
    let result = value(execute(
        client,
        "group",
        Action::CreateGroup {
            conversation: "conversation".into(),
            peer: peer.identity(),
        },
        Fault::None,
    ));
    peer.join(
        "conversation",
        &identity,
        result["value"]["welcome"].as_str().unwrap(),
    )
    .unwrap();
    peer
}
