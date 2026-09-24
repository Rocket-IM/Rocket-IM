use rocket_native_storage_probe::{
    model::{Fault, OpenOptions, Put, Scope, Snapshot},
    Engine, Reply,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

pub struct Files(pub PathBuf);
impl Files {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rocket-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn db(&self) -> PathBuf {
        self.0.join("state.sqlite")
    }
    pub fn open(&self) -> Engine {
        Engine::open(self.db(), scope(), OpenOptions::default()).unwrap()
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
pub fn scope() -> Scope {
    Scope {
        service: "local-service".into(),
        account: "alice".into(),
    }
}
pub fn put(revision: u64, key: &str, value: &str, fault: Fault) -> Put {
    Put {
        expected_revision: revision.to_string(),
        key: key.into(),
        value: value.into(),
        fault,
    }
}
pub fn snapshot(reply: Reply) -> Snapshot {
    reply.result.unwrap().unwrap()
}
