use std::{cell::RefCell, collections::BTreeSet};

use crate::protocol::ApiError;

thread_local! {
    // 只登记本 WASM 实例的连接所有权；业务状态仍唯一保存在 SQLite。
    // 跨 Worker 的竞争另由 OPFS 独占 SAH 与平台 Web Lock 拒绝。
    static ACTIVE_SCOPES: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}

pub struct ScopeLease(String);

impl ScopeLease {
    pub fn acquire(name: &str) -> Result<Self, ApiError> {
        ACTIVE_SCOPES.with(|scopes| {
            let mut scopes = scopes.try_borrow_mut().map_err(|_| Self::busy())?;
            if scopes.contains(name) {
                return Err(Self::busy());
            }
            if scopes.len() >= 16 {
                return Err(ApiError::new(
                    "capacity_exceeded",
                    "同时打开的数据空间超过上限。",
                    false,
                ));
            }
            scopes.insert(name.into());
            Ok(Self(name.into()))
        })
    }

    pub fn release(&mut self) -> Result<(), ApiError> {
        ACTIVE_SCOPES.with(|scopes| {
            scopes
                .try_borrow_mut()
                .map_err(|_| Self::busy())?
                .remove(&self.0);
            Ok(())
        })
    }

    fn busy() -> ApiError {
        ApiError::new("scope_in_use", "数据空间已有所有者。", false)
    }
}
