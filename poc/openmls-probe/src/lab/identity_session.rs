//! 生命周期仅由 Rust 会话持有；退出或切换范围后不能消费旧展示对象。
use super::{checked, codec, ensure, Context, LabError};
use crate::identity_trust::Display;
use std::{collections::BTreeMap, path::PathBuf};

pub struct Session {
    pub(super) interactive: bool,
    scope: Option<(PathBuf, Context)>,
    pub(super) nonce: String,
    pub(super) displays: BTreeMap<String, Display>,
}

pub(super) fn random() -> Result<String, LabError> {
    let mut bytes = [0u8; 32];
    checked("random_source", getrandom::getrandom(&mut bytes))?;
    Ok(codec::digest_hex(&bytes))
}

impl Session {
    /// 一次真实 Rust 进程/引擎生命周期；JSON 请求不能指定生命周期标识。
    pub fn new() -> Result<Self, LabError> {
        Ok(Self {
            interactive: true,
            scope: None,
            nonce: random()?,
            displays: BTreeMap::new(),
        })
    }

    pub(super) fn single() -> Result<Self, LabError> {
        let mut session = Self::new()?;
        session.interactive = false;
        Ok(session)
    }

    pub fn execute(&mut self, input: &str) -> Result<serde_json::Value, LabError> {
        super::execute_session(input, self)
    }

    pub(super) fn activate(
        &mut self,
        directory: PathBuf,
        context: Context,
    ) -> Result<(), LabError> {
        let next = (directory, context);
        if self.scope.as_ref() != Some(&next) {
            self.nonce = random()?;
            self.displays.clear();
            self.scope = Some(next);
        }
        Ok(())
    }

    pub(super) fn require(&self) -> Result<(), LabError> {
        ensure(
            self.interactive,
            "identity_session_required",
            "核验展示与确认必须使用同一 Rust 会话",
        )
    }

    pub(super) fn verify(&self, display: &Display) -> Result<(), LabError> {
        self.require()?;
        ensure(
            display.session_nonce == self.nonce
                && self.displays.get(&display.display_nonce) == Some(display),
            "identity_confirmation_stale",
            "展示对象不属于本次生命周期或已被替换",
        )
    }
}
