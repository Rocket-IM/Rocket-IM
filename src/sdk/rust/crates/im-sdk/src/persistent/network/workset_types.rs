//! 原件摘要使用ASCII字段的紧凑JSON数组；不依赖对象键顺序或PG的JSON表示。
use super::super::types::*;
use serde::{Deserialize, Serialize};

pub const WORKSET_VERSION: &str = "control-workset-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityWorkset {
    pub version: String,
    pub id: String,
    pub owner: Identity,
    /// 原系统进度保护标识，限定到创建本工作集的SDK数据空间；不是授权凭证。
    pub sdk_instance: String,
    pub conversation: String,
    pub context: String,
    pub first: String,
    pub last: String,
    pub originals_hash: String,
}
impl CapacityWorkset {
    pub(super) fn digest(&self) -> Result<String> {
        Ok(hash(&encode(&[
            "rocket-im/capacity-workset/1",
            &self.version,
            &self.owner.scope.service,
            &self.owner.scope.account,
            &self.owner.scope.device,
            &self.owner.identity_key,
            &self.sdk_instance,
            &self.conversation,
            &self.context,
            &self.first,
            &self.last,
            &self.originals_hash,
        ])?))
    }
    pub(super) fn validate(&self) -> Result<()> {
        let bad = || Error::paused("workset_invalid");
        self.owner.validate().map_err(|_| bad())?;
        id(&self.conversation).map_err(|_| bad())?;
        let first = number(&self.first)?;
        let last = number(&self.last)?;
        if self.version != WORKSET_VERSION
            || first == 0
            || first > last
            || last > 512
            || unhex(&self.sdk_instance, 32)?.len() != 32
            || unhex(&self.originals_hash, 32)?.len() != 32
            || (self.context != "initial" && unhex(&self.context, 32)?.len() != 32)
            || self.id != self.digest()?
        {
            return Err(bad());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorksetPhase {
    Prepared,
    Confirmed,
    Active,
    Settled,
}

/// 本地持久观察，不是跨库快照。只有SDK Active/Settled包含已持久保存的Service确认。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityWorksetState {
    pub workset: CapacityWorkset,
    pub phase: WorksetPhase,
}
