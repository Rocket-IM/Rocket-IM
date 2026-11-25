//! 原件摘要使用ASCII字段的紧凑JSON数组；不依赖对象键顺序或PG的JSON表示。
use super::super::types::*;
use serde::{Deserialize, Serialize};

pub const WORKSET_VERSION: &str = "control-workset-v1";
pub const WORKSET_CHAIN_VERSION: &str = "control-workset-v2";

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
    /// v2绑定唯一前轮；v1必须缺失。不是宿主可自由选择的用途标签。
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "previous_id"
    )]
    pub previous: Option<String>,
}
fn previous_id<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(decoder).map(Some)
}
impl CapacityWorkset {
    pub(super) fn digest(&self) -> Result<String> {
        let mut fields = vec![
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
        ];
        if self.version == WORKSET_CHAIN_VERSION {
            fields[0] = "rocket-im/capacity-workset/2";
            fields.push(self.previous.as_deref().unwrap_or(""));
        }
        Ok(hash(&encode(&fields)?))
    }
    pub(super) fn validate(&self) -> Result<()> {
        let bad = || Error::paused("workset_invalid");
        self.owner.validate().map_err(|_| bad())?;
        id(&self.conversation).map_err(|_| bad())?;
        let first = number(&self.first)?;
        let last = number(&self.last)?;
        let version_valid = match (self.version.as_str(), self.previous.as_deref()) {
            (WORKSET_VERSION, None) => true,
            (WORKSET_CHAIN_VERSION, Some(previous)) => unhex(previous, 32)?.len() == 32,
            _ => false,
        };
        if !version_valid
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

    pub(super) fn follows(&self, previous: &Self) -> Result<bool> {
        Ok(self.version == WORKSET_CHAIN_VERSION
            && self.previous.as_deref() == Some(previous.id.as_str())
            && self.owner == previous.owner
            && self.sdk_instance == previous.sdk_instance
            && self.conversation == previous.conversation
            && number(&self.first)? > number(&previous.last)?)
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
