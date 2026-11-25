//! 只含有界计数和阶段；数字使用u64规范十进制，不包含原请求、密码材料或路径。
use super::{RecoveryPhase, Scope};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityBudget {
    pub category: String,
    pub unit: String,
    pub used: String,
    pub limit: String,
    pub hard_remaining: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityComponent {
    pub category: String,
    pub included_in: String,
    pub bytes: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityReserve {
    pub state: String,
    pub protected_remaining: Option<String>,
    pub ordinary_available: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityOperationState {
    RequiresInput,
    NotReserved,
    Blocked,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityOperation {
    pub operation: String,
    pub state: CapacityOperationState,
    pub blockers: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityBlocker {
    pub code: String,
    pub resource: Option<String>,
    pub operations: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityRecovery {
    pub pending: String,
    pub phase: Option<RecoveryPhase>,
    pub candidate: bool,
    pub locally_authorized: bool,
    pub network_phase: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityCursors {
    pub downloaded: String,
    pub processed: String,
    pub reported: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityUnavailable {
    pub state: String,
    pub reserved: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
    pub version: String,
    pub owner: String,
    pub scope: Scope,
    pub observation_id: String,
    pub consistency: String,
    pub revision: String,
    pub cursors: Option<CapacityCursors>,
    pub recovery: CapacityRecovery,
    pub budgets: Vec<CapacityBudget>,
    pub components: Vec<CapacityComponent>,
    pub reserve: CapacityReserve,
    pub operations: Vec<CapacityOperation>,
    pub blockers: Vec<CapacityBlocker>,
    pub physical: CapacityUnavailable,
    pub remote: CapacityUnavailable,
}
