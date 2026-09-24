//! 锚协调状态不包含私钥；签名日志只用于恢复已经共同提交的结果。
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gate {
    pub binding: String,
    pub txn: String,
    pub base: String,
    pub input: String,
    pub reserved_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuild_fence: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredResult {
    pub kind: String,
    pub value: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Journal {
    pub gate: Gate,
    pub target: String,
    pub result: StoredResult,
}
pub(crate) struct Local {
    pub head: String,
    pub gate: Option<Gate>,
    pub journal: Option<Journal>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorFault {
    #[default]
    None,
    PauseAfterLocalGate,
    PauseAfterAnchorReserve,
    PauseAfterCandidateCommit,
    PauseAfterAnchorFinish,
    PauseAfterAnchorClear,
}
