//! 回收后的内容缺失是显式状态；原证明、槽身份及执行结果仍有总预算。
use super::{checked, ensure, wire_sync_types::Availability, LabError};
use crate::permission::receipts::SignedRecord;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) const MESSAGE_LIMIT: usize = 4096;
pub(super) const SLOT_LIMIT: usize = 10_000;
pub(super) const PLAN_LIMIT: usize = 1024;
pub(super) const BYTE_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    pub attempt_id: String,
    pub header_bytes: String,
    pub envelope_sha256: String,
    pub replaces_attempt_id: Option<String>,
    pub closure_id: Option<String>,
    pub terminal: Terminal,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Terminal {
    Accepted { receipt: SignedRecord },
    Closed { receipt: SignedRecord },
    Rejected { receipt: SignedRecord },
}
impl Terminal {
    pub fn receipt(&self) -> &SignedRecord {
        match self {
            Self::Accepted { receipt } | Self::Closed { receipt } | Self::Rejected { receipt } => {
                receipt
            }
        }
    }
    pub fn status(&self) -> &'static str {
        match self {
            Self::Accepted { .. } => "accepted",
            Self::Closed { .. } => "closed",
            Self::Rejected { .. } => "rejected",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Message {
    pub logical_key: String,
    pub acceptance_id: String,
    pub attempt_id: String,
    pub header_bytes: String,
    pub envelope_sha256: String,
    pub payload_digest: [u8; 32],
    pub acceptance_receipt: SignedRecord,
    pub availability: Availability,
    pub plan_id: String,
    pub outbound: Vec<Attempt>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SlotFact {
    pub event_id: String,
    pub acceptance_id: String,
    pub original_event_sha256: String,
    pub kind: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub receipt: SignedRecord,
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_json: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepared {
    pub request_json: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub version: u32,
    pub messages: BTreeMap<String, Message>,
    pub slots: BTreeMap<u64, SlotFact>,
    pub plans: BTreeMap<String, Plan>,
    // 空字段不改变v1原字节；首次准备才升级v2，完成后也不降级。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub prepared: BTreeMap<String, Prepared>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            messages: BTreeMap::new(),
            slots: BTreeMap::new(),
            plans: BTreeMap::new(),
            prepared: BTreeMap::new(),
        }
    }
}
impl State {
    pub fn budget(&self) -> Result<usize, LabError> {
        let bytes = checked("reclaim_state", serde_json::to_vec(self))?.len();
        ensure(
            self.messages.len() <= MESSAGE_LIMIT
                && self.slots.len() <= SLOT_LIMIT
                && self.plans.len() + self.prepared.len() <= PLAN_LIMIT
                && bytes <= BYTE_LIMIT,
            "resource_exhausted",
            "回收证明或计划账本达到独立硬预算",
        )?;
        Ok(bytes)
    }
    pub fn summary(&self) -> Result<Value, LabError> {
        let mut result = json!({"version":self.version,"message_count":self.messages.len(),
            "slot_count":self.slots.len(),"plan_count":self.plans.len(),"proof_bytes":self.budget()?,
            "message_limit":MESSAGE_LIMIT,"slot_limit":SLOT_LIMIT,"plan_limit":PLAN_LIMIT,"byte_limit":BYTE_LIMIT});
        if self.version == 2 {
            result["prepared_count"] = json!(self.prepared.len());
            result["plan_count"] = json!(self.plans.len() + self.prepared.len());
            result["applied_count"] = json!(self.plans.len());
        }
        Ok(result)
    }
}
