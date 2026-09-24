//! 回执pin、未完成意图与退役候选均属于同一设备加密快照。
use crate::permission::{
    receipts::{RecoveryRecord, SignedRecord},
    Action, PermissionCheckpoint,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Intent {
    pub origin_change_id: String,
    pub action: Action,
    pub minimum_version: String,
    pub minimum_state_ref: String,
    #[serde(default)]
    pub satisfied: bool,
}
#[derive(Default, Serialize, Deserialize)]
pub(super) struct RecoveryState {
    pub relay_receipt_key: Option<String>,
    #[serde(default)]
    pub prepare_count: u16,
    pub intent: Option<Intent>,
    pub access_removed: bool,
    pub service_target: Option<PermissionCheckpoint>,
    pub retired: BTreeMap<String, String>,
    pub records: BTreeMap<String, RecoveryRecord>,
    pub closes: BTreeMap<String, SignedRecord>,
    pub verified_refs: BTreeMap<String, String>,
}
