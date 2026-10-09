//! 实验操作输入及旧控制记录的幂等索引。
use super::{codec, digest, wire_sync, Peer, Pin};
use crate::authorization::{AuthorizationRequest, DeviceAuthorization};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Init,
    Create {
        peers: Vec<Peer>,
    },
    Join {
        welcome: String,
        pins: Vec<Pin>,
    },
    Send {
        id: String,
        payload: String,
    },
    Receive {
        id: String,
        ciphertext: String,
    },
    Remove {
        id: String,
        member: String,
    },
    ApplyCommit {
        commit: String,
    },
    Inspect,
    AnchorInspect,
    AnchorResume,
    RebuildInit {
        template: crate::rollback_anchor::rebuild::Plan,
    },
    RebuildOffer,
    RebuildStreamRequest {
        plan: crate::rollback_anchor::rebuild::Plan,
        approval: crate::rollback_anchor::Signed,
        anchor_request: crate::rollback_anchor::Signed,
        anchor_response: crate::rollback_anchor::Signed,
    },
    RebuildStreamBind {
        binding: crate::permission::receipts::SignedRecord,
    },
    RebuildStreamPull {
        limit: String,
    },
    RebuildStreamDownload {
        page_bytes: String,
        receipt: crate::permission::receipts::SignedRecord,
    },
    RebuildApprove {
        plan: crate::rollback_anchor::rebuild::Plan,
    },
    AnchorRebuild {
        plan: crate::rollback_anchor::rebuild::Plan,
        approval: crate::rollback_anchor::Signed,
        successor_directory: std::path::PathBuf,
    },
    AnchorRebuildCancel {
        plan: crate::rollback_anchor::rebuild::Plan,
        approval: crate::rollback_anchor::Signed,
    },
    ConsistencyChallenge,
    ConsistencyObserveHead {
        head: crate::permission::receipts::SignedRecord,
    },
    ConsistencyObserveFork {
        predecessor: crate::permission::PermissionCheckpoint,
        left: crate::permission::receipts::RecoveryRecord,
        right: crate::permission::receipts::RecoveryRecord,
    },
    ConsistencyResume {
        head: crate::permission::receipts::SignedRecord,
    },
    ConsistencyInspect,
    ConsistencyExchangeBegin {
        source: crate::permission::Identity,
        verified_fingerprint: String,
        verification: crate::consistency_exchange::Verification,
    },
    ConsistencyExchangeExport {
        request: crate::permission::receipts::SignedRecord,
        change_id: String,
    },
    ConsistencyExchangeImport {
        package: crate::permission::receipts::SignedRecord,
    },
    ConsistencyExchangeCancel,
    ConsistencyExchangeInspect,
    HistoryRequest {
        transfer_id: String,
        source: crate::permission::Identity,
        selection: Vec<crate::history_transfer::Selection>,
        validity_secs: Option<u16>,
    },
    HistoryExport {
        request: crate::permission::receipts::SignedRecord,
    },
    HistoryImport {
        request: crate::permission::receipts::SignedRecord,
        package: crate::history_transfer::Package,
        receipt: crate::permission::receipts::SignedRecord,
    },
    HistoryCancel {
        transfer_id: String,
    },
    HistoryInspect,
    PermissionBootstrap {
        checkpoint: crate::permission::PermissionCheckpoint,
        relay_receipt_key: Option<String>,
    },
    PermissionPrepare {
        change_id: String,
        action: crate::permission::Action,
        validity_secs: Option<u16>,
    },
    PermissionApply {
        change: crate::permission::Proof,
    },
    PermissionInspect,
    PermissionPinMember {
        member: crate::permission::Member,
    },
    PermissionPrepareAdd {
        change_id: String,
        member: crate::permission::Member,
        key_package: String,
        history_policy: String,
        validity_secs: Option<u16>,
    },
    PermissionPrepareDevice {
        change_id: String,
        member: crate::permission::Member,
        key_package: String,
        history_policy: String,
        validity_secs: Option<u16>,
    },
    PermissionJoinAnchor {
        checkpoint: crate::permission::PermissionCheckpoint,
        relay_receipt_key: String,
    },
    PermissionDeviceJoinAnchor {
        checkpoint: crate::permission::PermissionCheckpoint,
        relay_receipt_key: String,
    },
    PermissionJoinAdvance {
        record: crate::permission::receipts::RecoveryRecord,
    },
    PermissionJoin {
        record: crate::permission::receipts::RecoveryRecord,
        join: crate::permission::admission::JoinMaterial,
    },
    PermissionCloseRequest,
    PermissionRecover {
        record: crate::permission::receipts::RecoveryRecord,
    },
    WireConfigure {
        conversation_id: String,
        authorization_version: String,
        pending_limit: Option<usize>,
    },
    WireInspect,
    WireReclaimRequest {
        plan_id: String,
        acceptance_ids: Vec<String>,
    },
    WireReclaimList {
        after_plan_id: Option<String>,
        limit: String,
    },
    WireReclaimRecover {
        plan_id: String,
    },
    WireReclaim {
        receipt: crate::permission::receipts::SignedRecord,
    },
    WireRetention {
        receipt: crate::permission::receipts::SignedRecord,
        after_seq: String,
        limit: String,
    },
    WireRead {
        event_ids: Vec<String>,
    },
    WireReadPending,
    WireReadInspect,
    WireSendOrderEnable,
    WireReject {
        logical_message_id: String,
        attempt_id: String,
        rejection_receipt: crate::permission::receipts::SignedRecord,
    },
    WireCloseRequest {
        logical_message_id: String,
        attempt_id: String,
    },
    WireClose {
        logical_message_id: String,
        attempt_id: String,
        closure_receipt: crate::permission::receipts::SignedRecord,
    },
    WireSlotInspect {
        event_seq: String,
    },
    #[cfg(feature = "wire-sequence-probe")]
    WireSequenceSeed {
        stream_id: String,
        base_seq: String,
    },
    WireAccept {
        logical_message_id: String,
        attempt_id: String,
        acceptance_receipt: crate::permission::receipts::SignedRecord,
    },
    WireSend {
        logical_message_id: String,
        attempt_id: String,
        payload: String,
        replaces_attempt_id: Option<String>,
        closure_id: Option<String>,
    },
    WireReceive {
        header_bytes: String,
        payload_bytes: String,
        #[serde(default, deserialize_with = "super::wire_types::present_id")]
        acceptance_id: Option<String>,
        #[serde(default, deserialize_with = "super::wire_types::present_receipt")]
        acceptance_receipt: Option<crate::permission::receipts::SignedRecord>,
    },
    WireDownload {
        stream_id: String,
        events: Vec<wire_sync::Slot>,
        next_after_seq: String,
        watermark: String,
        has_more: bool,
    },
    WireProcess,
    WireDownloadSigned {
        page_bytes: String,
        receipt: crate::permission::receipts::SignedRecord,
    },
    WireApplyDependency {
        control: wire_sync::Control,
    },
    SignAuthorization {
        request: AuthorizationRequest,
    },
    Authorize {
        authorization: DeviceAuthorization,
        key_package: String,
        now_unix_secs: u64,
    },
}

impl Operation {
    pub(super) fn cache_key(&self) -> Option<String> {
        match self {
            Self::Create { .. } => Some("create".into()),
            Self::Join { .. } => Some("join".into()),
            Self::Remove { id, .. } => Some(format!("remove:{id}")),
            Self::ApplyCommit { commit } => Some(format!(
                "commit:{}",
                codec::encode(&digest(commit.as_bytes()))
            )),
            Self::RebuildApprove { plan } => Some(format!("rebuild:{}", plan.rebuild_id)),
            _ => None,
        }
    }
}
