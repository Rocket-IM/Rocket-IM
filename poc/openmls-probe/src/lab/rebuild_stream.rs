//! 后继流申请、固定授权和单活动拉取；与既有密码快照及独立锚共同提交。
use super::{checked, codec, ensure, rebuild_state, rollback_io, state::DeviceState, LabError};
use crate::{
    permission::receipts::{self, SignedRecord},
    rebuild_stream::{
        self as protocol, BindingStatement, PullStatement, Registration, RequestStatement, Trust,
    },
    rollback_anchor::{rebuild::Plan, Signed},
};
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub registration: Option<Registration>,
    pub binding: Option<SignedRecord>,
    pub pending_pull: Option<SignedRecord>,
    pub last_page: Option<DownloadedPage>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DownloadedPage {
    pub page_sha256: String,
    pub receipt: SignedRecord,
    pub result: Value,
}

pub(super) fn healthy(state: &DeviceState) -> Result<&Plan, LabError> {
    ensure(
        std::env::var_os("RIM_ROLLBACK_ANCHOR_CONFIG").is_some(),
        "rebuild_anchor_required",
        "新消息流必须由可信独立锚保护",
    )?;
    rebuild_state::healthy(state)?;
    state
        .rebuild
        .as_ref()
        .ok_or_else(|| LabError::new("rebuild_stream_required", "仅重建后继使用此流授权"))
}

fn sign<T: Serialize>(
    state: &DeviceState,
    value: &T,
    domain: &[u8],
) -> Result<SignedRecord, LabError> {
    let raw = checked("rebuild_stream_encoding", serde_json::to_vec(value))?;
    let mut bytes = domain.to_vec();
    bytes.extend(&raw);
    let signature = state
        .signer()?
        .sign(&bytes)
        .map_err(|_| LabError::new("rebuild_stream_signature", "新设备请求签名失败"))?;
    Ok(SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(&signature),
    })
}

pub(super) fn request(
    state: &mut DeviceState,
    plan: Plan,
    approval: Signed,
    anchor_request: Signed,
    anchor_response: Signed,
) -> Result<Value, LabError> {
    let mut expected = healthy(state)?.clone();
    // 初始快照不递归包含自身摘要；完整原计划由独立批准和锚关联证明核验。
    expected.successor_head = plan.successor_head.clone();
    ensure(
        expected == plan,
        "rebuild_stream_context",
        "流申请与本机唯一重建计划不同",
    )?;
    if let Some(saved) = &state.rebuild_stream.registration {
        ensure(
            saved.plan == plan
                && saved.approval == approval
                && saved.anchor_request == anchor_request
                && saved.anchor_response == anchor_response,
            "rebuild_stream_conflict",
            "已保存申请只允许精确重试",
        )?;
        return Ok(json!({"registration":saved,"duplicate":true}));
    }
    ensure(
        state.wire_sync.stream_id.is_none()
            && state.wire_sync.download_cursor == 0
            && state.wire_sync.processed_cursor == 0
            && state.wire_sync.slots.is_empty(),
        "rebuild_stream_conflict",
        "已有消息流或游标不能改为新授权",
    )?;
    let join_record = state
        .permissions
        .admission
        .joined_record
        .clone()
        .ok_or_else(|| LabError::new("rebuild_stream_join", "新设备必须先实际验证Welcome"))?;
    let statement = RequestStatement {
        protocol_version: "rim-rebuild-stream-request-1".into(),
        plan_sha256: checked("rebuild_plan", plan.digest())?,
        successor_scope: plan.successor_scope.clone(),
        conversation_id: plan.trust.checkpoint.conversation_id.clone(),
        stream_id: rollback_io::random_hex()?,
        initial_cursor: "0".into(),
        join_proof_sha256: receipts::proof_digest(&join_record.change)?,
    };
    let signed = sign(state, &statement, protocol::REQUEST_DOMAIN)?;
    let trusted = Trust {
        old_scope: plan.old_scope.clone(),
        anchor_public_key: plan.anchor_public_key.clone(),
        trust: plan.trust.clone(),
    };
    let registration = Registration {
        plan,
        approval,
        anchor_request,
        anchor_response,
        request: signed,
        join_record,
    };
    protocol::verify_registration(&trusted, &registration)?;
    state.rebuild_stream.registration = Some(registration);
    Ok(json!({"registration":state.rebuild_stream.registration,"duplicate":false}))
}

pub(super) fn binding(state: &DeviceState) -> Result<BindingStatement, LabError> {
    let plan = healthy(state)?;
    let receipt = state
        .rebuild_stream
        .binding
        .as_ref()
        .ok_or_else(|| LabError::new("rebuild_sync_unavailable", "未取得并保存独立新流授权"))?;
    Ok(protocol::verify_binding(
        &plan.trust.relay_receipt_key,
        receipt,
    )?)
}

pub(super) fn bind(state: &mut DeviceState, receipt: SignedRecord) -> Result<Value, LabError> {
    let plan = healthy(state)?;
    let granted = protocol::verify_binding(&plan.trust.relay_receipt_key, &receipt)?;
    let registration = state
        .rebuild_stream
        .registration
        .as_ref()
        .ok_or_else(|| LabError::new("rebuild_stream_request", "缺少本机持久化原申请"))?;
    let trusted = Trust {
        old_scope: plan.old_scope.clone(),
        anchor_public_key: plan.anchor_public_key.clone(),
        trust: plan.trust.clone(),
    };
    let requested = protocol::verify_registration(&trusted, registration)?;
    ensure(
        granted.request_sha256 == protocol::signed_digest(&registration.request)?
            && granted.plan_sha256 == requested.plan_sha256
            && granted.successor_scope == requested.successor_scope
            && granted.conversation_id == requested.conversation_id
            && granted.stream_id == requested.stream_id
            && granted.initial_cursor == "0"
            && granted.join_proof_sha256 == requested.join_proof_sha256,
        "rebuild_stream_binding",
        "授权未绑定本机原申请、新身份和新流",
    )?;
    if let Some(saved) = &state.rebuild_stream.binding {
        ensure(
            *saved == receipt,
            "rebuild_stream_conflict",
            "已有流授权不能替换",
        )?;
        return Ok(json!({"status":"bound","duplicate":true,"sync":state.wire_sync.summary()}));
    }
    ensure(
        state.wire_sync.stream_id.is_none()
            && state.wire_sync.download_cursor == 0
            && state.wire_sync.processed_cursor == 0
            && state.wire_sync.slots.is_empty(),
        "rebuild_stream_conflict",
        "绑定不能覆盖已有流、消息或游标",
    )?;
    state.wire_sync.stream_id = Some(granted.stream_id);
    state.rebuild_stream.binding = Some(receipt);
    Ok(json!({"status":"bound","duplicate":false,"sync":state.wire_sync.summary()}))
}

pub(super) fn validate_pull(
    state: &DeviceState,
    limit: &str,
) -> Result<BindingStatement, LabError> {
    let granted = binding(state)?;
    let count = super::wire_types::decimal(limit)?;
    ensure(
        (1..=100).contains(&count),
        "rebuild_stream_limit",
        "页大小必须为1至100",
    )?;
    ensure(
        !state.wire_sync.halted,
        "stream_conflict",
        "已冲突的消息流不能继续拉取",
    )?;
    if let Some(saved) = &state.rebuild_stream.pending_pull {
        let previous = protocol::verify_pull(&granted, saved)?;
        ensure(
            previous.limit == limit
                && previous.after_seq == state.wire_sync.download_cursor.to_string(),
            "rebuild_stream_conflict",
            "活动拉取只允许精确重试",
        )?;
    }
    Ok(granted)
}

pub(super) fn pull(state: &mut DeviceState, limit: String) -> Result<Value, LabError> {
    let granted = validate_pull(state, &limit)?;
    if let Some(saved) = &state.rebuild_stream.pending_pull {
        return Ok(json!({"request":saved,"duplicate":true}));
    }
    let receipt = state
        .rebuild_stream
        .binding
        .as_ref()
        .ok_or_else(|| LabError::new("rebuild_sync_unavailable", "流授权未保存"))?;
    let statement = PullStatement {
        protocol_version: "rim-rebuild-stream-pull-1".into(),
        service_id: state.context.service.clone(),
        conversation_id: granted.conversation_id.clone(),
        successor_scope: granted.successor_scope.clone(),
        stream_id: granted.stream_id.clone(),
        binding_sha256: protocol::signed_digest(receipt)?,
        after_seq: state.wire_sync.download_cursor.to_string(),
        limit,
        challenge: rollback_io::random_hex()?,
    };
    let request = sign(state, &statement, protocol::PULL_DOMAIN)?;
    protocol::verify_pull(&granted, &request)?;
    state.rebuild_stream.pending_pull = Some(request);
    Ok(json!({"request":state.rebuild_stream.pending_pull,"duplicate":false}))
}
