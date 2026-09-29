//! 签名分页仅包装既有双游标引擎；原始页完整验证后才允许落盘。
use super::{
    checked, ensure, rebuild_stream,
    state::DeviceState,
    wire_sync,
    wire_sync_types::{Event, Slot},
    wire_types::{bytes, decimal, Header},
    LabError,
};
use crate::{
    message_acceptance, permission::receipts::SignedRecord, rebuild_stream as protocol,
    rollback_anchor,
};
use serde::Deserialize;
use serde_json::{json, Value};

/// 只读完整快照，不恢复provider。被调用的bind/download只核验公开签名和修改临时元数据；
/// 不得在这些入口加入MLS、持久化或外部副作用。真正提交仍在锚预约后重新运行。
pub(super) fn preflight(
    locked: &super::store::LockedDevice,
    request: &super::Request,
    context: &super::Context,
) -> Result<(), LabError> {
    if !matches!(
        request.operation,
        super::Operation::RebuildStreamBind { .. }
            | super::Operation::RebuildStreamDownload { .. }
            | super::Operation::RebuildStreamPull { .. }
            | super::Operation::WireDownloadSigned { .. }
            | super::Operation::WireDownload { .. }
            | super::Operation::WireProcess
            | super::Operation::WireReclaimRequest { .. }
            | super::Operation::WireReclaim { .. }
            | super::Operation::WireRetention { .. }
            | super::Operation::WireSend { .. }
    ) {
        return Ok(());
    }
    let head = super::rollback_io::state_hash(&request.directory)?;
    let mut metadata = locked
        .metadata_committed(
            context,
            &checked("anchor_head", rollback_anchor::decode_hex(&head))?,
        )?
        .ok_or_else(|| LabError::new("anchor_state", "已登记设备缺少完整快照"))?;
    super::rebuild_state::guard(&metadata, &request.operation)?;
    super::wire_stream_source::preflight(&metadata, &request.operation)?;
    if matches!(
        request.operation,
        super::Operation::WireReclaimRequest { .. }
            | super::Operation::WireReclaim { .. }
            | super::Operation::WireRetention { .. }
            | super::Operation::WireSend { .. }
    ) {
        super::wire_send_order::preflight(&metadata, &request.operation)?;
        super::consistency_state::guard(&metadata, &request.operation)?;
        super::permissions::guard(&metadata, &request.operation)?;
    }
    match &request.operation {
        super::Operation::WireSend { .. } => {
            super::wire_send_order::preflight_send(&metadata, &request.operation)?;
        }
        super::Operation::WireReclaimRequest {
            plan_id,
            acceptance_ids,
        } => {
            super::wire_reclaim::request(&metadata, plan_id.clone(), acceptance_ids.clone())?;
        }
        super::Operation::WireReclaim { receipt } => {
            super::wire_reclaim::execute(&mut metadata, receipt.clone())?;
        }
        super::Operation::WireRetention {
            receipt,
            after_seq,
            limit,
        } => {
            super::wire_reclaim::retention(
                &metadata,
                receipt.clone(),
                after_seq.clone(),
                limit.clone(),
            )?;
        }
        super::Operation::RebuildStreamPull { limit } => {
            rebuild_stream::validate_pull(&metadata, limit)?;
        }
        super::Operation::RebuildStreamBind { binding } => {
            rebuild_stream::bind(&mut metadata, binding.clone())?;
        }
        super::Operation::RebuildStreamDownload {
            page_bytes,
            receipt,
        } => {
            download(&mut metadata, page_bytes.clone(), receipt.clone())?;
        }
        super::Operation::WireDownloadSigned {
            page_bytes,
            receipt,
        } => {
            super::wire_stream_source::download(
                &mut metadata,
                page_bytes.clone(),
                receipt.clone(),
            )?;
        }
        _ => {}
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    stream_id: String,
    events: Vec<Slot>,
    next_after_seq: String,
    watermark: String,
    has_more: bool,
}

fn validate_messages(state: &DeviceState, page: &Page) -> Result<(), LabError> {
    let plan = rebuild_stream::healthy(state)?;
    let joined = state
        .permissions
        .admission
        .joined_record
        .as_ref()
        .ok_or_else(|| LabError::new("rebuild_stream_join", "缺少已验证的实际入群记录"))?;
    let join =
        crate::permission::Statement::parse(&bytes(&joined.change.statement_bytes, 16 * 1024)?)?;
    for slot in &page.events {
        match &slot.event {
            Some(Event::Message {
                acceptance_id,
                envelope,
                acceptance_receipt,
            }) => {
                let raw_header = bytes(&envelope.header_bytes, 16 * 1024)?;
                let header = Header::parse(&raw_header)?;
                ensure(
                    header.service_id == state.context.service
                        && header.conversation_id == plan.trust.checkpoint.conversation_id
                        && decimal(&header.authorization_version)?
                            >= decimal(&join.authorization_version)?
                        && header.recipients.iter().any(|m| {
                            m.account_id == state.context.account
                                && m.device_id == state.context.device
                        }),
                    "rebuild_stream_scope",
                    "页中消息不属于新设备实际加入后的授权范围",
                )?;
                let receipt = acceptance_receipt.as_ref().ok_or_else(|| {
                    LabError::new("rebuild_stream_acceptance", "新流消息缺少精确接受证明")
                })?;
                let accepted = message_acceptance::verify(&plan.trust.relay_receipt_key, receipt)?;
                let payload = bytes(&envelope.payload_bytes, 512 * 1024)?;
                ensure(
                    accepted.acceptance_id == *acceptance_id
                        && accepted.service_id == header.service_id
                        && accepted.conversation_id == header.conversation_id
                        && accepted.authorization_version == header.authorization_version
                        && accepted.crypto_state_ref == header.crypto_state_ref
                        && accepted.envelope_sha256
                            == message_acceptance::envelope_digest(&raw_header, &payload),
                    "rebuild_stream_acceptance",
                    "接受证明与页中消息原字节不同",
                )?;
            }
            Some(Event::CryptoControl { .. }) => {
                return Err(LabError::new(
                    "signed_permission_required",
                    "重建签名权限流不接受无签名控制记录",
                ))
            }
            // 回执与不可用槽位由本次Service签页绑定范围；不把服务器声明当作独立密码证明。
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn download(
    state: &mut DeviceState,
    page_bytes: String,
    receipt: SignedRecord,
) -> Result<Value, LabError> {
    let granted = rebuild_stream::binding(state)?;
    let raw = bytes(&page_bytes, protocol::PAGE_BYTES_LIMIT)?;
    let page_sha256 = rollback_anchor::hash_bytes(&raw);
    if let Some(last) = &state.rebuild_stream.last_page {
        if last.page_sha256 == page_sha256 && last.receipt == receipt {
            let mut result = last.result.clone();
            result["duplicate"] = json!(true);
            result["sync"] = state.wire_sync.summary();
            return Ok(result);
        }
    }
    let pending =
        state.rebuild_stream.pending_pull.as_ref().ok_or_else(|| {
            LabError::new("rebuild_stream_request", "没有本机持久化的活动拉取请求")
        })?;
    let pull = protocol::verify_pull(&granted, pending)?;
    let plan = rebuild_stream::healthy(state)?;
    let signed = protocol::verify_page(&plan.trust.relay_receipt_key, &receipt)?;
    let binding = state
        .rebuild_stream
        .binding
        .as_ref()
        .ok_or_else(|| LabError::new("rebuild_sync_unavailable", "授权未保存"))?;
    ensure(
        signed.binding_sha256 == protocol::signed_digest(binding)?
            && signed.request_sha256 == protocol::signed_digest(pending)?
            && signed.service_id == pull.service_id
            && signed.conversation_id == pull.conversation_id
            && signed.successor_scope == pull.successor_scope
            && signed.stream_id == pull.stream_id
            && signed.after_seq == pull.after_seq
            && signed.limit == pull.limit
            && signed.challenge == pull.challenge
            && signed.page_sha256 == page_sha256
            && pull.after_seq == state.wire_sync.download_cursor.to_string(),
        "rebuild_stream_page",
        "签页不属于本机活动请求、授权或原始页面",
    )?;
    let page: Page = checked("rebuild_stream_page", serde_json::from_slice(&raw))?;
    ensure(
        page.stream_id == granted.stream_id && page.events.len() as u64 <= decimal(&pull.limit)?,
        "rebuild_stream_page",
        "页代际或条数与固定请求不符",
    )?;
    validate_messages(state, &page)?;
    let mut result = wire_sync::download_verified(
        state,
        page.stream_id,
        page.events,
        page.next_after_seq,
        page.watermark,
        page.has_more,
    )?;
    if result["status"] == "downloaded" {
        state.wire_sync.source_verified = true;
        result["sync"] = state.wire_sync.summary();
        state.rebuild_stream.pending_pull = None;
        state.rebuild_stream.last_page = Some(rebuild_stream::DownloadedPage {
            page_sha256,
            receipt,
            result: result.clone(),
        });
    }
    Ok(result)
}
