//! 普通签页只包装原同步引擎；任何未经证明的旧流必须显式迁移，不能由新页洗白。
use super::{
    checked, codec, ensure, state::DeviceState, wire_sync, wire_sync_types::Slot,
    wire_types::decimal, LabError, Operation,
};
use crate::{permission::receipts::SignedRecord, stream_page};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    stream_id: String,
    events: Vec<Slot>,
    next_after_seq: String,
    watermark: String,
    has_more: bool,
}

pub(super) fn guard(state: &DeviceState, operation: &Operation) -> Result<(), LabError> {
    let pinned = state.permissions.recovery.relay_receipt_key.is_some();
    if matches!(operation, Operation::WireDownload { .. }) {
        ensure(
            !pinned,
            "stream_source_required",
            "固定Service公钥后只接受签名分页",
        )?;
    }
    // 后继仍由 rebuild_state 的独立授权门禁核验，普通入口不能赋予后继权限。
    if pinned
        && state.rebuild.is_none()
        && matches!(
            operation,
            Operation::WireDownloadSigned { .. } | Operation::WireProcess
        )
    {
        let sync = &state.wire_sync;
        ensure(
            sync.source_verified
                || (sync.stream_id.is_none()
                    && sync.slots.is_empty()
                    && sync.download_cursor == 0
                    && sync.processed_cursor == 0),
            "source_migration_required",
            "旧流缺少来源证明，必须显式迁移后继续同步",
        )?;
    }
    Ok(())
}

fn verify(state: &DeviceState, page_bytes: &str, receipt: &SignedRecord) -> Result<Page, LabError> {
    let key = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_ref()
        .ok_or_else(|| LabError::new("stream_source_required", "签页需要预固定的Service公钥"))?;
    let raw = crate::permission::types::bytes(page_bytes, stream_page::PAGE_BYTES_LIMIT)
        .map_err(|_| LabError::new("stream_page_invalid", "分页字节编码或尺寸无效"))?;
    let signed = stream_page::verify(key, receipt)?;
    ensure(
        signed.service_id == state.context.service
            && signed.account_id == state.context.account
            && signed.device_id == state.context.device,
        "stream_page_context",
        "签页不属于本机实例、账号与设备",
    )?;
    ensure(
        signed.page_sha256 == codec::digest_hex(&codec::digest(&raw)),
        "stream_page_digest",
        "分页原始字节与签名摘要不符",
    )?;
    let page: Page = checked("stream_page_invalid", serde_json::from_slice(&raw))?;
    ensure(
        page.stream_id == signed.stream_id,
        "stream_page_context",
        "签名与分页流代际不符",
    )?;
    let after = decimal(&signed.after_seq)?;
    let limit = decimal(&signed.limit)?;
    ensure(
        after <= state.wire_sync.download_cursor && page.events.len() as u64 <= limit,
        "stream_page_range",
        "签页起点跳过本机游标或超出条数上限",
    )?;
    ensure(
        match page.events.first() {
            Some(slot) => after.checked_add(1) == Some(decimal(&slot.event_seq)?),
            None => decimal(&page.next_after_seq)? == after,
        },
        "stream_page_range",
        "签页首槽或空页游标不对应已签起点",
    )?;
    super::wire_terminal_reference::preflight(state, &page.events, true)?;
    Ok(page)
}

pub(super) fn preflight(state: &DeviceState, operation: &Operation) -> Result<(), LabError> {
    guard(state, operation)?;
    if let Operation::WireDownloadSigned {
        page_bytes,
        receipt,
    } = operation
    {
        verify(state, page_bytes, receipt)?;
    }
    Ok(())
}

pub(super) fn download(
    state: &mut DeviceState,
    page_bytes: String,
    receipt: SignedRecord,
) -> Result<Value, LabError> {
    let page = verify(state, &page_bytes, &receipt)?;
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
    }
    Ok(result)
}
