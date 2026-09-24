//! 全包验证后才提交独立副本和终态；不会触碰MLS、账号roster或消息游标。
use super::{
    checked, ensure,
    history_state::{self as stored, ArchivedCopy, Body, ImportRecord, RequestStatus, LIMIT},
    state::DeviceState,
    LabError,
};
use crate::{
    history_transfer::{self as public, Package},
    permission::receipts::SignedRecord,
};
use openmls_traits::{crypto::OpenMlsCrypto, types::HpkeCiphertext, OpenMlsProvider};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) fn import(
    state: &mut DeviceState,
    request: SignedRecord,
    package: Package,
    receipt: SignedRecord,
) -> Result<Value, LabError> {
    let cp = stored::current(state)?;
    let (statement, _) = public::verify(cp, &request, &package)?;
    stored::live(&statement)?;
    ensure(
        statement.target == stored::own(state),
        "history_denied",
        "只有指定目标可以导入",
    )?;
    let receipt_key = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "缺少Service回执公钥"))?;
    public::verify_receipt(receipt_key, &request, &package, &receipt)?;
    let local = state
        .history_transfers
        .requests
        .get(&statement.transfer_id)
        .ok_or_else(|| LabError::new("history_unavailable", "本机没有原始迁移请求"))?;
    ensure(
        local.request == request,
        "history_conflict",
        "请求与本机原始字节不一致",
    )?;
    ensure(
        local.status != RequestStatus::Cancelled,
        "history_cancelled",
        "本机已取消迁移",
    )?;
    if let Some(saved) = state.history_transfers.imports.get(&statement.transfer_id) {
        ensure(
            saved.package == package
                && saved.receipt == receipt
                && local.status == RequestStatus::Imported,
            "history_conflict",
            "已导入迁移对应另一份包或回执",
        )?;
        let mut result = saved.result.clone();
        result["duplicate"] = json!(true);
        result["imported_count"] = json!(0);
        return Ok(result);
    }
    ensure(
        local.status == RequestStatus::Pending,
        "history_conflict",
        "请求已结束但没有完整导入记录",
    )?;
    let private = local
        .private_key
        .as_ref()
        .ok_or_else(|| LabError::new("history_unavailable", "本机没有迁移解密材料"))?;
    let input = HpkeCiphertext {
        kem_output: public::bytes(&package.kem_output, 32)?.into(),
        ciphertext: public::bytes(&package.ciphertext, public::MAX_BODY + 16)?.into(),
    };
    let raw = checked(
        "history_decryption_failed",
        state.provider.crypto().hpke_open(
            super::codec::CIPHERSUITE.hpke_config(),
            &input,
            private,
            &public::hpke_info(&request)?,
            &public::bytes(&request.statement_bytes, 16 * 1024)?,
        ),
    )?;
    ensure(
        raw.len() <= public::MAX_BODY,
        "resource_exhausted",
        "历史明文包超过256KiB",
    )?;
    let body: Body = checked("history_invalid", serde_json::from_slice(&raw))?;
    ensure(
        body.protocol_version == "rim-history-copies-1"
            && body.records.len() == statement.selection.len(),
        "history_context",
        "副本包没有精确覆盖选择清单",
    )?;
    let mut staged = BTreeMap::new();
    let mut summaries = Vec::new();
    for (copy, selected) in body.records.into_iter().zip(&statement.selection) {
        let (key, summary) = stored::validate_copy(state, &statement, &copy, selected)?;
        if let Some(native) = state.wire.inbox.get(&key) {
            ensure(
                native.envelope == copy.envelope
                    && native.payload_digest == super::codec::digest(copy.payload.as_bytes())
                    && native
                        .acceptance_id
                        .as_ref()
                        .is_none_or(|id| *id == selected.acceptance_id),
                "history_conflict",
                "迁移副本与目标已验证消息冲突",
            )?;
        }
        let copy_header =
            super::wire_types::Header::parse(&super::codec::decode(&copy.envelope.header_bytes)?)?;
        for native in state.wire.outbox.values().filter(|r| r.logical_key == key) {
            ensure(
                native.payload == copy.payload
                    && (native.attempt_id != copy_header.attempt_id
                        || native.envelope == copy.envelope),
                "history_conflict",
                "迁移副本与本机原发送正文或同尝试字节冲突",
            )?;
            if let Some(accepted) = &native.acceptance_receipt {
                ensure(
                    native.envelope == copy.envelope && *accepted == copy.acceptance_receipt,
                    "history_conflict",
                    "迁移副本与本机原发送接受事实冲突",
                )?;
            }
        }
        ensure(
            !staged.contains_key(&key),
            "history_conflict",
            "包内重复逻辑消息",
        )?;
        if let Some(old) = state.history_transfers.copies.get(&key) {
            ensure(
                old.copy == copy,
                "history_conflict",
                "历史副本正文或原接受身份冲突",
            )?;
        }
        staged.insert(key, copy);
        summaries.push(summary);
    }
    let count = staged
        .keys()
        .filter(|key| !state.history_transfers.copies.contains_key(*key))
        .count();
    ensure(
        state.history_transfers.copies.len() + count <= LIMIT,
        "resource_exhausted",
        "历史副本达到容量上限",
    )?;
    for (key, copy) in staged {
        state
            .history_transfers
            .copies
            .entry(key)
            .or_insert_with(|| ArchivedCopy {
                copy,
                source: statement.source.clone(),
            });
    }
    let result = json!({"transfer_id":statement.transfer_id,"imported_count":count,"duplicate":false,"copies":summaries});
    state.history_transfers.imports.insert(
        statement.transfer_id.clone(),
        ImportRecord {
            package,
            receipt,
            result: result.clone(),
        },
    );
    let local = state
        .history_transfers
        .requests
        .get_mut(&statement.transfer_id)
        .ok_or_else(|| LabError::new("history_conflict", "提交时缺少请求"))?;
    local.private_key = None;
    local.status = RequestStatus::Imported;
    Ok(result)
}
