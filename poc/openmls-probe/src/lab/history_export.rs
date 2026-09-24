//! 源端只读取已接受的本机发送或收件副本；外部请求不提供明文。
use super::{
    checked, codec, ensure,
    history_state::{self as stored, Body, Copy, ExportRecord, LIMIT},
    history_transfer,
    state::DeviceState,
    LabError,
};
use crate::{
    history_transfer::{self as public, Package, PackageStatement},
    permission::receipts::SignedRecord,
};
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};
use serde_json::{json, Value};

pub(super) fn export(state: &mut DeviceState, request: SignedRecord) -> Result<Value, LabError> {
    let cp = stored::current(state)?;
    let statement = public::verify_request(cp, &request)?;
    stored::live(&statement)?;
    ensure(
        statement.source == stored::own(state),
        "history_denied",
        "只能由指定源设备导出",
    )?;
    if let Some(saved) = state.history_transfers.exports.get(&statement.transfer_id) {
        ensure(
            saved.request == request,
            "history_conflict",
            "迁移标识绑定其他请求",
        )?;
        return Ok(json!({"request":saved.request,"package":saved.package,"reused":true}));
    }
    ensure(
        state.history_transfers.requests.len() + state.history_transfers.exports.len() < LIMIT,
        "resource_exhausted",
        "迁移记录达到128条上限",
    )?;
    let mut copies = Vec::new();
    for selected in &statement.selection {
        let incoming = state
            .wire
            .inbox
            .values()
            .filter(|r| r.acceptance_id.as_ref() == Some(&selected.acceptance_id))
            .collect::<Vec<_>>();
        let pin = state
            .permissions
            .recovery
            .relay_receipt_key
            .as_ref()
            .ok_or_else(|| LabError::new("trust_required", "缺少Service公钥"))?;
        let mut outgoing = Vec::new();
        for outbound in state.wire.outbox.values() {
            if let Some(receipt) = &outbound.acceptance_receipt {
                if crate::message_acceptance::verify(pin, receipt)?.acceptance_id
                    == selected.acceptance_id
                {
                    outgoing.push((outbound, receipt));
                }
            }
        }
        let total = incoming.len() + outgoing.len();
        ensure(
            total > 0,
            "history_content_unavailable",
            "源端没有选定的已接受副本",
        )?;
        ensure(
            total == 1,
            "history_conflict",
            "同接受ID对应多个发送或收件记录",
        )?;
        let copy = if let Some(inbound) = incoming.first() {
            let payload = inbound.payload.as_ref().ok_or_else(|| {
                LabError::new("history_content_unavailable", "旧快照未保存历史正文")
            })?;
            ensure(
                codec::digest(payload.as_bytes()) == inbound.payload_digest,
                "history_conflict",
                "源端正文与接收摘要冲突",
            )?;
            Copy {
                envelope: inbound.envelope.clone(),
                payload: payload.clone(),
                acceptance_receipt: inbound.acceptance_receipt.clone().ok_or_else(|| {
                    LabError::new("history_acceptance_required", "副本缺少原始接受证明")
                })?,
            }
        } else {
            let (outbound, receipt) = outgoing
                .first()
                .ok_or_else(|| LabError::new("history_content_unavailable", "缺少选定发送副本"))?;
            Copy {
                envelope: outbound.envelope.clone(),
                payload: outbound.payload.clone(),
                acceptance_receipt: (*receipt).clone(),
            }
        };
        stored::validate_copy(state, &statement, &copy, selected)?;
        copies.push(copy);
    }
    let raw = checked(
        "history_invalid",
        serde_json::to_vec(&Body {
            protocol_version: "rim-history-copies-1".into(),
            records: copies,
        }),
    )?;
    ensure(
        raw.len() <= public::MAX_BODY,
        "resource_exhausted",
        "选定副本整体超过256KiB",
    )?;
    let aad = public::bytes(&request.statement_bytes, 16 * 1024)?;
    let key = public::bytes(&statement.recipient_key, 32)?;
    let encrypted = checked(
        "history_crypto",
        state.provider.crypto().hpke_seal(
            codec::CIPHERSUITE.hpke_config(),
            &key,
            &public::hpke_info(&request)?,
            &aad,
            &raw,
        ),
    )?;
    let package_statement = PackageStatement {
        protocol_version: "rim-history-package-1".into(),
        transfer_id: statement.transfer_id.clone(),
        request_sha256: public::request_digest(&request)?,
        ciphertext_sha256: public::ciphertext_digest(
            encrypted.kem_output.as_slice(),
            encrypted.ciphertext.as_slice(),
        ),
    };
    let signed = history_transfer::sign(state, public::PACKAGE_DOMAIN, &package_statement)?;
    let package = Package {
        statement_bytes: signed.statement_bytes,
        signature_bytes: signed.signature_bytes,
        kem_output: codec::encode(encrypted.kem_output.as_slice()),
        ciphertext: codec::encode(encrypted.ciphertext.as_slice()),
    };
    public::verify(cp, &request, &package)?;
    state.history_transfers.exports.insert(
        statement.transfer_id,
        ExportRecord {
            request: request.clone(),
            package: package.clone(),
        },
    );
    Ok(json!({"request":request,"package":package,"reused":false}))
}
