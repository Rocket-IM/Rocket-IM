//! 目标端请求及本地取消；临时HPKE私钥不离开目标的加密快照。
use super::{
    checked, codec, ensure,
    history_state::{self as stored, RequestRecord, RequestStatus, LIMIT},
    state::DeviceState,
    LabError,
};
use crate::{
    history_transfer::{self as public, RequestStatement, Selection},
    permission::{receipts::SignedRecord, Identity},
};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, OpenMlsProvider};
use serde::Serialize;
use serde_json::{json, Value};

pub(super) fn sign<T: Serialize>(
    state: &DeviceState,
    domain: &[u8],
    statement: &T,
) -> Result<SignedRecord, LabError> {
    let raw = checked("history_invalid", serde_json::to_vec(statement))?;
    let mut signed = domain.to_vec();
    signed.extend(&raw);
    Ok(SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(
            &state
                .signer()?
                .sign(&signed)
                .map_err(|_| LabError::new("history_signature", "迁移签名失败"))?,
        ),
    })
}
pub(super) fn request(
    state: &mut DeviceState,
    transfer_id: String,
    source: Identity,
    selection: Vec<Selection>,
    validity: Option<u16>,
) -> Result<Value, LabError> {
    let cp = stored::current(state)?;
    super::wire_types::id(&transfer_id)?;
    public::validate_selection(&selection)?;
    ensure(
        selection
            .iter()
            .all(|s| super::wire_reclaimed::acceptance(state, &s.acceptance_id).is_none()),
        "history_content_unavailable",
        "已回收内容不能新建迁移请求",
    )?;
    ensure(
        validity.is_none_or(|s| (1..=300).contains(&s)),
        "history_invalid",
        "有效期只能为1到300秒",
    )?;
    if let Some(saved) = state.history_transfers.requests.get(&transfer_id) {
        ensure(
            saved.status != RequestStatus::Cancelled,
            "history_cancelled",
            "迁移请求已取消，不能重用标识",
        )?;
        let statement = public::verify_request(cp, &saved.request)?;
        stored::live(&statement)?;
        ensure(
            statement.source == source
                && statement.selection == selection
                && validity.is_none_or(|s| {
                    public::decimal(&statement.expires_at_unix_secs)
                        .ok()
                        .zip(public::decimal(&statement.issued_at_unix_secs).ok())
                        .is_some_and(|(e, i)| e - i == u64::from(s))
                }),
            "history_conflict",
            "迁移标识对应其他选择或请求",
        )?;
        return Ok(json!({"request":saved.request,"reused":true}));
    }
    ensure(
        state.history_transfers.requests.len() + state.history_transfers.exports.len() < LIMIT,
        "resource_exhausted",
        "迁移记录达到128条上限",
    )?;
    let issued = stored::now()?;
    let expires = issued
        .checked_add(u64::from(validity.unwrap_or(300)))
        .ok_or_else(|| LabError::new("history_invalid", "期限溢出"))?;
    let mut seed = [0u8; 32];
    let mut nonce = [0u8; 32];
    checked("randomness", getrandom::getrandom(&mut seed))?;
    checked("randomness", getrandom::getrandom(&mut nonce))?;
    let pair = checked(
        "history_crypto",
        state
            .provider
            .crypto()
            .derive_hpke_keypair(codec::CIPHERSUITE.hpke_config(), &seed),
    )?;
    seed.fill(0);
    let statement = RequestStatement {
        protocol_version: "rim-history-request-1".into(),
        transfer_id: transfer_id.clone(),
        service_id: cp.service_id.clone(),
        conversation_id: cp.conversation_id.clone(),
        source,
        target: stored::own(state),
        authorization_version: cp.authorization_version.clone(),
        crypto_state_ref: cp.crypto_state_ref.clone(),
        recipient_key: codec::encode(&pair.public),
        selection,
        nonce: codec::digest_hex(&nonce),
        issued_at_unix_secs: issued.to_string(),
        expires_at_unix_secs: expires.to_string(),
    };
    let request = sign(state, public::REQUEST_DOMAIN, &statement)?;
    public::verify_request(cp, &request)?;
    state.history_transfers.requests.insert(
        transfer_id,
        RequestRecord {
            request: request.clone(),
            private_key: Some(pair.private),
            status: RequestStatus::Pending,
        },
    );
    Ok(json!({"request":request,"reused":false}))
}
pub(super) fn cancel(state: &mut DeviceState, transfer_id: String) -> Result<Value, LabError> {
    super::wire_types::id(&transfer_id)?;
    let record = state
        .history_transfers
        .requests
        .get_mut(&transfer_id)
        .ok_or_else(|| LabError::new("history_unavailable", "本机没有此迁移请求"))?;
    ensure(
        record.status != RequestStatus::Imported,
        "history_conflict",
        "已导入请求不能取消",
    )?;
    let duplicate = record.status == RequestStatus::Cancelled;
    record.private_key = None;
    record.status = RequestStatus::Cancelled;
    Ok(json!({"transfer_id":transfer_id,"status":"cancelled","duplicate":duplicate}))
}
pub(super) fn inspect(state: &DeviceState) -> Result<Value, LabError> {
    let mut exportable = Vec::new();
    for record in state.wire.inbox.values() {
        if record.payload.is_some() && record.acceptance_receipt.is_some() {
            if let Some(id) = &record.acceptance_id {
                let raw = codec::decode(&record.envelope.header_bytes)?;
                let payload = codec::decode(&record.envelope.payload_bytes)?;
                exportable.push(public::Selection {
                    acceptance_id: id.clone(),
                    envelope_sha256: crate::message_acceptance::envelope_digest(&raw, &payload),
                });
            }
        }
    }
    for record in state.wire.outbox.values() {
        if let Some(receipt) = &record.acceptance_receipt {
            let pin = state
                .permissions
                .recovery
                .relay_receipt_key
                .as_ref()
                .ok_or_else(|| LabError::new("trust_required", "缺少Service公钥"))?;
            let fact = crate::message_acceptance::verify(pin, receipt)?;
            exportable.push(public::Selection {
                acceptance_id: fact.acceptance_id,
                envelope_sha256: fact.envelope_sha256,
            });
        }
    }
    exportable.sort_by(|a, b| a.acceptance_id.cmp(&b.acceptance_id));
    let requests: Vec<_> = state
        .history_transfers
        .requests
        .iter()
        .map(|(id, r)| json!({"transfer_id":id,"status":r.status}))
        .collect();
    let mut copies = Vec::new();
    for archived in state.history_transfers.copies.values() {
        let header = super::wire_types::Header::parse(&codec::decode(
            &archived.copy.envelope.header_bytes,
        )?)?;
        let receipt: crate::message_acceptance::MessageAcceptanceStatement = checked(
            "history_invalid",
            serde_json::from_slice(&codec::decode(
                &archived.copy.acceptance_receipt.statement_bytes,
            )?),
        )?;
        copies.push(json!({"logical_message_id":header.logical_message_id,"acceptance_id":receipt.acceptance_id,
            "payload_sha256":codec::digest_hex(&codec::digest(archived.copy.payload.as_bytes())),"source":archived.source,"provenance":"source_authenticated_copy"}));
    }
    Ok(
        json!({"exportable":exportable,"missing_content_count":state.wire.inbox.values().filter(|r|r.payload.is_none()).count(),
        "missing_receipt_count":state.wire.inbox.values().filter(|r|r.acceptance_receipt.is_none()).count(),
        "sent_without_acceptance_count":state.wire.outbox.values().filter(|r|r.acceptance_receipt.is_none()).count(),
        "requests":requests,"export_count":state.history_transfers.exports.len(),"imported_count":copies.len(),"copies":copies}),
    )
}
