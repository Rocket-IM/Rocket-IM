//! 迁移请求、固定导出包和独立副本都属于同一设备加密快照。
use super::{
    checked, codec, ensure, permission_state,
    state::DeviceState,
    wire_types::{Envelope, Header},
    LabError, MAX_MESSAGE_BYTES,
};
use crate::{
    history_transfer::{self as public, RequestStatement},
    message_acceptance,
    permission::{receipts::SignedRecord, Identity, PermissionCheckpoint},
};
use openmls_traits::types::HpkePrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) const LIMIT: usize = 128;
#[derive(Serialize, Deserialize)]
pub(super) struct RequestRecord {
    pub request: SignedRecord,
    pub private_key: Option<HpkePrivateKey>,
    pub status: RequestStatus,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum RequestStatus {
    Pending,
    Cancelled,
    Imported,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ExportRecord {
    pub request: SignedRecord,
    pub package: public::Package,
}
#[derive(Serialize, Deserialize)]
pub(super) struct ImportRecord {
    pub package: public::Package,
    pub receipt: SignedRecord,
    pub result: Value,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Copy {
    pub envelope: Envelope,
    pub acceptance_receipt: SignedRecord,
    pub payload: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Body {
    pub protocol_version: String,
    pub records: Vec<Copy>,
}
#[derive(Serialize, Deserialize)]
pub(super) struct ArchivedCopy {
    pub copy: Copy,
    pub source: Identity,
}
#[derive(Default, Serialize, Deserialize)]
pub(super) struct HistoryState {
    pub requests: BTreeMap<String, RequestRecord>,
    pub exports: BTreeMap<String, ExportRecord>,
    pub imports: BTreeMap<String, ImportRecord>,
    pub copies: BTreeMap<String, ArchivedCopy>,
}
pub(super) fn own(state: &DeviceState) -> Identity {
    Identity {
        account_id: state.context.account.clone(),
        device_id: state.context.device.clone(),
    }
}
pub(super) fn current(state: &DeviceState) -> Result<&PermissionCheckpoint, LabError> {
    ensure(
        state.permissions.pending.is_none() && state.permissions.recovery.intent.is_none(),
        "permission_pending",
        "迁移要求先完成当前权限意图",
    )?;
    ensure(
        !state.permissions.recovery.access_removed,
        "access_removed",
        "本机访问已移除",
    )?;
    ensure(
        state.permissions.recovery.relay_receipt_key.is_some(),
        "trust_required",
        "迁移要求固定Service回执公钥",
    )?;
    let cp = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "迁移要求已验证检查点"))?;
    let group = state.group()?;
    ensure(group.is_active(), "access_removed", "本机已不在群中")?;
    permission_state::validate_current(state, cp, &group)?;
    ensure(
        cp.members.iter().any(|m| {
            m.identity() == own(state) && m.signature_key == codec::encode(&state.own_signature_key)
        }),
        "history_denied",
        "本机不属于检查点",
    )?;
    Ok(cp)
}
pub(super) fn now() -> Result<u64, LabError> {
    Ok(checked("clock_error", SystemTime::now().duration_since(UNIX_EPOCH))?.as_secs())
}
pub(super) fn live(statement: &RequestStatement) -> Result<(), LabError> {
    let now = now()?;
    ensure(
        public::decimal(&statement.issued_at_unix_secs)? <= now
            && now < public::decimal(&statement.expires_at_unix_secs)?,
        "history_expired",
        "迁移请求未生效或已到期",
    )
}
pub(super) fn validate_copy(
    state: &DeviceState,
    request: &RequestStatement,
    copy: &Copy,
    selected: &public::Selection,
) -> Result<(String, Value), LabError> {
    let raw = public::bytes(&copy.envelope.header_bytes, 16 * 1024)?;
    let payload = public::bytes(&copy.envelope.payload_bytes, 512 * 1024)?;
    let header = Header::parse(&raw)?;
    let key = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_ref()
        .ok_or_else(|| LabError::new("trust_required", "缺少Service公钥"))?;
    let acceptance = message_acceptance::verify(key, &copy.acceptance_receipt)?;
    let hash = message_acceptance::envelope_digest(&raw, &payload);
    ensure(
        copy.payload.len() <= MAX_MESSAGE_BYTES,
        "resource_exhausted",
        "单条历史正文超过64KiB",
    )?;
    ensure(
        acceptance.acceptance_id == selected.acceptance_id
            && acceptance.envelope_sha256 == selected.envelope_sha256
            && acceptance.envelope_sha256 == hash
            && acceptance.service_id == header.service_id
            && acceptance.conversation_id == header.conversation_id
            && acceptance.authorization_version == header.authorization_version
            && acceptance.crypto_state_ref == header.crypto_state_ref
            && header.service_id == request.service_id
            && header.conversation_id == request.conversation_id
            && ((header.sender.account_id == request.source.account_id
                && header.sender.device_id == request.source.device_id)
                || header.recipients.iter().any(|r| {
                    r.account_id == request.source.account_id
                        && r.device_id == request.source.device_id
                })),
        "history_context",
        "副本与原始接受证明、范围或源发送/收件身份不符",
    )?;
    Ok((
        header.logical_key()?,
        json!({"logical_message_id":header.logical_message_id,"acceptance_id":acceptance.acceptance_id,
        "payload_sha256":codec::digest_hex(&codec::digest(copy.payload.as_bytes())),"source":request.source,"provenance":"source_authenticated_copy"}),
    ))
}
