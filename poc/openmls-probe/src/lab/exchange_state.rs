//! 对照来源、请求及完整公开证据同快照保存；每次重试先检查当前身份。
use super::{
    checked, codec, consistency_state, ensure, permission_state, state::DeviceState, LabError,
};
use crate::{
    consistency_exchange::{self as public, RequestStatement, Verification},
    permission::{receipts::SignedRecord, Identity, PermissionCheckpoint},
};
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) const LIMIT: usize = 128;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Active {
    pub request: SignedRecord,
    pub verification: Verification,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Export {
    pub request: SignedRecord,
    pub change_id: String,
    pub package: SignedRecord,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Matched,
    ForkDetected,
    InsufficientComparison,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Import {
    pub request: SignedRecord,
    pub verification: Verification,
    pub package: SignedRecord,
    pub outcome: Outcome,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct ExchangeState {
    pub active: Option<Active>,
    pub exports: BTreeMap<String, Export>,
    pub imports: BTreeMap<String, Import>,
}

pub(super) fn own(state: &DeviceState) -> Identity {
    Identity {
        account_id: state.context.account.clone(),
        device_id: state.context.device.clone(),
    }
}

pub(super) fn current(state: &DeviceState) -> Result<&PermissionCheckpoint, LabError> {
    ensure(
        !state.permissions.recovery.access_removed,
        "access_removed",
        "本机访问已经撤销",
    )?;
    ensure(
        state.permissions.pending.is_none() && state.permissions.recovery.intent.is_none(),
        "permission_pending",
        "本机权限变更尚未完成",
    )?;
    let cp = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("exchange_trust_required", "缺少本机可信检查点"))?;
    ensure(
        state.permissions.recovery.relay_receipt_key.is_some(),
        "exchange_trust_required",
        "缺少初始固定的 Service 回执钥",
    )?;
    permission_state::validate_current(state, cp, &state.group()?)?;
    trusted(state, cp)?;
    ensure(
        member_key(cp, &own(state))? == codec::encode(&state.own_signature_key),
        "exchange_key_changed",
        "本机身份钥与当前可信成员不同",
    )?;
    Ok(cp)
}

pub(super) fn trusted(state: &DeviceState, cp: &PermissionCheckpoint) -> Result<(), LabError> {
    ensure(
        state
            .permissions
            .consistency
            .checkpoints
            .get(&consistency_state::version(cp)?)
            == Some(cp),
        "consistency_coverage",
        "缺少实际 MLS 核验过的完整前驱",
    )
}

pub(super) fn member_key<'a>(
    cp: &'a PermissionCheckpoint,
    identity: &Identity,
) -> Result<&'a str, LabError> {
    cp.members
        .iter()
        .find(|m| m.identity() == *identity)
        .map(|m| m.signature_key.as_str())
        .ok_or_else(|| LabError::new("exchange_trust_required", "对照设备不在本机当前可信成员中"))
}

pub(super) fn verify_request(
    state: &DeviceState,
    signed: &SignedRecord,
) -> Result<RequestStatement, LabError> {
    let request = public::parse_request(signed)?;
    let cp = current(state)?;
    ensure(
        request.service_id == cp.service_id && request.conversation_id == cp.conversation_id,
        "exchange_context",
        "对照请求属于其他实例或群",
    )?;
    let source = member_key(cp, &request.source)?;
    let target = member_key(cp, &request.target)?;
    ensure(
        public::fingerprint(source)? == request.source_fingerprint
            && public::fingerprint(target)? == request.target_fingerprint,
        "exchange_key_changed",
        "对照身份的当前公钥与本次核验指纹不同",
    )?;
    public::verify_signature(
        target,
        public::REQUEST_DOMAIN,
        signed,
        public::REQUEST_LIMIT,
    )?;
    Ok(request)
}

pub(super) fn sign<T: Serialize>(
    state: &DeviceState,
    domain: &[u8],
    statement: &T,
) -> Result<SignedRecord, LabError> {
    let raw = checked("exchange_invalid", serde_json::to_vec(statement))?;
    let mut message = domain.to_vec();
    message.extend(&raw);
    Ok(SignedRecord {
        statement_bytes: codec::encode(&raw),
        signature_bytes: codec::encode(
            &state
                .signer()?
                .sign(&message)
                .map_err(|_| LabError::new("exchange_signature", "对照签名失败"))?,
        ),
    })
}

pub(super) fn result(state: &DeviceState, outcome: Outcome, duplicate: bool) -> Value {
    json!({"outcome":outcome,"duplicate":duplicate,"consistency":consistency_state::inspect(state)})
}

pub(super) fn inspect(state: &DeviceState) -> Result<Value, LabError> {
    let stored = &state.permissions.exchange;
    let active = stored
        .active
        .as_ref()
        .map(|active| {
            let r = public::parse_request(&active.request)?;
            Ok::<_, LabError>(
                json!({"source":r.source,"target":r.target,"verification":active.verification,
            "source_fingerprint":r.source_fingerprint,"target_fingerprint":r.target_fingerprint,
            "challenge":r.challenge,"request_sha256":public::request_digest(&active.request)?}),
            )
        })
        .transpose()?;
    let imports: Vec<_> = stored.imports.iter().map(|(digest, record)| json!({"request_sha256":digest,"verification":record.verification,"outcome":record.outcome})).collect();
    Ok(
        json!({"active":active,"export_count":stored.exports.len(),"import_count":stored.imports.len(),"imports":imports,
        "freshness":"unknown","consistency":consistency_state::inspect(state)}),
    )
}
