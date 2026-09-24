//! 导入仅比较公开已接受后继；不推进 MLS、权限、消息、历史或同步游标。
use super::{
    consistency, consistency_state, ensure, exchange_state as stored, state::DeviceState, LabError,
};
use crate::{
    consistency_exchange::{self as public, PackageStatement},
    permission::{
        self,
        receipts::{self, Outcome as ReceiptOutcome, RecoveryRecord, SignedRecord},
        PermissionCheckpoint,
    },
};
use serde_json::Value;

fn verify(
    state: &DeviceState,
    package: &SignedRecord,
    body: &PackageStatement,
    request: &SignedRecord,
) -> Result<PermissionCheckpoint, LabError> {
    let request_body = stored::verify_request(state, request)?;
    ensure(
        body.target == stored::own(state)
            && body.source == request_body.source
            && body.target == request_body.target
            && body.service_id == request_body.service_id
            && body.conversation_id == request_body.conversation_id
            && body.challenge == request_body.challenge
            && body.request_sha256 == public::request_digest(request)?,
        "exchange_context",
        "证据未绑定本机本次来源、范围和请求",
    )?;
    let cp = stored::current(state)?;
    public::verify_signature(
        stored::member_key(cp, &body.source)?,
        public::PACKAGE_DOMAIN,
        package,
        public::PACKAGE_LIMIT,
    )?;
    ensure(
        body.predecessor.service_id == body.service_id
            && body.predecessor.conversation_id == body.conversation_id,
        "exchange_context",
        "证据前驱属于其他实例或群",
    )?;
    stored::trusted(state, &body.predecessor)?;
    accepted_successor(state, &body.predecessor, &body.record)
}

fn accepted_successor(
    state: &DeviceState,
    predecessor: &PermissionCheckpoint,
    record: &RecoveryRecord,
) -> Result<PermissionCheckpoint, LabError> {
    let key = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_deref()
        .ok_or_else(|| LabError::new("exchange_trust_required", "缺少固定Service钥"))?;
    let receipt = receipts::verify_receipt(key, record)?.0;
    ensure(
        receipt.outcome == ReceiptOutcome::Accepted,
        "exchange_invalid",
        "对照只接受accepted终态证据",
    )?;
    Ok(permission::verify(predecessor, &record.change)?.0)
}

pub(super) fn import(state: &mut DeviceState, package: SignedRecord) -> Result<Value, LabError> {
    let body = public::parse_package(&package)?;
    let mut continuing = false;
    if let Some(previous) = state.permissions.exchange.imports.get(&body.request_sha256) {
        verify(state, &package, &body, &previous.request)?;
        ensure(
            previous.package == package,
            "exchange_conflict",
            "已导入请求不接受另一份包",
        )?;
        continuing = matches!(previous.outcome, stored::Outcome::InsufficientComparison)
            && state
                .permissions
                .exchange
                .active
                .as_ref()
                .is_some_and(|active| active.request == previous.request)
            && state.permissions.consistency.challenge.as_ref() == Some(&body.challenge);
        // 只有仍属同一次检查的未完成对照可以在真实补链后重算；不消费后来新建的闸。
        if !continuing {
            return Ok(stored::result(state, previous.outcome, true));
        }
    }
    let active = state.permissions.exchange.active.clone().ok_or_else(|| {
        LabError::new("exchange_unavailable", "本机没有有效对照请求，或请求已取消")
    })?;
    let incoming = verify(state, &package, &body, &active.request)?;
    ensure(
        state.permissions.consistency.challenge.as_ref() == Some(&body.challenge),
        "exchange_challenge_required",
        "对照挑战已被消费或更换",
    )?;
    ensure(
        continuing || state.permissions.exchange.imports.len() < stored::LIMIT,
        "resource_exhausted",
        "对照导入达到128条上限",
    )?;
    let mut comparison = None;
    for record in state.permissions.recovery.records.values() {
        let key = state
            .permissions
            .recovery
            .relay_receipt_key
            .as_deref()
            .ok_or_else(|| LabError::new("exchange_trust_required", "缺少固定Service钥"))?;
        let (receipt, change) = receipts::verify_receipt(key, record)?;
        if receipt.outcome != ReceiptOutcome::Accepted
            || change.previous_authorization_version != body.predecessor.authorization_version
            || change.from_state_ref != body.predecessor.crypto_state_ref
        {
            continue;
        }
        let successor = accepted_successor(state, &body.predecessor, record)?;
        stored::trusted(state, &successor)?;
        ensure(
            state.permissions.applied.get(&change.change_id) == Some(&record.change),
            "exchange_unavailable",
            "本机对照记录尚未实际应用",
        )?;
        comparison = Some((successor, record.clone()));
        if comparison
            .as_ref()
            .is_some_and(|(successor, _)| *successor != incoming)
        {
            break;
        }
    }
    let outcome = match comparison {
        Some((successor, local)) if successor != incoming => {
            consistency::observe_fork(
                state,
                consistency_state::ForkEvidence {
                    predecessor: body.predecessor.clone(),
                    left: local,
                    right: body.record.clone(),
                },
            )?;
            stored::Outcome::ForkDetected
        }
        Some(_) => {
            state.permissions.consistency.challenge = None;
            stored::Outcome::Matched
        }
        None => stored::Outcome::InsufficientComparison,
    };
    if !matches!(outcome, stored::Outcome::InsufficientComparison) {
        state.permissions.exchange.active = None;
    }
    state.permissions.exchange.imports.insert(
        body.request_sha256,
        stored::Import {
            request: active.request,
            verification: active.verification,
            package,
            outcome,
        },
    );
    Ok(stored::result(state, outcome, false))
}
