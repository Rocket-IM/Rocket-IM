//! 最终共同提交的候选校验与 SQL；借用调用方事务，不自行提交。
#[path = "receive_persistence.rs"]
mod receive;
use crate::{
    crypto::{
        contract::{Action, Candidate, Fault, Outcome, Request, Reservation, Scope},
        model::{self, Envelope},
        query::{self, Meta},
        schema::corrupt,
    },
    model::{revision, Error, Result},
};
use rusqlite::{params, Transaction};

pub(in crate::crypto) fn input_hash(request: &Request) -> Result<String> {
    Ok(model::hash(query::serialized(&request.action)?.as_bytes()))
}

pub(super) fn check_reservation(
    tx: &Transaction<'_>,
    scope: &Scope,
    reservation: &Reservation,
) -> Result<Meta> {
    if query::pending(tx)?.as_ref() != Some(reservation) {
        return Err(corrupt());
    }
    let meta = query::load(tx, scope)?;
    if meta.revision != reservation.base_revision
        || meta.provider_hash != reservation.base_provider_hash
    {
        return Err(corrupt());
    }
    Ok(meta)
}

pub(super) fn validate_candidate(
    meta: &Meta,
    scope: &Scope,
    request: &Request,
    reservation: &Reservation,
    candidate: &Candidate,
) -> Result<()> {
    let next = revision(&meta.revision)?
        .checked_add(1)
        .ok_or_else(corrupt)?
        .to_string();
    if request.request_id != reservation.request_id
        || request.action.operation() != reservation.operation
        || input_hash(request)? != reservation.input_hash
        || candidate.provider.is_empty()
        || candidate.provider.len() > query::PROVIDER_LIMIT
        || candidate.outcome.cached
        || candidate.outcome.revision != next
        || candidate.outcome.kind != request.action.operation()
        || candidate.identity.service != scope.service
        || candidate.identity.account != scope.account
        || candidate.identity.device != scope.device
        || model::decode(&candidate.identity.identity_key)?.len() != 32
    {
        return Err(corrupt());
    }
    let count = revision(&meta.encryptions)?;
    let expected_count = if matches!(request.action, Action::Send { .. }) {
        count.checked_add(1).ok_or_else(corrupt)?
    } else {
        count
    };
    if candidate.encryptions != expected_count.to_string()
        || (!matches!(request.action, Action::Receive { .. })
            && (candidate.processed_cursor != meta.processed_cursor
                || candidate.decryptions != meta.decryptions))
    {
        return Err(corrupt());
    }
    if let Some(before) = &meta.identity {
        if candidate.identity.identity_key != before.identity_key {
            return Err(corrupt());
        }
    }
    match &request.action {
        Action::Initialize {} => {
            if meta.identity.is_some()
                || candidate.conversation.is_some()
                || candidate.identity.key_package.is_empty()
                || candidate.outcome.value
                    != serde_json::to_value(&candidate.identity).map_err(|_| corrupt())?
            {
                return Err(corrupt());
            }
            model::decode(&candidate.identity.key_package)?;
        }
        Action::CreateGroup { conversation, .. } => {
            if meta.identity.is_none()
                || meta.conversation.is_some()
                || candidate.conversation.as_ref() != Some(conversation)
                || !candidate.identity.key_package.is_empty()
                || candidate
                    .outcome
                    .value
                    .as_object()
                    .is_none_or(|v| v.len() != 1)
            {
                return Err(corrupt());
            }
            model::decode(
                candidate
                    .outcome
                    .value
                    .get("welcome")
                    .and_then(|v| v.as_str())
                    .ok_or_else(corrupt)?,
            )?;
        }
        Action::RebuildAdd { plan, peer } => {
            let (approved, admission) =
                crate::crypto::engine::Engine::validate_rebuild_result(&candidate.outcome.value)?;
            if meta.conversation.is_none()
                || candidate.conversation != meta.conversation
                || candidate.identity != *meta.identity.as_ref().ok_or_else(corrupt)?
                || !candidate.identity.key_package.is_empty()
                || serde_json::to_value(&approved).map_err(|_| corrupt())? != *plan
                || admission.successor_identity != *peer
                || admission.approver.account_id != scope.account
                || admission.approver.device_id != scope.device
                || admission.approver.signature_key != candidate.identity.identity_key
                || Some(&admission.checkpoint_after.conversation_id) != meta.conversation.as_ref()
            {
                return Err(corrupt());
            }
        }
        Action::Send { message_id, .. } => {
            if meta.conversation.is_none()
                || candidate.conversation != meta.conversation
                || !candidate.identity.key_package.is_empty()
            {
                return Err(corrupt());
            }
            let envelope: Envelope = query::parsed(&query::serialized(&candidate.outcome.value)?)?;
            if envelope.service != scope.service
                || envelope.sender_account != scope.account
                || envelope.sender_device != scope.device
                || Some(&envelope.conversation) != meta.conversation.as_ref()
                || &envelope.message_id != message_id
            {
                return Err(corrupt());
            }
            model::decode(&envelope.ciphertext)?;
        }
        Action::Receive { .. } => {
            receive::validate(meta, request, candidate)?;
        }
    }
    Ok(())
}

pub(crate) fn save(
    tx: &Transaction<'_>,
    scope: &Scope,
    request: &Request,
    reservation: &Reservation,
    candidate: Candidate,
) -> Result<Outcome> {
    let meta = check_reservation(tx, scope, reservation)?;
    // 核对 BLOB 的实际摘要，不把保存的摘要字段当成密码状态本身。
    let previous_provider = query::provider(tx, &meta)?;
    validate_candidate(&meta, scope, request, reservation, &candidate)?;
    let provider_hash = model::hash(&candidate.provider);
    let duplicate = if matches!(request.action, Action::Receive { .. }) {
        receive::validate(&meta, request, &candidate)?
    } else {
        false
    };
    if duplicate {
        if previous_provider.as_deref() != Some(candidate.provider.as_slice()) {
            return Err(corrupt());
        }
    } else if provider_hash == meta.provider_hash {
        return Err(corrupt());
    }
    if let Action::Receive { sequence, envelope } = &request.action {
        super::download::save_receive(tx, &meta, sequence, envelope)?;
    }
    let changed=tx.execute("UPDATE crypto_meta SET revision=?1,identity_json=?2,conversation=?3,provider=?4,provider_hash=?5,encryptions=?6,processed_cursor=?7,decryptions=?8 WHERE singleton=1 AND revision=?9 AND provider_hash=?10",params![candidate.outcome.revision,query::serialized(&candidate.identity)?,candidate.conversation,candidate.provider,provider_hash,candidate.encryptions,candidate.processed_cursor,candidate.decryptions,reservation.base_revision,reservation.base_provider_hash]).map_err(Error::database)?;
    if changed != 1 {
        return Err(corrupt());
    }
    if request.fault == Fault::AfterSql {
        tx.execute(
            "INSERT INTO crypto_intentionally_missing_table(value) VALUES(1)",
            [],
        )
        .map_err(Error::database)?;
        return Err(corrupt());
    }
    tx.execute(
        "INSERT INTO crypto_results(request_id,input_hash,kind,outcome_json) VALUES(?1,?2,?3,?4)",
        params![
            request.request_id,
            reservation.input_hash,
            candidate.outcome.kind,
            query::serialized(&candidate.outcome)?
        ],
    )
    .map_err(Error::database)?;
    if let Action::Send {
        attempt_id,
        message_id,
        ..
    } = &request.action
    {
        tx.execute("INSERT INTO crypto_outbox(attempt_id,message_id,request_id,input_hash,envelope_json) VALUES(?1,?2,?3,?4,?5)",params![attempt_id,message_id,request.request_id,reservation.input_hash,query::serialized(&candidate.outcome.value)?]).map_err(Error::database)?;
    }
    if matches!(request.action, Action::Receive { .. }) {
        receive::save(tx, request, reservation, &candidate)?;
    }
    if tx
        .execute("DELETE FROM crypto_pending WHERE singleton=1", [])
        .map_err(Error::database)?
        != 1
    {
        return Err(corrupt());
    }
    let after = query::load(tx, scope)?;
    query::provider(tx, &after)?;
    Ok(candidate.outcome)
}
