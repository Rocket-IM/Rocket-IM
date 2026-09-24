//! 密码元数据、结果与 outbox 的交叉一致性校验；不读取数据库或恢复 provider。
use super::{corrupt, model, parsed, revision, serialized, Identity, Meta, Result, Scope};

pub(super) fn validate(meta: &Meta, scope: &Scope) -> Result<()> {
    let rev = revision(&meta.revision).map_err(|_| corrupt())?;
    let encryptions = revision(&meta.encryptions).map_err(|_| corrupt())?;
    if rev != meta.results.len() as u64 || encryptions != meta.outbox.len() as u64 {
        return Err(corrupt());
    }
    let mut revisions = std::collections::BTreeSet::new();
    for result in &meta.results {
        let value = revision(&result.outcome.revision).map_err(|_| corrupt())?;
        if value == 0 || value > rev || !revisions.insert(value) {
            return Err(corrupt());
        }
        match result.outcome.kind.as_str() {
            "initialize" => {
                let identity: Identity = parsed(&serialized(&result.outcome.value)?)?;
                let current = meta.identity.as_ref().ok_or_else(corrupt)?;
                if value != 1
                    || identity.service != scope.service
                    || identity.account != scope.account
                    || identity.device != scope.device
                    || identity.identity_key != current.identity_key
                    || identity.key_package.is_empty()
                {
                    return Err(corrupt());
                }
                model::decode(&identity.key_package).map_err(|_| corrupt())?;
            }
            "create_group" => {
                if value != 2
                    || meta.conversation.is_none()
                    || result
                        .outcome
                        .value
                        .as_object()
                        .is_none_or(|v| v.len() != 1)
                    || result
                        .outcome
                        .value
                        .get("welcome")
                        .and_then(|v| v.as_str())
                        .is_none()
                {
                    return Err(corrupt());
                }
                model::decode(
                    result.outcome.value["welcome"]
                        .as_str()
                        .ok_or_else(corrupt)?,
                )
                .map_err(|_| corrupt())?;
            }
            "rebuild_add" => {
                let (_, admission) =
                    crate::crypto::engine::Engine::validate_rebuild_result(&result.outcome.value)?;
                let own = meta.identity.as_ref().ok_or_else(corrupt)?;
                if value < 3
                    || meta
                        .results
                        .iter()
                        .filter(|entry| entry.outcome.kind == "rebuild_add")
                        .count()
                        != 1
                    || admission.approver.account_id != scope.account
                    || admission.approver.device_id != scope.device
                    || admission.approver.signature_key != own.identity_key
                    || admission.checkpoint_after.service_id != scope.service
                    || Some(&admission.checkpoint_after.conversation_id)
                        != meta.conversation.as_ref()
                {
                    return Err(corrupt());
                }
            }
            "send" => {
                if value < 3
                    || !meta
                        .outbox
                        .iter()
                        .any(|entry| entry.request_id == result.request_id)
                {
                    return Err(corrupt());
                }
            }
            "receive" => {
                if value < 3
                    || !meta
                        .receipts
                        .iter()
                        .any(|entry| entry.request_id == result.request_id)
                {
                    return Err(corrupt());
                }
            }
            _ => return Err(corrupt()),
        }
    }
    if meta.identity.is_some() != meta.results.iter().any(|v| v.outcome.kind == "initialize")
        || meta.conversation.is_some()
            != meta
                .results
                .iter()
                .any(|v| v.outcome.kind == "create_group")
    {
        return Err(corrupt());
    }
    for entry in &meta.outbox {
        let result = meta
            .results
            .iter()
            .find(|v| v.request_id == entry.request_id)
            .ok_or_else(corrupt)?;
        if result.input_hash != entry.input_hash
            || result.outcome.kind != "send"
            || result.outcome.value
                != serde_json::to_value(&entry.envelope).map_err(|_| corrupt())?
            || entry.envelope.message_id != entry.message_id
            || entry.envelope.service != scope.service
            || entry.envelope.sender_account != scope.account
            || entry.envelope.sender_device != scope.device
            || Some(&entry.envelope.conversation) != meta.conversation.as_ref()
        {
            return Err(corrupt());
        }
        model::decode(&entry.envelope.ciphertext).map_err(|_| corrupt())?;
    }
    Ok(())
}
