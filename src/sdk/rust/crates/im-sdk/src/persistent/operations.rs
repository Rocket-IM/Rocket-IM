use super::{
    data::{action_name, Record, Saved},
    types::*,
};
pub(super) enum Preparation {
    Cached(Box<Outcome>),
    Ready(Box<Saved>),
}
pub(super) fn fingerprint(s: &Saved) -> Result<String> {
    Ok(hash(
        &[encode(&s.data)?, s.crypto.clone(), encode(&s.meta)?].concat(),
    ))
}
pub(super) fn prepare(s: &mut Saved, request_id: &str, action: &Action) -> Result<Preparation> {
    let digest = hash(&encode(action)?);
    if let Some(r) = s.data.requests.get(request_id) {
        if !matches_input(&r.hash, action)? {
            return Err(Error::new("request_conflict"));
        }
        return match &r.result {
            RequestState::Complete { outcome } => {
                let mut o = outcome.clone();
                o.cached = true;
                Ok(Preparation::Cached(Box::new(o)))
            }
            RequestState::Failed { error } => Err(error.clone()),
            RequestState::Retired { .. } => Err(Error::new("request_retired")),
            _ => Err(Error::paused("operation_pending")),
        };
    }
    if s.meta.blocks_operations() {
        return Err(Error::paused("recovery_active"));
    }
    if super::network::recovery_gate(s) {
        return Err(Error::paused("recovery_active"));
    }
    if s.data.state.pending_request.is_some() {
        return Err(Error::paused("operation_pending"));
    }
    if s.data.requests.len() >= 1024 {
        return Err(Error::new("request_limit"));
    }
    // 在密码处理前预留有界结果空间；容量拒绝不能留下不可恢复的密码预约。
    let growth = encode(action)?.len().saturating_mul(6).max(1024 * 1024);
    if encode(&s.data)?.len().saturating_add(growth) > super::data::MAX_DATA {
        return Err(Error::new("storage_limit"));
    }
    if encode(&s.meta)?
        .len()
        .saturating_add(encode(&s.data)?.len())
        .saturating_add(s.crypto.len())
        .saturating_add(growth)
        > super::store::MAX_META
    {
        return Err(Error::new("storage_limit"));
    }
    let st = &s.data.state;
    let initialized = st.identity.is_some();
    match action {
        Action::Initialize if initialized => return Err(Error::new("already_initialized")),
        Action::Initialize => {}
        _ if !initialized => return Err(Error::new("initialize_required")),
        Action::CreateGroup { peer, .. } | Action::JoinGroup { peer, .. } => {
            if st.conversation.is_some() {
                return Err(Error::new("already_grouped"));
            }
            if peer.scope.service != st.scope.service
                || peer.scope == st.scope
                || Some(&peer.identity_key) == st.identity.as_ref().map(|i| &i.identity_key)
            {
                return Err(Error::new("identity_mismatch"));
            }
        }
        Action::Send { message_id, .. } => {
            if s.data.requests.values().any(|r| r.rejection.is_some()
                && matches!(&r.input, Some(Action::Send { message_id: old, .. }) if old == message_id)) {
                return Err(Error::new("message_conflict"));
            }
            if s.data.requests.values().any(|r| matches!((&r.result,&r.input), (RequestState::Retired {..},Some(Action::Send {message_id:old,..})) if old == message_id)) { return Err(Error::new("message_conflict")); }
            if st.conversation.is_none() {
                return Err(Error::new("group_required"));
            }
            if s.data.messages.iter().any(|m| {
                m.message.sender_account == st.scope.account
                    && m.message.sender_device == st.scope.device
                    && &m.message.message_id == message_id
            }) {
                return Err(Error::new("message_conflict"));
            }
        }
        Action::Receive { envelope: e } => {
            let peer = st
                .peer
                .as_ref()
                .ok_or_else(|| Error::new("group_required"))?;
            if e.context != st.context {
                return Err(Error::new("context_retired"));
            }
            if e.service != st.scope.service
                || Some(&e.conversation) != st.conversation.as_ref()
                || e.sender_account != peer.scope.account
                || e.sender_device != peer.scope.device
            {
                return Err(Error::new("scope_mismatch"));
            }
            if let Some(m) = s.data.messages.iter().find(|m| {
                (
                    &m.message.sender_account,
                    &m.message.sender_device,
                    &m.message.message_id,
                ) == (&e.sender_account, &e.sender_device, &e.message_id)
            }) {
                if &m.envelope != e {
                    return Err(Error::new("message_conflict"));
                }
                let mut outcome = m
                    .receipt
                    .clone()
                    .ok_or_else(|| Error::paused("store_invalid"))?;
                outcome.cached = true;
                s.data.requests.insert(
                    request_id.into(),
                    Record {
                        rejection: None,
                        hash: digest,
                        input: Some(action.clone()),
                        action: action_name(action).into(),
                        result: RequestState::Complete {
                            outcome: outcome.clone(),
                        },
                    },
                );
                return Ok(Preparation::Cached(Box::new(outcome)));
            }
            // 同一原密文不允许改写 message_id 作为新消息，必须在密码处理前拒绝。
            if s.data
                .messages
                .iter()
                .any(|m| m.envelope.ciphertext == e.ciphertext)
            {
                return Err(Error::new("message_conflict"));
            }
        }
    }
    if matches!(action, Action::Send { .. } | Action::Receive { .. })
        && s.data.messages.len() >= 256
    {
        return Err(Error::new("message_limit"));
    }
    s.data.requests.insert(
        request_id.into(),
        Record {
            rejection: None,
            hash: digest,
            input: Some(action.clone()),
            action: action_name(action).into(),
            result: RequestState::Pending,
        },
    );
    s.data.state.pending_request = Some(request_id.into());
    Ok(Preparation::Ready(Box::new(s.clone())))
}

pub(super) fn matches_input(expected: &str, action: &Action) -> Result<bool> {
    if expected == hash(&encode(action)?) {
        return Ok(true);
    }
    if let Action::Receive { envelope } = action {
        if envelope.context == "initial" {
            #[derive(serde::Serialize)]
            struct OldEnvelope<'a> {
                service: &'a str,
                conversation: &'a str,
                sender_account: &'a str,
                sender_device: &'a str,
                message_id: &'a str,
                ciphertext: &'a str,
            }
            #[derive(serde::Serialize)]
            struct OldAction<'a> {
                kind: &'static str,
                envelope: OldEnvelope<'a>,
            }
            let e = envelope;
            let old = OldAction {
                kind: "receive",
                envelope: OldEnvelope {
                    service: &e.service,
                    conversation: &e.conversation,
                    sender_account: &e.sender_account,
                    sender_device: &e.sender_device,
                    message_id: &e.message_id,
                    ciphertext: &e.ciphertext,
                },
            };
            return Ok(expected == hash(&encode(&old)?));
        }
    }
    Ok(false)
}
