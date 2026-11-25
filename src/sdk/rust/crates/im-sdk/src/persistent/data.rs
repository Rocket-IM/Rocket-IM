//! 有界开发库账本。有效状态、请求原摘要、消息与快照一同保存；不清理幂等记录。
use super::{
    metering::{MAX_CRYPTO, MAX_MESSAGES, MAX_REQUESTS, MAX_ROUNDS},
    types::*,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const MAX_DATA: usize = 16 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub hash: String,
    #[serde(default)]
    pub input: Option<Action>,
    pub action: String,
    pub result: RequestState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<super::network::SendRejection>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredMessage {
    pub message: Message,
    pub envelope: Envelope,
    pub receipt: Option<Outcome>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Data {
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<super::network::NetworkData>,
    pub requests: BTreeMap<String, Record>,
    pub messages: Vec<StoredMessage>,
    #[serde(default)]
    pub transitions: Vec<Transition>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Transition {
    pub context: String,
    pub revision: String,
}
#[derive(Clone)]
pub(super) struct Saved {
    pub data: Data,
    pub crypto: Vec<u8>,
    pub meta: super::recovery_types::Meta,
}
impl Data {
    pub fn has_workset(&self) -> bool {
        self.network.as_ref().is_some_and(|n| n.workset.is_some())
    }
    pub fn empty(scope: Scope) -> Self {
        Self {
            state: State {
                scope,
                revision: "0".into(),
                context: initial_context(),
                identity: None,
                conversation: None,
                peer: None,
                received_count: "0".into(),
                pending_request: None,
            },
            network: None,
            requests: BTreeMap::new(),
            messages: Vec::new(),
            transitions: Vec::new(),
        }
    }
    pub fn validate(&self, crypto: &[u8]) -> Result<()> {
        let bad = || Error::paused("store_invalid");
        if let Some(network) = &self.network {
            network.validate(self)?;
        }
        self.state.scope.validate().map_err(|_| bad())?;
        let rev = number(&self.state.revision)?;
        if self.requests.len() > MAX_REQUESTS
            || self.messages.len() > MAX_MESSAGES
            || crypto.len() > MAX_CRYPTO
        {
            return Err(bad());
        }
        if (rev == 0) != self.state.identity.is_none() || (rev == 0) != crypto.is_empty() {
            return Err(bad());
        }
        if let Some(own) = &self.state.identity {
            own.validate().map_err(|_| bad())?;
            if own.scope != self.state.scope {
                return Err(bad());
            }
        }
        let pending: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, r)| matches!(r.result, RequestState::Pending))
            .map(|(k, _)| k.clone())
            .collect();
        if pending
            != self
                .state
                .pending_request
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        {
            return Err(bad());
        }
        let mut revisions = BTreeMap::new();
        let mut init = 0;
        let mut group = 0;
        let mut sends = 0;
        let mut rejected = 0;
        let mut receives = 0;
        for (key, r) in &self.requests {
            super::network::validate_rejection(self, r)?;
            rejected += usize::from(r.rejection.is_some());
            id(key).map_err(|_| bad())?;
            if let Some(input) = &r.input {
                input.validate().map_err(|_| bad())?;
                if !super::operations::matches_input(&r.hash, input)?
                    || action_name(input) != r.action
                {
                    return Err(bad());
                }
            }
            if let RequestState::Retired { context } = &r.result {
                if !self.transitions.iter().any(|t| &t.context == context) {
                    return Err(bad());
                }
            }
            if unhex(&r.hash, 32).map_err(|_| bad())?.len() != 32 {
                return Err(bad());
            }
            if let RequestState::Complete { outcome: o } = &r.result {
                let n = number(&o.revision)?;
                if n == 0 || n > rev {
                    return Err(bad());
                }
                if o.cached {
                    continue;
                }
                if revisions.insert(n, ()).is_some() {
                    return Err(bad());
                }
                match (&*r.action, &o.value) {
                    ("initialize", Value::Initialized { identity })
                        if n == 1 && Some(identity) == self.state.identity.as_ref() =>
                    {
                        init += 1
                    }
                    ("create_group", Value::Created { welcome })
                        if n == 2 && !welcome.is_empty() =>
                    {
                        group += 1
                    }
                    ("join_group", Value::Joined) if n == 2 => group += 1,
                    ("send", Value::Sent { envelope })
                        if r.rejection.is_some()
                            || self
                                .messages
                                .iter()
                                .any(|m| m.receipt.is_none() && &m.envelope == envelope) =>
                    {
                        sends += 1
                    }
                    ("receive", Value::Received { message, .. })
                        if self
                            .messages
                            .iter()
                            .any(|m| &m.message == message && m.receipt.as_ref() == Some(o)) =>
                    {
                        receives += 1
                    }
                    _ => return Err(bad()),
                }
            }
        }
        for t in &self.transitions {
            let n = number(&t.revision)?;
            if n == 0 || n > rev || revisions.insert(n, ()).is_some() || t.context.len() != 64 {
                return Err(bad());
            }
        }
        if self.transitions.len() > MAX_ROUNDS
            || self.state.context
                != self
                    .transitions
                    .last()
                    .map_or_else(initial_context, |t| t.context.clone())
        {
            return Err(bad());
        }
        if revisions.len() as u64 != rev
            || init != usize::from(rev > 0)
            || (self.transitions.is_empty()
                && group != usize::from(self.state.conversation.is_some()))
            || group > 1
            || self.state.conversation.is_some() != self.state.peer.is_some()
            || sends + receives != self.messages.len() + rejected
            || receives as u64 != number(&self.state.received_count)?
        {
            return Err(bad());
        }
        if let Some(peer) = &self.state.peer {
            peer.validate().map_err(|_| bad())?;
            if peer.scope.service != self.state.scope.service || peer.scope == self.state.scope {
                return Err(bad());
            }
        }
        let mut keys = std::collections::BTreeSet::new();
        let mut positions = std::collections::BTreeSet::new();
        for m in &self.history_messages()? {
            Action::Receive {
                envelope: m.envelope.clone(),
            }
            .validate()
            .map_err(|_| bad())?;
            if !keys.insert((
                &m.message.sender_account,
                &m.message.sender_device,
                &m.message.message_id,
            )) || m.message.service != self.state.scope.service
                || Some(&m.message.conversation) != self.state.conversation.as_ref()
                || m.message.text.is_empty()
                || m.message.text.len() > 32768
                || !same_header(&m.message, &m.envelope)
            {
                return Err(bad());
            }
            let sender = if let Some(receipt) = &m.receipt {
                let Value::Received { message, position } = &receipt.value else {
                    return Err(bad());
                };
                if message != &m.message || !positions.insert(number(position)?) {
                    return Err(bad());
                }
                &self.state.peer.as_ref().ok_or_else(bad)?.scope
            } else {
                &self.state.scope
            };
            if (
                m.message.sender_account.as_str(),
                m.message.sender_device.as_str(),
            ) != (sender.account.as_str(), sender.device.as_str())
            {
                return Err(bad());
            }
        }
        if positions.iter().copied().ne(1..=receives as u64) {
            return Err(bad());
        }
        Ok(())
    }
}
pub(super) fn same_header(m: &Message, e: &Envelope) -> bool {
    (
        &m.service,
        &m.conversation,
        &m.sender_account,
        &m.sender_device,
        &m.message_id,
        &m.context,
    ) == (
        &e.service,
        &e.conversation,
        &e.sender_account,
        &e.sender_device,
        &e.message_id,
        &e.context,
    )
}
pub(super) fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Initialize => "initialize",
        Action::CreateGroup { .. } => "create_group",
        Action::JoinGroup { .. } => "join_group",
        Action::Send { .. } => "send",
        Action::Receive { .. } => "receive",
    }
}
