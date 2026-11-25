//! 下载原件、接受状态和双游标只通过原SQLite显式事务保存。
use super::{
    super::{data::Data, types::*},
    types::*,
};

impl NetworkData {
    pub(super) fn new(binding: Binding) -> Self {
        Self {
            binding: Some(binding),
            processed: zero(),
            reported: zero(),
            ..Self::default()
        }
    }
    pub(in crate::persistent) fn validate(&self, data: &Data) -> Result<()> {
        super::workset::validate(data, self)?;
        let bad = || Error::paused("network_store_invalid");
        let b = self.binding.as_ref().ok_or_else(bad)?;
        b.peer.validate().map_err(|_| bad())?;
        if b.peer.scope.service != data.state.scope.service
            || b.peer.scope == data.state.scope
            || self.events.len() > super::super::metering::MAX_EVENTS
            || number(&self.reported)? > number(&self.processed)?
            || number(&self.processed)? > self.events.len() as u64
        {
            return Err(bad());
        }
        if let Some(c) = &data.state.conversation {
            if c != &b.conversation || data.state.peer.as_ref() != Some(&b.peer) {
                return Err(bad());
            }
        }
        if let Some(r) = &self.recovery {
            if let Some(round) = &r.round {
                super::recovery_validation::validate_round(data, round)?;
            }
            if r.decision
                .as_deref()
                .is_some_and(|d| !matches!(d, "approve" | "reject" | "seal"))
            {
                return Err(bad());
            }
            if let Some(q) = &r.intent {
                if Some(&q.target) != data.state.identity.as_ref()
                    || q.peer != b.peer
                    || q.conversation != b.conversation
                    || data
                        .requests
                        .get(&q.request)
                        .is_none_or(|r| r.hash != q.request_hash)
                {
                    return Err(bad());
                }
            }
        }
        if let Some(upper) = &self.upper {
            if number(upper)? < self.events.len() as u64 || number(upper)? > 512 {
                return Err(bad());
            }
        }
        for (i, event) in self.events.iter().enumerate() {
            if number(&event.sequence)? != i as u64 + 1 {
                return Err(bad());
            }
            self.validate_event(data, event)?;
            if i < number(&self.processed)? as usize
                && matches!(event.kind.as_str(), "delivered" | "unavailable")
                && self.accepted.get(&event.acceptance.message_id) != Some(&event.acceptance)
            {
                return Err(bad());
            }
            if i < number(&self.processed)? as usize
                && event.kind == "message"
                && !self.retired_events.contains(&event.sequence)
                && !data
                    .messages
                    .iter()
                    .any(|m| m.receipt.is_some() && Some(&m.envelope) == event.envelope.as_ref())
            {
                return Err(bad());
            }
        }
        let expected_delivered: std::collections::BTreeSet<_> = self
            .events
            .iter()
            .take(number(&self.processed)? as usize)
            .filter(|e| e.kind == "delivered")
            .map(|e| e.acceptance.message_id.clone())
            .collect();
        if expected_delivered != self.delivered {
            return Err(bad());
        }
        let expected_unavailable = self
            .events
            .iter()
            .take(number(&self.processed)? as usize)
            .filter(|e| e.kind == "unavailable")
            .map(|e| e.acceptance.message_id.clone())
            .collect();
        if self.unavailable != expected_unavailable
            || !self.unavailable.is_disjoint(&self.delivered)
        {
            return Err(bad());
        }
        for sequence in &self.retired_events {
            let i = number(sequence)?.checked_sub(1).ok_or_else(bad)? as usize;
            let e = self.events.get(i).ok_or_else(bad)?;
            if i >= number(&self.processed)? as usize
                || e.kind != "message"
                || e.envelope
                    .as_ref()
                    .is_none_or(|v| !super::queue::retired_context(data, &v.context))
                || data
                    .messages
                    .iter()
                    .any(|m| Some(&m.envelope) == e.envelope.as_ref())
            {
                return Err(bad());
            }
        }
        for message in &self.not_accepted {
            if self.accepted.contains_key(message) || !data.requests.values().any(|r|matches!(&r.result,RequestState::Complete{outcome} if matches!(&outcome.value,Value::Sent{envelope} if &envelope.message_id==message && super::queue::retired_context(data,&envelope.context)))) {return Err(bad());}
        }
        let mut accepted_sequences = std::collections::BTreeSet::new();
        for (message, ack) in &self.accepted {
            if !accepted_sequences.insert(&ack.sequence) {
                return Err(bad());
            }
            if &ack.message_id != message {
                return Err(bad());
            };
            validate_ack(data, ack)?;
        }
        if self
            .delivered
            .iter()
            .any(|id| !self.accepted.contains_key(id))
        {
            return Err(bad());
        }
        Ok(())
    }
    pub(super) fn validate_event(&self, data: &Data, e: &Event) -> Result<()> {
        let bad = || Error::paused("network_event_invalid");
        id(&e.acceptance.request_id)?;
        id(&e.acceptance.message_id)?;
        let seq = number(&e.acceptance.sequence)?;
        if seq == 0 || seq > 256 {
            return Err(bad());
        }
        match (&*e.kind, &e.envelope) {
            ("message", Some(envelope)) => {
                let binding = self.binding.as_ref().ok_or_else(bad)?;
                Action::Receive {
                    envelope: envelope.clone(),
                }
                .validate()?;
                if envelope.service != data.state.scope.service
                    || envelope.conversation != binding.conversation
                    || envelope.sender_account != binding.peer.scope.account
                    || envelope.sender_device != binding.peer.scope.device
                    || envelope.message_id != e.acceptance.message_id
                    || hash(&encode(envelope)?) != e.acceptance.envelope_hash
                {
                    return Err(bad());
                }
            }
            ("delivered" | "unavailable", None) => validate_ack(data, &e.acceptance)?,
            _ => return Err(bad()),
        }
        Ok(())
    }
    pub(super) fn download(&mut self, data: &Data, page: Page) -> Result<()> {
        let bad = || Error::paused("network_page_invalid");
        let before = self.events.len() as u64;
        if number(&page.after)? != before
            || number(&page.upper)? < before
            || number(&page.upper)? > 512
            || page.events.len() > 4
            || self.upper.as_ref().is_some_and(|u| u != &page.upper)
        {
            return Err(bad());
        }
        for (i, event) in page.events.iter().enumerate() {
            if number(&event.sequence)? != before + i as u64 + 1 {
                return Err(bad());
            }
            self.validate_event(data, event)?;
        }
        let next = before + page.events.len() as u64;
        if number(&page.next)? != next
            || next > number(&page.upper)?
            || (next < number(&page.upper)? && page.events.is_empty())
        {
            return Err(bad());
        }
        self.events.extend(page.events);
        self.upper = if page.next == page.upper {
            None
        } else {
            Some(page.upper)
        };
        Ok(())
    }
}
pub(super) fn validate_ack(data: &Data, ack: &Acceptance) -> Result<()> {
    let bad = || Error::paused("network_acceptance_invalid");
    let record = data.requests.get(&ack.request_id).ok_or_else(bad)?;
    if record.rejection.is_some() {
        return Err(bad());
    }
    if let RequestState::Complete { outcome } = &record.result {
        if let Value::Sent { envelope } = &outcome.value {
            if envelope.message_id == ack.message_id
                && hash(&encode(envelope)?) == ack.envelope_hash
                && (1..=256).contains(&number(&ack.sequence)?)
            {
                return Ok(());
            }
        }
    }
    Err(bad())
}
/// 密码、去重、消息和处理游标进入同一候选，最终事务一起提交。
pub(in crate::persistent) fn mark_received(data: &mut Data, envelope: &Envelope) -> Result<()> {
    if let Some(n) = &mut data.network {
        if let Some(e) = n.events.get(number(&n.processed)? as usize) {
            if e.kind == "message" && e.envelope.as_ref() == Some(envelope) {
                n.processed = e.sequence.clone();
            }
        }
    }
    Ok(())
}
/// 执行候选只允许当前精确接收推动一个处理游标；其他网络状态不能混入密码提交。
pub(in crate::persistent) fn check_candidate(
    before: &Data,
    after: &Data,
    action: &Action,
) -> Result<()> {
    let mut expected = before.clone();
    if let Action::Receive { envelope } = action {
        mark_received(&mut expected, envelope)?;
    }
    if encode(&expected.network)? != encode(&after.network)? {
        return Err(Error::paused("network_candidate_invalid"));
    }
    Ok(())
}

#[cfg(feature = "network")]
pub(super) fn bind(data: &mut Data, binding: Binding) -> Result<()> {
    match &data.network {
        Some(n) if n.binding.as_ref() != Some(&binding) => {
            Err(Error::new("network_binding_mismatch"))
        }
        Some(_) => Ok(()),
        None if data.state.conversation.is_some() => {
            Err(Error::new("network_fresh_group_required"))
        }
        None if data.state.pending_request.is_some() => Err(Error::paused("operation_pending")),
        None => {
            data.network = Some(NetworkData::new(binding));
            Ok(())
        }
    }
}
