//! 普通消息槽与原请求账本共同投影完整追加历史；拒绝不产生第二份原件或无界集合。
use super::{
    data::{Data, StoredMessage},
    types::*,
};

impl Data {
    pub(super) fn has_rejections(&self) -> bool {
        self.requests.values().any(|r| r.rejection.is_some())
    }
    pub(super) fn history_messages(&self) -> Result<Vec<StoredMessage>> {
        if !self.has_rejections() {
            return Ok(self.messages.clone());
        }
        let mut records = Vec::new();
        for record in self.requests.values() {
            let RequestState::Complete { outcome } = &record.result else {
                continue;
            };
            if outcome.cached {
                continue;
            }
            let message = match &outcome.value {
                Value::Sent { envelope } => {
                    if record.rejection.is_some() {
                        super::network::rejected_original(record)?
                    } else {
                        self.messages
                            .iter()
                            .find(|m| m.receipt.is_none() && &m.envelope == envelope)
                            .cloned()
                            .ok_or_else(|| Error::paused("store_invalid"))?
                    }
                }
                Value::Received { .. } => self
                    .messages
                    .iter()
                    .find(|m| m.receipt.as_ref() == Some(outcome))
                    .cloned()
                    .ok_or_else(|| Error::paused("store_invalid"))?,
                _ => continue,
            };
            records.push((number(&outcome.revision)?, message));
        }
        records.sort_by_key(|(revision, _)| *revision);
        Ok(records.into_iter().map(|(_, m)| m).collect())
    }
}
