//! 永久拒绝只来自已关联的认证 Service send 响应；原输入和原密文仍归原请求账本。
#[cfg(feature = "network")]
use super::super::data::Saved;
use super::super::{
    data::{Data, Record, StoredMessage},
    types::*,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCode {
    MessageLimit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum SendRejection {
    ServiceSend { code: RejectionCode },
}

impl SendRejection {
    /// 仅供成功完成 TLS、会话身份及 RPC id 核验的 send 错误调用。
    /// 本地容量错误、传输丢失、认证、冲突及未知执行均不进入此分类。
    #[cfg(feature = "network")]
    pub(super) fn from_service_send(error: &Error) -> Option<Self> {
        (!error.paused && error.code == "message_limit").then_some(Self::ServiceSend {
            code: RejectionCode::MessageLimit,
        })
    }
}

pub(in crate::persistent) fn original(record: &Record) -> Result<StoredMessage> {
    let bad = || Error::paused("rejection_record_invalid");
    let (Some(Action::Send { message_id, text }), RequestState::Complete { outcome }) =
        (&record.input, &record.result)
    else {
        return Err(bad());
    };
    let Value::Sent { envelope } = &outcome.value else {
        return Err(bad());
    };
    if record.action != "send" || outcome.cached || message_id != &envelope.message_id {
        return Err(bad());
    }
    Ok(StoredMessage {
        message: Message {
            service: envelope.service.clone(),
            conversation: envelope.conversation.clone(),
            sender_account: envelope.sender_account.clone(),
            sender_device: envelope.sender_device.clone(),
            message_id: message_id.clone(),
            context: envelope.context.clone(),
            text: text.clone(),
        },
        envelope: envelope.clone(),
        receipt: None,
    })
}

pub(in crate::persistent) fn validate(data: &Data, record: &Record) -> Result<()> {
    if record.rejection.is_none() {
        return Ok(());
    }
    let bad = || Error::paused("rejection_record_invalid");
    let message = original(record)?;
    let n = data.network.as_ref().ok_or_else(bad)?;
    let e = &message.envelope;
    if n.accepted.contains_key(&e.message_id)
        || n.not_accepted.contains(&e.message_id)
        || e.service != data.state.scope.service
        || e.sender_account != data.state.scope.account
        || e.sender_device != data.state.scope.device
        || Some(&e.conversation) != data.state.conversation.as_ref()
        || data.messages.iter().any(|m| {
            m.message.sender_account == e.sender_account
                && m.message.sender_device == e.sender_device
                && m.message.message_id == e.message_id
        })
    {
        return Err(bad());
    }
    Action::Receive {
        envelope: e.clone(),
    }
    .validate()
    .map_err(|_| bad())?;
    Ok(())
}

/// 与消息投影移除在同一事务内提交；不改变密码、原结果、业务修订或处理游标。
#[cfg(feature = "network")]
pub(super) fn commit(
    saved: &mut Saved,
    request: &str,
    envelope: &Envelope,
    rejection: SendRejection,
) -> Result<()> {
    let bad = || Error::paused("rejection_record_invalid");
    if saved.meta.blocks_operations()
        || super::recovery_gate(saved)
        || saved.data.state.pending_request.is_some()
    {
        return Err(Error::paused("recovery_active"));
    }
    let record = saved.data.requests.get(request).ok_or_else(bad)?;
    let original = original(record)?;
    if &original.envelope != envelope {
        return Err(bad());
    }
    let n = saved.data.network.as_ref().ok_or_else(bad)?;
    if n.accepted.contains_key(&envelope.message_id)
        || n.not_accepted.contains(&envelope.message_id)
    {
        return Err(bad());
    }
    if let Some(prior) = &record.rejection {
        return if prior == &rejection {
            validate(&saved.data, record)
        } else {
            Err(bad())
        };
    }
    let index = saved
        .data
        .messages
        .iter()
        .position(|m| m.envelope == *envelope)
        .ok_or_else(bad)?;
    if encode(&saved.data.messages[index])? != encode(&original)? {
        return Err(bad());
    }
    saved
        .data
        .requests
        .get_mut(request)
        .ok_or_else(bad)?
        .rejection = Some(rejection);
    saved.data.messages.remove(index);
    Ok(())
}
