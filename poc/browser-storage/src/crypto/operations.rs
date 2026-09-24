//! 只处理一次候选密码状态；出错的候选必须丢弃，持久预约由存储层保留。

use super::{
    engine::Engine,
    model::{decode, hash},
    query::{self, Event, Message, Outbound, State, LIMIT},
    requests::Action,
};
use crate::protocol::{parse_revision, ApiError, Scope};

pub(super) fn next(value: &str) -> Result<String, ApiError> {
    parse_revision(value)?
        .checked_add(1)
        .map(|value| value.to_string())
        .ok_or_else(|| ApiError::new("crypto_limit", "密码实验计数已耗尽。", false))
}

fn reject(code: &'static str, message: &'static str) -> ApiError {
    ApiError::new(code, message, false)
}

/// 幂等、范围与容量预检不调用密码库，也不生成新的密码状态。
pub(super) fn cached(state: &State, scope: &Scope, action: &Action) -> Result<bool, ApiError> {
    if matches!(action, Action::Initialize) {
        return Ok(state.identity.is_some());
    }
    if state.identity.is_none() {
        return Err(reject("crypto_not_initialized", "尚未显式创建实验身份。"));
    }
    match action {
        Action::CreateGroup { .. } | Action::JoinGroup { .. } => {
            if state.conversation.is_some() {
                return Err(reject("crypto_already_grouped", "实验仅支持一个双成员群。"));
            }
        }
        Action::Send {
            attempt_id,
            message_id,
            text,
        } => {
            if let Some(old) = state
                .outbox
                .iter()
                .find(|item| item.attempt_id == *attempt_id)
            {
                if old.message_id != *message_id || old.plaintext_hash != hash(text.as_bytes()) {
                    return Err(reject(
                        "crypto_attempt_conflict",
                        "相同尝试不能对应不同内容。",
                    ));
                }
                return Ok(true);
            }
            if state
                .outbox
                .iter()
                .any(|item| item.message_id == *message_id)
            {
                return Err(reject(
                    "crypto_message_conflict",
                    "同一消息不能创建第二个发送尝试。",
                ));
            }
            if state.outbox.len() >= LIMIT {
                return Err(limit());
            }
            require_group(state)?;
        }
        Action::Download { event } => {
            require_group(state)?;
            if event.envelope.service != scope.service
                || Some(&event.envelope.conversation) != state.conversation.as_ref()
            {
                return Err(reject("crypto_event_scope", "原始事件不属于当前实例或群。"));
            }
            if let Some(old) = state
                .events
                .iter()
                .find(|item| item.sequence == event.sequence)
            {
                if old.event_id != event.event_id
                    || query::serialized(&old.envelope)? != query::serialized(&event.envelope)?
                {
                    return Err(reject(
                        "crypto_event_conflict",
                        "相同事件序号对应不同记录。",
                    ));
                }
                return Ok(true);
            }
            if event.sequence != next(&state.download_cursor)? {
                return Err(reject(
                    "crypto_download_gap",
                    "下载事件必须紧接已保存的连续游标。",
                ));
            }
            if state
                .events
                .iter()
                .any(|item| item.event_id == event.event_id)
            {
                return Err(reject(
                    "crypto_event_conflict",
                    "相同事件标识不能对应不同序号。",
                ));
            }
            if state.events.len() >= LIMIT {
                return Err(limit());
            }
        }
        Action::ProcessNext => {
            require_group(state)?;
            return Ok(state.processing_cursor == state.download_cursor);
        }
        Action::Inspect | Action::Initialize => {}
    }
    Ok(false)
}

fn require_group(state: &State) -> Result<(), ApiError> {
    if state.conversation.is_none() {
        return Err(reject("crypto_no_group", "尚未完成实验群建立。"));
    }
    Ok(())
}

fn limit() -> ApiError {
    reject("crypto_limit", "密码实验记录达到上限。")
}

fn restored(state: &State, scope: &Scope) -> Result<Engine, ApiError> {
    Engine::restore(state.provider.as_deref().ok_or_else(query::corrupt)?, scope)
}

fn capture(state: &mut State, engine: &Engine) -> Result<(), ApiError> {
    state.provider = Some(engine.export()?);
    state.identity = Some(engine.identity());
    state.conversation = engine.conversation();
    Ok(())
}

pub(super) fn apply(
    state: &mut State,
    scope: &Scope,
    action: &Action,
) -> Result<&'static str, ApiError> {
    match action {
        Action::Initialize => {
            let engine = Engine::new(scope)?;
            capture(state, &engine)?;
            Ok("initialized")
        }
        Action::CreateGroup { conversation, peer } => {
            let mut engine = restored(state, scope)?;
            state.welcome = Some(engine.create_group(conversation, peer)?);
            capture(state, &engine)?;
            Ok("grouped")
        }
        Action::JoinGroup {
            conversation,
            peer,
            welcome,
        } => {
            let mut engine = restored(state, scope)?;
            engine.join_group(conversation, peer, welcome)?;
            capture(state, &engine)?;
            Ok("grouped")
        }
        Action::Send {
            attempt_id,
            message_id,
            text,
        } => {
            let mut engine = restored(state, scope)?;
            let envelope = engine.send(message_id, text)?;
            let ciphertext_hash = hash(&decode(&envelope.ciphertext)?);
            capture(state, &engine)?;
            state.outbox.push(Outbound {
                attempt_id: attempt_id.clone(),
                message_id: message_id.clone(),
                plaintext_hash: hash(text.as_bytes()),
                ciphertext_hash,
                envelope,
            });
            state.encryptions = next(&state.encryptions)?;
            Ok("outbox_ready")
        }
        Action::Download { event } => {
            state.events.push(Event {
                sequence: event.sequence.clone(),
                event_id: event.event_id.clone(),
                ciphertext_hash: hash(&decode(&event.envelope.ciphertext)?),
                status: "pending".into(),
                envelope: event.envelope.clone(),
            });
            state.download_cursor = event.sequence.clone();
            Ok("downloaded")
        }
        Action::ProcessNext => process(state, scope),
        Action::Inspect => Err(ApiError::invalid()),
    }
}

fn process(state: &mut State, scope: &Scope) -> Result<&'static str, ApiError> {
    let sequence = next(&state.processing_cursor)?;
    let index = state
        .events
        .iter()
        .position(|event| event.sequence == sequence)
        .ok_or_else(query::corrupt)?;
    let event = state.events[index].clone();
    if event.status != "pending" {
        return Err(query::corrupt());
    }
    let previous = state.events.iter().find(|old| {
        old.status == "processed"
            && (old.ciphertext_hash == event.ciphertext_hash
                || old.envelope.message_id == event.envelope.message_id)
    });
    if let Some(old) = previous {
        if old.ciphertext_hash != event.ciphertext_hash
            || query::serialized(&old.envelope)? != query::serialized(&event.envelope)?
        {
            return Err(ApiError::new(
                "crypto_replay_conflict",
                "重放密文或消息标识的认证上下文不一致。",
                true,
            ));
        }
        // 完全相同的已验证信封只推进新事件槽；不再次解密、复制消息或产生送达回执。
        state.events[index].status = "duplicate".into();
    } else {
        if state.messages.len() >= LIMIT {
            return Err(limit());
        }
        let mut engine = restored(state, scope)?;
        let message = engine.receive(&event.envelope)?;
        capture(state, &engine)?;
        state.messages.push(Message {
            sequence: sequence.clone(),
            event_id: event.event_id.clone(),
            message_id: message.message_id,
            sender_account: message.sender_account,
            text: message.text,
        });
        state.receipts.push(event.event_id.clone());
        state.events[index].status = "processed".into();
        state.decryptions = next(&state.decryptions)?;
    }
    state.processing_cursor = sequence;
    Ok("processed")
}
