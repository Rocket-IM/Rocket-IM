//! 显式启用的单未决发送门；只复用原 outbox 与已验签接受事实，不另存明文队列。

use super::{
    checked, ensure,
    state::DeviceState,
    wire,
    wire_types::{self, Header},
    LabError, Operation,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Policy {
    AcceptanceSerialV1 { conversation_id: String },
}

impl Policy {
    fn conversation(&self) -> &str {
        match self {
            Self::AcceptanceSerialV1 { conversation_id } => conversation_id,
        }
    }
}

fn header(record: &wire_types::Outbound) -> Result<Header, LabError> {
    let raw = checked(
        "send_order_state",
        wire_types::bytes(&record.envelope.header_bytes, 16 * 1024),
    )?;
    checked("send_order_state", Header::parse(&raw))
}

/// 在恢复 provider 之前验证持久门禁；损坏状态只能明确失败，不能清除标记后继续。
pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    super::wire_closures::validate(state)?;
    let Some(policy) = &state.wire_send_order else {
        return Ok(());
    };
    let config = state
        .wire
        .configuration
        .as_ref()
        .ok_or_else(|| LabError::new("send_order_state", "发送门缺少会话配置"))?;
    let checkpoint = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("send_order_state", "发送门缺少权限检查点"))?;
    ensure(
        policy.conversation() == config.conversation_id
            && checkpoint.conversation_id == config.conversation_id
            && checkpoint.service_id == state.context.service
            && state.permissions.recovery.relay_receipt_key.is_some()
            && state.outbox.is_empty(),
        "send_order_state",
        "发送门范围、固定 Service 公钥或旧发送记录不符合持久约束",
    )?;
    for (key, record) in &state.wire.outbox {
        let header = header(record)?;
        ensure(
            header.service_id == state.context.service
                && header.conversation_id == policy.conversation()
                && header.sender.account_id == state.context.account
                && header.sender.device_id == state.context.device
                && header.attempt_id == record.attempt_id
                && header.attempt_key()? == *key
                && header.logical_key()? == record.logical_key,
            "send_order_state",
            "原发送记录不属于当前服务、账号、设备及会话",
        )?;
    }
    Ok(())
}

pub(super) fn preflight(state: &DeviceState, operation: &Operation) -> Result<(), LabError> {
    validate(state)?;
    ensure(
        state.wire_send_order.is_none() || !matches!(operation, Operation::Send { .. }),
        "send_order_required",
        "已启用持久发送顺序，旧消息入口不能绕过原 wire outbox",
    )
}

pub(super) fn enable(state: &mut DeviceState) -> Result<Value, LabError> {
    if state.wire_send_order.is_none() {
        let conversation_id = wire::configuration(state)?.conversation_id.clone();
        ensure(
            state.group()?.is_active(),
            "device_revoked",
            "只有活跃群成员可以启用发送门",
        )?;
        ensure(
            state.permissions.recovery.relay_receipt_key.is_some(),
            "receipt_pin_required",
            "启用发送门前必须固定 Service 回执公钥",
        )?;
        ensure(
            state.permissions.checkpoint.is_some(),
            "trust_required",
            "启用发送门前必须绑定权限检查点",
        )?;
        ensure(
            state.outbox.is_empty() && state.wire.outbox.is_empty(),
            "send_order_enable_conflict",
            "只能在旧消息与 wire 发送队列均为空时首次启用",
        )?;
        state.wire_send_order = Some(Policy::AcceptanceSerialV1 { conversation_id });
    }
    validate(state)?;
    summary(state)
}

/// 已有 key 在调用点复用原字节；新后继只消费同内容当前尾的签名终态。
pub(super) fn new_attempt(
    state: &DeviceState,
    logical: &str,
    payload: &str,
    replaces: Option<&str>,
    closure: Option<&str>,
) -> Result<(), LabError> {
    if state.wire_send_order.is_none() {
        return Ok(());
    }
    let Some((key, tail)) = super::wire_closures::pending(state) else {
        return Ok(());
    };
    let terminal = super::wire_closures::terminal(state, key)?;
    ensure(
        tail.logical_key == logical && terminal.is_some(),
        "send_order_pending",
        "上一原尝试尚未接受或取得同逻辑消息终态",
    )?;
    let terminal =
        terminal.ok_or_else(|| LabError::new("send_order_pending", "缺少当前尾的终态"))?;
    ensure(
        replaces == Some(tail.attempt_id.as_str()) && closure == Some(terminal.closure_id()),
        terminal.conflict_code(),
        "后继必须引用当前尾及其精确签名终态",
    )?;
    if let super::wire_closures::Terminal::Rejected(fact) = &terminal {
        ensure(
            super::wire_rejections::checkpoint_satisfied(state, fact)?,
            "rejection_checkpoint_required",
            "后继前必须补齐拒绝所需的精确已验证权限链",
        )?;
    }
    ensure(
        payload == tail.payload,
        "idempotency_conflict",
        "后继不能修改原逻辑内容",
    )?;
    ensure(
        state
            .wire
            .outbox
            .values()
            .filter(|r| r.logical_key == logical)
            .count()
            < 5,
        "send_order_successor_limit",
        "单逻辑消息最多四个后继；当前终态保持未决",
    )
}

pub(super) fn summary(state: &DeviceState) -> Result<Value, LabError> {
    let policy = state
        .wire_send_order
        .as_ref()
        .ok_or_else(|| LabError::new("send_order_required", "发送顺序模式尚未启用"))?;
    let pending = super::wire_closures::pending(state).map(|(key, record)| {
        let header = header(record)?;
        let mut value = json!({"logical_message_id":header.logical_message_id,"attempt_id":header.attempt_id});
        match super::wire_closures::terminal(state, key)? {
            Some(super::wire_closures::Terminal::Closed(fact)) => {
                value["status"] = json!("closed_awaiting_successor");
                value["closure_id"] = json!(fact.closure_id);
            }
            Some(super::wire_closures::Terminal::Rejected(fact)) => {
                value["status"] = json!(if super::wire_rejections::checkpoint_satisfied(state, &fact)? {"rejected_awaiting_successor"} else {"rejected_awaiting_checkpoint"});
                value["closure_id"] = json!(fact.closure_id);
                value["required_authorization_version"] = json!(fact.required_authorization_version);
                value["required_crypto_state_ref"] = json!(fact.required_crypto_state_ref);
            }
            None => {}
        }
        Ok::<_, LabError>(value)
    }).transpose()?;
    Ok(
        json!({"policy":"acceptance_serial_v1","conversation_id":policy.conversation(),"pending":pending}),
    )
}
