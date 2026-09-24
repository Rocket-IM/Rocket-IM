//! 逐次核验指纹；verification 是调用方声明，不能自动证明人工核验或渠道独立。
use super::{
    consistency, consistency_state, ensure, exchange_state as stored, state::DeviceState, LabError,
};
use crate::{
    consistency_exchange::{self as public, RequestStatement, Verification},
    permission::Identity,
};
use serde_json::{json, Value};

pub(super) fn begin(
    state: &mut DeviceState,
    source: Identity,
    fingerprint: String,
    verification: Verification,
) -> Result<Value, LabError> {
    let cp = stored::current(state)?;
    ensure(
        source != stored::own(state),
        "exchange_context",
        "对照来源不能是本机设备",
    )?;
    ensure(
        public::fingerprint(stored::member_key(cp, &source)?)? == fingerprint,
        "exchange_key_changed",
        "来源指纹与当前已核验公钥不符",
    )?;
    if let Some(active) = &state.permissions.exchange.active {
        let request = stored::verify_request(state, &active.request)?;
        ensure(
            request.source == source
                && request.source_fingerprint == fingerprint
                && active.verification == verification,
            "exchange_conflict",
            "已有其他来源或核验方式的对照请求",
        )?;
        ensure(
            state.permissions.consistency.challenge.as_ref() == Some(&request.challenge),
            "exchange_challenge_required",
            "本次对照检查闸已被其他观察消费",
        )?;
        return Ok(json!({"request":active.request,"reused":true}));
    }
    ensure(
        state.permissions.consistency.challenge.is_none(),
        "exchange_challenge_required",
        "先完成已有一致性检查，不能接管其他挑战",
    )?;
    ensure(
        state.permissions.exchange.imports.len() < stored::LIMIT,
        "resource_exhausted",
        "对照导入记录达到128条上限",
    )?;
    let mut request = RequestStatement {
        protocol_version: "rim-consistency-exchange-request-1".into(),
        service_id: cp.service_id.clone(),
        conversation_id: cp.conversation_id.clone(),
        source,
        target: stored::own(state),
        source_fingerprint: fingerprint,
        target_fingerprint: public::fingerprint(stored::member_key(cp, &stored::own(state))?)?,
        challenge: String::new(),
    };
    consistency::challenge(state)?;
    request.challenge = state
        .permissions
        .consistency
        .challenge
        .clone()
        .ok_or_else(|| LabError::new("exchange_challenge_required", "挑战生成失败"))?;
    let signed = stored::sign(state, public::REQUEST_DOMAIN, &request)?;
    stored::verify_request(state, &signed)?;
    state.permissions.exchange.active = Some(stored::Active {
        request: signed.clone(),
        verification,
    });
    Ok(json!({"request":signed,"reused":false}))
}

pub(super) fn cancel(state: &mut DeviceState) -> Result<Value, LabError> {
    let duplicate = state.permissions.exchange.active.take().is_none();
    // 取消只停止文件交换；原挑战继续阻断发送，须走原 head 核验或显式恢复。
    Ok(
        json!({"cancelled":true,"duplicate":duplicate,"consistency":consistency_state::inspect(state)}),
    )
}
