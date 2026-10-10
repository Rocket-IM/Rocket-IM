//! 首次观察、精确确认与显式重置；候选完整通过预算后才替换账本。
use super::{
    checked, codec, ensure, identity_session::Session, identity_state as stored,
    state::DeviceState, LabError, Operation,
};
use crate::{
    consistency_exchange::Verification,
    identity_trust::{DeviceIdentity, Display, Purpose},
    permission::Identity,
};
use serde_json::{json, Value};

fn get<'a>(state: &'a DeviceState, target: &Identity) -> Result<&'a stored::Record, LabError> {
    let key = stored::key(target)?;
    state
        .identity_trust
        .as_ref()
        .and_then(|s| s.records.get(&key))
        .ok_or_else(|| LabError::new("identity_not_found", "本机尚未观察此设备身份"))
}
fn scope(state: &DeviceState, identity: &DeviceIdentity) -> Result<(), LabError> {
    identity.validate()?;
    ensure(
        identity.service_id == state.context.service
            && !(identity.account_id == state.context.account
                && identity.device_id == state.context.device),
        "identity_context",
        "核验对象属于其他实例或本机自身",
    )
}
fn result(record: &stored::Record, duplicate: bool) -> Value {
    json!({"record":record,"duplicate":duplicate})
}
fn candidate(state: &DeviceState) -> stored::State {
    state.identity_trust.clone().unwrap_or(stored::State {
        version: 1,
        records: Default::default(),
    })
}
fn budget(state: &DeviceState, next: &stored::State) -> Result<(), LabError> {
    stored::validate_records(state, next)?;
    // 元数据预检与执行使用同一快照候选，不把账本上限误当全快照有空余。
    let mut encoded = checked("identity_invalid", serde_json::to_value(state))?;
    encoded["identity_trust"] = checked("identity_invalid", serde_json::to_value(next))?;
    ensure(
        checked("identity_invalid", serde_json::to_vec(&encoded))?.len()
            <= crate::snapshot::MAX_PLAINTEXT_BYTES,
        "identity_budget",
        "完整快照没有核验记录所需容量",
    )
}
fn observed(
    state: &DeviceState,
    identity: &DeviceIdentity,
) -> Result<(stored::State, Value), LabError> {
    scope(state, identity)?;
    let mut next = candidate(state);
    let key = stored::key(&stored::target(identity))?;
    if let Some(record) = next.records.get_mut(&key) {
        if record.identity == *identity || record.candidate.as_ref() == Some(identity) {
            let output = result(record, true);
            return Ok((next, output));
        }
        // 合法但冲突的变化也必须持久暂停；候选不授予绑定，确认另行拒绝复用。
        record.candidate = Some(identity.clone());
        record.status = stored::Status::Changed;
        record.history = stored::History::Gap;
        record.revision = stored::next(&record.revision)?;
    } else {
        let old = stored::legacy(state, &stored::target(identity));
        let changed = old.as_ref().is_some_and(|old| old != identity);
        if !changed {
            stored::binding_available(state, identity)?;
        }
        next.records.insert(
            key.clone(),
            stored::Record {
                identity: old.unwrap_or_else(|| identity.clone()),
                candidate: changed.then(|| identity.clone()),
                revision: "1".into(),
                status: if changed {
                    stored::Status::Changed
                } else {
                    stored::Status::Unverified
                },
                history: if changed {
                    stored::History::Gap
                } else {
                    stored::History::Unknown
                },
                verification: None,
                retired: Vec::new(),
                last_reset: None,
            },
        );
    }
    budget(state, &next)?;
    let output = result(
        next.records
            .get(&key)
            .ok_or_else(|| LabError::new("identity_invalid", "缺少核验候选"))?,
        false,
    );
    Ok((next, output))
}

fn can_prepare(
    state: &DeviceState,
    session: &Session,
    target: &Identity,
    purpose: Purpose,
) -> Result<(), LabError> {
    session.require()?;
    ensure(
        session.displays.len() < 128,
        "identity_budget",
        "本会话展示达到128条上限",
    )?;
    let record = get(state, target)?;
    ensure(
        match purpose {
            Purpose::Verify => record.status != stored::Status::Changed,
            Purpose::Reset => record.status == stored::Status::Changed,
        },
        "identity_changed",
        "身份变化须显式重置；重置仅适用于变化候选",
    )
}

fn confirmed(
    state: &DeviceState,
    session: &Session,
    display: &Display,
    independent: &DeviceIdentity,
    verification: Verification,
    purpose: Purpose,
) -> Result<(stored::State, Value), LabError> {
    session.verify(display)?;
    ensure(
        display.observer == stored::own(state) && display.purpose == purpose,
        "identity_context",
        "核验展示的本机身份或用途不匹配",
    )?;
    independent.validate()?;
    ensure(
        *independent == display.identity,
        "identity_context",
        "独立公开对象与展示身份不一致",
    )?;
    stored::binding_available(state, independent)?;
    let hash = codec::digest_hex(&codec::digest(&checked(
        "identity_invalid",
        serde_json::to_vec(&(display, independent, verification)),
    )?));
    let mut next = candidate(state);
    let record = next
        .records
        .get_mut(&stored::key(&stored::target(independent))?)
        .ok_or_else(|| LabError::new("identity_not_found", "核验目标不存在"))?;
    let duplicate = match purpose {
        Purpose::Verify => {
            record.status == stored::Status::Verified
                && record
                    .verification
                    .as_ref()
                    .is_some_and(|v| v.confirmation_sha256 == hash)
        }
        Purpose::Reset => record.last_reset.as_ref() == Some(&hash),
    };
    if duplicate {
        let output = result(record, true);
        return Ok((next, output));
    }
    ensure(
        record.revision == display.record_revision,
        "identity_confirmation_stale",
        "展示之后记录版本已改变",
    )?;
    match purpose {
        Purpose::Verify => {
            ensure(
                record.status != stored::Status::Changed
                    && record.identity == display.identity
                    && display.previous.is_none(),
                "identity_changed",
                "变化候选未经显式重置，不能直接核验替换",
            )?;
            record.status = stored::Status::Verified;
            record.verification = Some(stored::Fact {
                verification,
                confirmation_sha256: hash,
            });
        }
        Purpose::Reset => {
            ensure(
                record.status == stored::Status::Changed
                    && record.candidate.as_ref() == Some(&display.identity)
                    && display.previous.as_ref() == Some(&record.identity),
                "identity_confirmation_stale",
                "重置展示不是准确旧绑定和新候选",
            )?;
            record.retired.push(stored::Retired {
                identity: record.identity.clone(),
                verification: record.verification.take(),
            });
            record.identity = display.identity.clone();
            record.candidate = None;
            record.status = stored::Status::Unverified;
            record.history = stored::History::Reset;
            record.last_reset = Some(hash);
        }
    }
    record.revision = stored::next(&record.revision)?;
    let output = result(record, false);
    budget(state, &next)?;
    Ok((next, output))
}

pub(super) fn preflight(
    state: &DeviceState,
    session: &Session,
    operation: &Operation,
) -> Result<(), LabError> {
    match operation {
        Operation::PermissionPinMember { member } => {
            super::permission_admission::check_pin(state, member)?;
        }
        Operation::Authorize { authorization, .. } => {
            let request = &authorization.request;
            stored::binding_available(
                state,
                &stored::object(
                    &request.service,
                    &request.account,
                    &request.new_device,
                    &codec::encode(&request.new_signature_key),
                ),
            )?;
        }
        Operation::IdentityTrustObserve { identity } => {
            observed(state, identity)?;
        }
        Operation::IdentityTrustPrepare { target, purpose } => {
            can_prepare(state, session, target, *purpose)?
        }
        Operation::IdentityTrustConfirm {
            display,
            independent_identity,
            verification,
        } => {
            confirmed(
                state,
                session,
                display,
                independent_identity,
                *verification,
                Purpose::Verify,
            )?;
        }
        Operation::IdentityTrustReset {
            display,
            independent_identity,
            verification,
        } => {
            confirmed(
                state,
                session,
                display,
                independent_identity,
                *verification,
                Purpose::Reset,
            )?;
        }
        Operation::IdentityTrustInspect {
            target: Some(target),
        } => {
            get(state, target)?;
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn observe(
    state: &mut DeviceState,
    identity: DeviceIdentity,
) -> Result<Value, LabError> {
    let (next, output) = observed(state, &identity)?;
    if output["duplicate"] != true {
        state.identity_trust = Some(next);
    }
    Ok(output)
}
pub(super) fn prepare(
    state: &DeviceState,
    session: &mut Session,
    target: Identity,
    purpose: Purpose,
) -> Result<Value, LabError> {
    can_prepare(state, session, &target, purpose)?;
    let record = get(state, &target)?;
    let display = Display {
        protocol_version: "rim-identity-verification-1".into(),
        observer: stored::own(state),
        identity: record
            .candidate
            .as_ref()
            .unwrap_or(&record.identity)
            .clone(),
        previous: (purpose == Purpose::Reset).then(|| record.identity.clone()),
        record_revision: record.revision.clone(),
        session_nonce: session.nonce.clone(),
        display_nonce: super::identity_session::random()?,
        purpose,
    };
    session
        .displays
        .insert(display.display_nonce.clone(), display.clone());
    Ok(json!({"display":display}))
}
pub(super) fn confirm(
    state: &mut DeviceState,
    session: &Session,
    display: Display,
    independent: DeviceIdentity,
    verification: Verification,
    purpose: Purpose,
) -> Result<Value, LabError> {
    let (next, output) = confirmed(
        state,
        session,
        &display,
        &independent,
        verification,
        purpose,
    )?;
    if output["duplicate"] != true {
        state.identity_trust = Some(next);
    }
    Ok(output)
}
pub(super) fn inspect(state: &DeviceState, target: Option<Identity>) -> Result<Value, LabError> {
    let records: Vec<_> = if let Some(target) = target {
        vec![get(state, &target)?]
    } else {
        state
            .identity_trust
            .iter()
            .flat_map(|s| s.records.values())
            .collect()
    };
    Ok(json!({"strict":true,"records":records}))
}
