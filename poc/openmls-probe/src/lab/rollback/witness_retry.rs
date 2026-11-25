//! 只读返回 W1 已承诺原件；不是通用执行许可，不恢复 provider 或刷新签名。
use crate::join_recovery::{self as p, witness as w};
use crate::lab::{
    checked, ensure, identity_preflight, join_recovery_state as recovery,
    join_recovery_witness_state as stored, rollback_io, state::DeviceState, store::LockedDevice,
    Context, LabError, Operation, Request, Session,
};
use crate::rollback_anchor::{Action, Status};
use serde_json::{json, Value};

pub(super) fn try_result(
    config: &super::Config,
    locked: &LockedDevice,
    request: &Request,
    context: &Context,
    session: &Session,
) -> Result<Option<Value>, LabError> {
    let Operation::JoinRecovery { command } = &request.operation else {
        return Ok(None);
    };
    if !matches!(
        command,
        recovery::Command::WitnessRequest { .. }
            | recovery::Command::WitnessRespond { .. }
            | recovery::Command::WitnessApply { .. }
    ) {
        return Ok(None);
    }
    let head = rollback_io::state_hash(&request.directory)?;
    let mut metadata = locked
        .metadata_committed(
            context,
            &checked("anchor_head", crate::rollback_anchor::decode_hex(&head))?,
        )?
        .ok_or_else(|| LabError::new("anchor_state", "已登记设备缺少完整快照"))?;
    if !has_result(&metadata, command)? {
        return Ok(None);
    }
    // 门禁与返回值使用同一份完整摘要认证的元数据，不能沿用另一份加载结果。
    let before = checked(
        "state_encoding",
        serde_json::to_vec(&metadata.permissions.consistency),
    )?;
    identity_preflight::check_loaded(&mut metadata, request, session)?;
    if before
        != checked(
            "state_encoding",
            serde_json::to_vec(&metadata.permissions.consistency),
        )?
        || checkpoint_mismatch(&metadata)?
    {
        // 原执行路径可能需要实际 provider 核验并提交 Q02 暂停；不能以缓存跳过。
        return Ok(None);
    }
    let result = cached_result(&metadata, command)?;
    let identity: String = metadata
        .own_signature_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    ensure(
        config.scope.service == context.service
            && config.scope.account == context.account
            && config.scope.device == context.device,
        "anchor_scope",
        "可信锚配置与请求设备范围不匹配",
    )?;
    ensure(
        identity == config.scope.identity_key,
        "anchor_identity",
        "设备密码身份与登记公钥不匹配",
    )?;
    no_pending(&request.directory)?;
    // rpc 验证独立锚签名及本次随机挑战；Inspect 不预约、不结束任何许可。
    let observed = config.rpc(
        Action::Inspect,
        &rollback_io::random_hex()?,
        &head,
        "absent",
        "0",
    )?;
    ensure(
        observed.status == Status::Inspected,
        "anchor_response",
        "锚检查响应类型错误",
    )?;
    ensure(
        observed.head == head && observed.active_txn.is_none() && observed.closure.is_none(),
        "anchor_conflict",
        "缓存返回要求准确完整快照且独立锚没有未决许可或封存",
    )?;
    no_pending(&request.directory)?;
    ensure(
        rollback_io::state_hash(&request.directory)? == head,
        "anchor_state_changed",
        "只读缓存输出前完整快照已被替换",
    )?;
    Ok(Some(json!({"ok":true,"result":result})))
}

fn no_pending(directory: &std::path::Path) -> Result<(), LabError> {
    ensure(
        !super::exists(&directory.join(super::GATE))?
            && !super::exists(&directory.join(super::JOURNAL))?,
        "anchor_paused",
        "已有独立锚门禁或结果日志；只读重试不能自动恢复",
    )
}

fn has_result(state: &DeviceState, command: &recovery::Command) -> Result<bool, LabError> {
    let Some(ledger) = state.witness_state.as_ref() else {
        return Ok(false);
    };
    Ok(match command {
        recovery::Command::WitnessRequest { request_id, .. } => {
            ledger.challenges.contains_key(request_id)
        }
        recovery::Command::WitnessRespond { request, .. } => ledger
            .responses
            .contains_key(&w::parse_witness_request(request)?.request_id),
        recovery::Command::WitnessApply { record, .. } => ledger
            .installed
            .contains_key(&p::parse_intent(&record.bundle.intent)?.change_id),
        _ => false,
    })
}

fn full_original(state: &DeviceState, record: &p::Record) -> Result<(), LabError> {
    let id = p::parse_intent(&record.bundle.intent)?.change_id;
    ensure(
        recovery::get(state)?
            .records
            .get(&id)
            .and_then(|old| old.record.full())
            == Some(record),
        "idempotency_conflict",
        "只读精确重试必须匹配已保存完整接受材料原件",
    )
}

fn cached_result(state: &DeviceState, command: &recovery::Command) -> Result<Value, LabError> {
    match command {
        recovery::Command::WitnessRequest {
            record,
            request_id,
            ttl,
        } => {
            full_original(state, record)?;
            let old = stored::get(state)?
                .challenges
                .get(request_id)
                .ok_or_else(|| LabError::new("w1_challenge_inactive", "请求不存在"))?;
            ensure(
                old.requested_ttl == *ttl,
                "w1_request_id_conflict",
                "同一请求 ID 不可改变窗口",
            )?;
            Ok(json!({"request":old.request,"duplicate":true}))
        }
        recovery::Command::WitnessRespond { record, request } => {
            let r = crate::lab::join_recovery_witness_response::check(state, record, request)?;
            let old = stored::get(state)?
                .responses
                .get(&r.request_id)
                .ok_or_else(|| LabError::new("w1_request_id_conflict", "原响应不存在"))?;
            let mut delivery = old.delivery.clone();
            // 原签名、highest_known 与期限不变；仍披露此快照后来保存的公开事实。
            delivery.supplemental_evidence = crate::lab::join_recovery_witness_evidence::export(
                state,
                &delivery.known_evidence,
            )?;
            Ok(json!({"delivery":delivery,"duplicate":true}))
        }
        recovery::Command::WitnessApply {
            record,
            request,
            delivery,
        } => {
            full_original(state, record)?;
            ensure(
                crate::lab::join_recovery_witness_apply::check(state, record, request, delivery)?
                    .is_none(),
                "w1_binding_mismatch",
                "只读安装重试必须已有准确已安装关联",
            )?;
            Ok(json!({"duplicate":true,"installed":true,"checkpoint":state.permissions.checkpoint}))
        }
        _ => Err(LabError::new("invalid_request", "不属于 W1 精确重试")),
    }
}

fn checkpoint_mismatch(state: &DeviceState) -> Result<bool, LabError> {
    // 与 consistency_state::preflight 的元数据触发条件相同；只决定是否回原路径。
    if state.permissions.recovery.relay_receipt_key.is_none()
        || state.permissions.recovery.access_removed
    {
        return Ok(false);
    }
    let Some(cp) = state.permissions.checkpoint.as_ref() else {
        return Ok(false);
    };
    let version = crate::lab::consistency_state::version(cp)?;
    let stored = &state.permissions.consistency;
    Ok(stored
        .checkpoints
        .get(&version)
        .is_some_and(|known| known != cp)
        || stored
            .checkpoints
            .last_key_value()
            .is_some_and(|(latest, _)| version < *latest)
        || stored.heads.iter().any(|head| {
            head.statement.checkpoint.authorization_version == cp.authorization_version
                && head.statement.checkpoint != *cp
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection() -> (DeviceState, p::Record, recovery::Command) {
        // 仅将既有格式向量投影到缓存字段；占位 MLS 从不交给校验器或处理器。
        let v: Value = serde_json::from_str(include_str!(
            "../../../../../api/realtime/join-recovery-witness-vectors.json"
        ))
        .unwrap();
        let public: p::PublicRecord = serde_json::from_value(v["public_record"].clone()).unwrap();
        let record = p::Record {
            bundle: p::Bundle {
                intent: public.bundle.intent,
                claim: public.bundle.claim,
                allocation: public.bundle.allocation,
                change: public.bundle.change,
                key_package: v["material_scope"]["key_package"]["bytes"]
                    .as_str()
                    .unwrap()
                    .into(),
                welcome: v["material_scope"]["welcome"]["bytes"]
                    .as_str()
                    .unwrap()
                    .into(),
            },
            receipt: public.receipt,
        };
        let proof =
            serde_json::from_value(v["format_envelopes"]["witness_request"]["envelope"].clone())
                .unwrap();
        let q = w::parse_witness_request(&proof).unwrap();
        let fact: w::InstallationFact = p::raw(
            v["unsigned_objects"]["installation_fact"]["raw_bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let mut state = DeviceState::new(Context {
            service: q.scope.service_id,
            account: q.target.account_id,
            device: q.target.device_id,
        })
        .unwrap();
        state.join_recovery = Some(recovery::State::default());
        state.join_recovery.as_mut().unwrap().records.insert(
            q.change_id,
            recovery::Accepted {
                predecessor: fact.previous.checkpoint.clone(),
                record: p::Evidence::Full(record.clone()),
                installed: false,
            },
        );
        state.witness_state = Some(stored::State::default());
        state.witness_state.as_mut().unwrap().challenges.insert(
            q.request_id.clone(),
            stored::Challenge {
                request: proof,
                requested_ttl: "60".into(),
                status: stored::ChallengeStatus::Active,
            },
        );
        state.permissions.checkpoint = Some(fact.previous.checkpoint);
        state.permissions.recovery.relay_receipt_key = Some("format-only".into());
        let command = recovery::Command::WitnessRequest {
            record: record.clone(),
            request_id: q.request_id,
            ttl: "60".into(),
        };
        // 缓存投影不得借新身份初始化的 provider 运行密码动作。
        let state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        (state, record, command)
    }

    #[test]
    fn witness_cached_request_requires_exact_original_and_never_refreshes_it() {
        let (state, record, command) = projection();
        assert!(state.group().is_err());
        let before = serde_json::to_vec(&state).unwrap();
        let result = cached_result(&state, &command).unwrap();
        let old = state
            .witness_state
            .as_ref()
            .unwrap()
            .challenges
            .values()
            .next()
            .unwrap();
        assert_eq!(result["request"], json!(old.request));
        assert_eq!(result["duplicate"], json!(true));
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        let recovery::Command::WitnessRequest { request_id, .. } = &command else {
            panic!("fixture");
        };
        for changed in [
            recovery::Command::WitnessRequest {
                record: record.clone(),
                request_id: request_id.clone(),
                ttl: "59".into(),
            },
            recovery::Command::WitnessRequest {
                record: p::Record {
                    bundle: p::Bundle {
                        welcome: "different-opaque-format-bytes".into(),
                        ..record.bundle.clone()
                    },
                    receipt: record.receipt.clone(),
                },
                request_id: request_id.clone(),
                ttl: "60".into(),
            },
        ] {
            assert!(cached_result(&state, &changed).is_err());
            assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        }
        assert!(!has_result(
            &state,
            &recovery::Command::WitnessRequest {
                record: record.clone(),
                request_id: "not-saved".into(),
                ttl: "60".into(),
            },
        )
        .unwrap());
        assert!(!has_result(
            &state,
            &recovery::Command::Apply {
                record: p::Evidence::Full(record),
            },
        )
        .unwrap());
    }

    #[test]
    fn witness_cached_retry_defers_checkpoint_conflict_and_rollback_to_execution() {
        let (mut state, _, _) = projection();
        let cp = state.permissions.checkpoint.clone().unwrap();
        let version = crate::lab::consistency_state::version(&cp).unwrap();
        state
            .permissions
            .consistency
            .checkpoints
            .insert(version, cp.clone());
        assert!(!checkpoint_mismatch(&state).unwrap());
        state
            .permissions
            .checkpoint
            .as_mut()
            .unwrap()
            .crypto_state_ref = "other".into();
        assert!(checkpoint_mismatch(&state).unwrap());
        state.permissions.checkpoint = Some(cp.clone());
        state
            .permissions
            .consistency
            .checkpoints
            .insert(version + 1, cp);
        assert!(checkpoint_mismatch(&state).unwrap());
    }
}
