//! 固定confirm原件与原P同快照保存；重试不按当前游标重建，也不记录宿主网络进度。
use super::{
    checked, ensure, state::DeviceState, wire_reclaim, wire_reclaim_types::Prepared, wire_types,
    LabError,
};
use crate::message_reclamation;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Confirm {
    pub service_id: String,
    pub conversation_id: String,
    pub plan_id: String,
    pub stream_id: String,
    pub processed_seq: String,
    pub acceptance_ids: Vec<String>,
}

impl Confirm {
    pub fn from_statement(statement: &message_reclamation::Statement) -> Self {
        Self {
            service_id: statement.service_id.clone(),
            conversation_id: statement.conversation_id.clone(),
            plan_id: statement.plan_id.clone(),
            stream_id: statement.stream_id.clone(),
            processed_seq: statement.processed_seq.clone(),
            acceptance_ids: statement
                .messages
                .iter()
                .map(|m| m.acceptance_id.clone())
                .collect(),
        }
    }

    pub fn value(&self) -> Result<Value, LabError> {
        checked("reclaim_state", serde_json::to_value(self))
    }

    pub fn encode(&self) -> Result<String, LabError> {
        // Value使用有序键，与原json!请求导出一致；不采用结构体声明顺序。
        checked("reclaim_state", serde_json::to_string(&self.value()?))
    }

    pub fn parse(raw: &str) -> Result<Self, LabError> {
        ensure(
            raw.len() <= message_reclamation::MAX_STATEMENT_BYTES,
            "reclaim_state",
            "准备请求编码超过上限",
        )?;
        let request: Self = checked("reclaim_state", serde_json::from_str(raw))?;
        for id in [
            &request.service_id,
            &request.conversation_id,
            &request.plan_id,
            &request.stream_id,
        ] {
            wire_types::id(id)?;
        }
        wire_types::decimal(&request.processed_seq)?;
        wire_reclaim::selection(&request.acceptance_ids)?;
        ensure(
            request.encode()? == raw,
            "reclaim_state",
            "准备请求不是原固定JSON编码",
        )?;
        Ok(request)
    }

    pub fn scope(&self, state: &DeviceState) -> Result<(), LabError> {
        ensure(
            self.service_id == state.context.service
                && self.conversation_id == super::wire::configuration(state)?.conversation_id
                && state.wire_sync.stream_id.as_deref() == Some(self.stream_id.as_str())
                && wire_types::decimal(&self.processed_seq)? <= state.wire_sync.processed_cursor,
            "reclaim_state",
            "准备请求范围或原处理前缀不符",
        )
    }
}

pub(super) fn output(plan_id: &str, prepared: &Prepared) -> Result<Value, LabError> {
    let request = Confirm::parse(&prepared.request_json)?;
    Ok(
        json!({"status":"prepared","plan_id":plan_id,"request":request.value()?,
        "request_json":prepared.request_json}),
    )
}

pub(super) fn no_overlap(
    state: &DeviceState,
    plan_id: &str,
    ids: &[String],
) -> Result<(), LabError> {
    if let Some(ledger) = &state.wire_reclamation {
        for (other, prepared) in &ledger.prepared {
            if other != plan_id {
                let original = Confirm::parse(&prepared.request_json)?;
                ensure(
                    !original.acceptance_ids.iter().any(|id| ids.contains(id)),
                    "reclaim_conflict",
                    "选择已归属另一持久准备计划",
                )?;
            }
        }
    }
    Ok(())
}

pub(super) fn permit(
    state: &DeviceState,
    statement: &message_reclamation::Statement,
) -> Result<(), LabError> {
    let request = Confirm::from_statement(statement);
    no_overlap(state, &request.plan_id, &request.acceptance_ids)?;
    if let Some(prepared) = state
        .wire_reclamation
        .as_ref()
        .and_then(|r| r.prepared.get(&request.plan_id))
    {
        ensure(
            Confirm::parse(&prepared.request_json)? == request,
            "reclaim_conflict",
            "许可与本机固定准备请求不一致",
        )?;
    }
    Ok(())
}

pub(super) fn prepare(
    state: &mut DeviceState,
    plan_id: String,
    ids: Vec<String>,
) -> Result<Value, LabError> {
    wire_reclaim::source(state)?;
    wire_types::id(&plan_id)?;
    wire_reclaim::selection(&ids)?;
    let mut refresh = None;
    if let Some(ledger) = &state.wire_reclamation {
        if let Some(prepared) = ledger.prepared.get(&plan_id) {
            let original = Confirm::parse(&prepared.request_json)?;
            ensure(
                original.acceptance_ids == ids,
                "reclaim_conflict",
                "原计划ID不能改变准备选择",
            )?;
            if let Some(evidence) = super::wire_reclaim_refresh::evidence(state, &original)? {
                refresh = Some((original, prepared.request_json.clone(), evidence));
            } else {
                let mut result = output(&plan_id, prepared)?;
                result["duplicate"] = json!(true);
                return Ok(result);
            }
        }
        if let Some(plan) = ledger.plans.get(&plan_id) {
            let statement =
                message_reclamation::verify(wire_reclaim::source(state)?.0, &plan.receipt)?;
            let request = Confirm::from_statement(&statement);
            ensure(
                request.acceptance_ids == ids,
                "reclaim_conflict",
                "原计划ID不能用于另一选择",
            )?;
            let mut result = json!({"status":"applied","plan_id":plan_id,"request":request.value()?,"duplicate":true});
            if let Some(raw) = &plan.request_json {
                result["request_json"] = json!(raw);
            }
            return Ok(result);
        }
    }
    no_overlap(state, &plan_id, &ids)?;
    for id in &ids {
        wire_reclaim::candidate(state, id, &plan_id, None)?;
    }
    let request = Confirm {
        service_id: state.context.service.clone(),
        conversation_id: super::wire::configuration(state)?.conversation_id.clone(),
        plan_id: plan_id.clone(),
        stream_id: wire_reclaim::source(state)?.1.into(),
        processed_seq: state.wire_sync.processed_cursor.to_string(),
        acceptance_ids: ids,
    };
    let prepared = Prepared {
        request_json: request.encode()?,
    };
    let mut result = output(&plan_id, &prepared)?;
    result["duplicate"] = json!(false);
    if let Some((original, raw, evidence)) = refresh {
        super::wire_reclaim_refresh::describe(&mut result, &original, &raw, evidence);
    }
    let mut ledger = state.wire_reclamation.clone().unwrap_or_default();
    ledger.version = 2;
    ledger.prepared.insert(plan_id, prepared);
    ledger.budget()?;
    let previous = state.wire_reclamation.replace(ledger);
    let checked_state = (|| {
        super::wire_reclaim_validate::validate(state)?;
        ensure(
            checked("state_encoding", serde_json::to_vec(state))?.len()
                <= crate::snapshot::MAX_PLAINTEXT_BYTES,
            "resource_exhausted",
            "完整快照没有保存回收准备的空间",
        )
    })();
    if checked_state.is_err() {
        state.wire_reclamation = previous;
    }
    checked_state?;
    Ok(result)
}

/// 加载只核对固定事实，不因后续权限、阅读或迁移活动而让整个有效快照无法打开。
pub(super) fn validate(state: &DeviceState) -> Result<(), LabError> {
    let Some(ledger) = &state.wire_reclamation else {
        return Ok(());
    };
    let mut selected = BTreeSet::new();
    for (id, prepared) in &ledger.prepared {
        let request = Confirm::parse(&prepared.request_json)?;
        request.scope(state)?;
        ensure(
            request.plan_id == *id && !ledger.plans.contains_key(id),
            "reclaim_state",
            "准备与完成计划ID冲突",
        )?;
        for acceptance_id in request.acceptance_ids {
            ensure(
                selected.insert(acceptance_id.clone())
                    && !ledger
                        .messages
                        .values()
                        .any(|m| m.acceptance_id == acceptance_id),
                "reclaim_state",
                "准备选择重复或与已回收事实冲突",
            )?;
        }
    }
    for plan in ledger.plans.values() {
        if let Some(raw) = &plan.request_json {
            let request = Confirm::parse(raw)?;
            request.scope(state)?;
            let pin = state
                .permissions
                .recovery
                .relay_receipt_key
                .as_deref()
                .ok_or_else(|| LabError::new("reclaim_state", "准备原件缺少固定回执钥"))?;
            let statement = message_reclamation::verify(pin, &plan.receipt)?;
            ensure(
                request == Confirm::from_statement(&statement),
                "reclaim_state",
                "完成计划的原请求与许可不一致",
            )?;
        }
    }
    Ok(())
}
