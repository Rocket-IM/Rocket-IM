//! 仅分页发现和导出本机已有计划；不推测Relay状态，也不自动执行网络或回收。
use super::{
    ensure, state::DeviceState, wire_reclaim, wire_reclaim_preparation, wire_types, LabError,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) fn list(
    state: &DeviceState,
    after_plan_id: Option<String>,
    limit: String,
) -> Result<Value, LabError> {
    wire_reclaim::source(state)?;
    if let Some(after) = &after_plan_id {
        wire_types::id(after).map_err(|_| LabError::new("reclaim_invalid", "计划分页游标无效"))?;
    }
    let limit = wire_types::decimal(&limit)
        .map_err(|_| LabError::new("reclaim_invalid", "计划分页数量必须为十进制字符串"))?;
    ensure(
        (1..=100).contains(&limit),
        "reclaim_invalid",
        "计划分页数量必须为1—100",
    )?;
    let mut plans = BTreeMap::new();
    if let Some(ledger) = &state.wire_reclamation {
        for id in ledger.prepared.keys() {
            plans.insert(id, "prepared");
        }
        for id in ledger.plans.keys() {
            plans.insert(id, "applied");
        }
    }
    let mut page = plans
        .into_iter()
        .filter(|(id, _)| after_plan_id.as_ref().is_none_or(|after| *id > after));
    let records: Vec<_> = page
        .by_ref()
        .take(limit as usize)
        .map(|(id, status)| json!({"plan_id":id,"status":status}))
        .collect();
    let has_more = page.next().is_some();
    let next = if has_more {
        records.last().map(|p| p["plan_id"].clone())
    } else {
        None
    };
    Ok(json!({"plans":records,"has_more":has_more,"next_after_plan_id":next}))
}

pub(super) fn recover(state: &DeviceState, plan_id: String) -> Result<Value, LabError> {
    wire_reclaim::source(state)?;
    wire_types::id(&plan_id).map_err(|_| LabError::new("reclaim_invalid", "恢复计划ID无效"))?;
    if let Some(ledger) = &state.wire_reclamation {
        if let Some(prepared) = ledger.prepared.get(&plan_id) {
            return wire_reclaim_preparation::output(&plan_id, prepared);
        }
        if let Some(plan) = ledger.plans.get(&plan_id) {
            return Ok(json!({"status":"applied","plan_id":plan_id,
                "finish_request":plan.result["finish_request"],"result":plan.result}));
        }
    }
    Err(LabError::new(
        "reclaim_not_found",
        "本机没有此准备或完成计划",
    ))
}
