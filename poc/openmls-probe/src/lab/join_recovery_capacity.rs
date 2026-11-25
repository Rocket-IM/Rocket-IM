//! 公共恢复证据的原子接纳：容量不足只提交暂停，不部分更新证据或权限视图。
use super::{
    checked, consistency_state::Status, join_recovery_state as stored, state::DeviceState, LabError,
};
use serde_json::Value;

/// 仅供 Observe / AdvancePublic / Resolve 使用；三条路径不访问或改变 MLS provider。
/// 它们的容量错误均位于签名和证据范围校验之后，坏证据仍原样拒绝且不改变状态。
/// 预检也走同一路径，使暂停能通过独立锚 Reserve / Finish 和正常快照提交。
pub(super) fn accept(
    state: &mut DeviceState,
    operation: impl FnOnce(&mut DeviceState) -> Result<Value, LabError>,
) -> Result<Value, LabError> {
    let raw = checked("recovery_encoding", serde_json::to_vec(state))?;
    // provider 是 serde(skip)，候选只用于公共元数据校验，不复制或恢复密码引擎。
    let mut candidate: DeviceState = checked("recovery_encoding", serde_json::from_slice(&raw))?;
    let result = operation(&mut candidate).and_then(|result| {
        // 也检查附加完整材料、关闭原件等最后一步；不能只检查新增观察前的容量。
        if let Some(recovery) = &candidate.join_recovery {
            stored::budget(recovery)?;
        }
        super::join_recovery_witness_state::budget(&candidate, 0)?;
        Ok(result)
    });
    match result {
        Ok(value) => {
            state.version = candidate.version;
            state.permissions = candidate.permissions;
            state.join_recovery = candidate.join_recovery;
            state.witness_state = candidate.witness_state;
            Ok(value)
        }
        Err(error) if error.code == "resource_exhausted" => {
            state.permissions.consistency.pause(
                Status::EvidenceCapacityExhausted,
                "recovery_evidence_capacity",
            );
            // 暂停标记在有独立限额的恢复证据容器之外；不淘汰原件，不抬高已知水位。
            // 外层只有保存成功（启用独立锚时还需 Finish）才交付此结果。
            Ok(super::join_recovery_consistency::paused(state))
        }
        Err(error) => Err(error),
    }
}
