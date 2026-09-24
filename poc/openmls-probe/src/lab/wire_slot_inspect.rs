//! 仅实验观察：从本次已加载快照读取一个原始网络槽及处理摘要，不导出正文或密码状态。

use super::{ensure, state::DeviceState, wire_types::decimal, LabError};
use serde_json::{json, Value};

pub(super) fn inspect(state: &DeviceState, event_seq: &str) -> Result<Value, LabError> {
    let seq = decimal(event_seq)?;
    ensure(seq > 0, "cursor_invalid", "槽位序号必须大于零")?;
    let stored = state.wire_sync.slots.get(&seq);
    // 单次最多返回一个已保存的受限网络槽，绝不序列化整个 inbox 或 provider。
    Ok(json!({
        "event_seq":event_seq,
        "found":stored.is_some(),
        "slot":stored.map(|record| &record.slot),
        "result":stored.and_then(|record| record.result.as_ref()),
        "waiting":stored.is_some_and(|record| record.waiting),
    }))
}
