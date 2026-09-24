//! 只从本机实际恢复记录导出，不接收外部注入的证据或另一设备快照。
use super::{ensure, exchange_state as stored, state::DeviceState, wire_types, LabError};
use crate::{
    consistency_exchange::{self as public, PackageStatement},
    permission::{
        self,
        receipts::{self, Outcome, SignedRecord},
    },
};
use serde_json::{json, Value};

pub(super) fn export(
    state: &mut DeviceState,
    request: SignedRecord,
    change_id: String,
) -> Result<Value, LabError> {
    wire_types::id(&change_id)?;
    let statement = stored::verify_request(state, &request)?;
    ensure(
        statement.source == stored::own(state),
        "exchange_context",
        "本机不是请求中的证据来源",
    )?;
    let digest = public::request_digest(&request)?;
    if let Some(previous) = state.permissions.exchange.exports.get(&digest) {
        ensure(
            previous.request == request && previous.change_id == change_id,
            "exchange_conflict",
            "同一请求已经绑定其他证据",
        )?;
        return Ok(json!({"package":previous.package,"reused":true}));
    }
    ensure(
        state.permissions.exchange.exports.len() < stored::LIMIT,
        "resource_exhausted",
        "对照导出达到128条上限",
    )?;
    let record = state
        .permissions
        .recovery
        .records
        .get(&change_id)
        .ok_or_else(|| LabError::new("exchange_unavailable", "本机未持有此已接受记录"))?;
    let key = state
        .permissions
        .recovery
        .relay_receipt_key
        .as_deref()
        .ok_or_else(|| LabError::new("exchange_trust_required", "缺少固定Service钥"))?;
    let (receipt, change) = receipts::verify_receipt(key, record)?;
    ensure(
        receipt.outcome == Outcome::Accepted,
        "exchange_unavailable",
        "closed 或候选不是已接受证据",
    )?;
    let version = permission::types::decimal(&change.previous_authorization_version)?;
    let predecessor = state
        .permissions
        .consistency
        .checkpoints
        .get(&version)
        .ok_or_else(|| LabError::new("consistency_coverage", "本机未保留此记录的完整可信前驱"))?;
    let successor = permission::verify(predecessor, &record.change)?.0;
    stored::trusted(state, &successor)?;
    ensure(
        state.permissions.applied.get(&change_id) == Some(&record.change),
        "exchange_unavailable",
        "记录尚未由本机实际应用",
    )?;
    let body = PackageStatement {
        protocol_version: "rim-consistency-exchange-package-1".into(),
        service_id: statement.service_id,
        conversation_id: statement.conversation_id,
        source: statement.source,
        target: statement.target,
        challenge: statement.challenge,
        request_sha256: digest.clone(),
        predecessor: predecessor.clone(),
        record: record.clone(),
    };
    let package = stored::sign(state, public::PACKAGE_DOMAIN, &body)?;
    public::parse_package(&package)?;
    state.permissions.exchange.exports.insert(
        digest,
        stored::Export {
            request,
            change_id,
            package: package.clone(),
        },
    );
    Ok(json!({"package":package,"reused":false}))
}
