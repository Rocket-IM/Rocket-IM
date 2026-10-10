//! 核验的确定性拒绝在预约前完成；成功仍须原锚预约和执行时重核。
use super::{
    checked, ensure, identity_session::Session, state::DeviceState, store::LockedDevice, Context,
    LabError, Operation, Request,
};

pub(super) fn registration(state: &DeviceState, challenge_bytes: &str) -> Result<(), LabError> {
    let challenge = crate::device_registration::parse_challenge(challenge_bytes)?;
    ensure(
        challenge.service_id == state.context.service
            && challenge.account_id == state.context.account
            && challenge.device_id == state.context.device
            && challenge.signature_key == super::codec::encode(&state.own_signature_key),
        "registration_context",
        "注册挑战未绑定本机准确身份",
    )
}
pub(super) fn check(
    locked: &LockedDevice,
    request: &Request,
    context: &Context,
    session: &Session,
) -> Result<(), LabError> {
    if !matches!(
        request.operation,
        Operation::IdentityTrustObserve { .. }
            | Operation::IdentityTrustPrepare { .. }
            | Operation::IdentityTrustConfirm { .. }
            | Operation::IdentityTrustReset { .. }
            | Operation::IdentityTrustInspect { .. }
            | Operation::DeviceRegistrationProve { .. }
            | Operation::PermissionPinMember { .. }
            | Operation::Authorize { .. }
            | Operation::Create { .. }
            | Operation::Send { .. }
            | Operation::Remove { .. }
            | Operation::WireSend { .. }
            | Operation::PermissionPrepare { .. }
            | Operation::PermissionPrepareAdd { .. }
            | Operation::PermissionPrepareDevice { .. }
            | Operation::HistoryExport { .. }
    ) {
        return Ok(());
    }
    let head = super::rollback_io::state_hash(&request.directory)?;
    let metadata = locked
        .metadata_committed(
            context,
            &checked("anchor_head", crate::rollback_anchor::decode_hex(&head))?,
        )?
        .ok_or_else(|| LabError::new("not_initialized", "设备尚未初始化"))?;
    super::rebuild_state::guard(&metadata, &request.operation)?;
    super::wire_send_order::preflight(&metadata, &request.operation)?;
    super::wire_stream_source::preflight(&metadata, &request.operation)?;
    super::consistency_state::guard(&metadata, &request.operation)?;
    super::permissions::guard(&metadata, &request.operation)?;
    super::wire_send_order::preflight_send(&metadata, &request.operation)?;
    super::identity_records::preflight(&metadata, session, &request.operation)?;
    if let Operation::DeviceRegistrationProve { challenge_bytes } = &request.operation {
        registration(&metadata, challenge_bytes)?;
    }
    super::identity_gate::check(&metadata, &request.operation)
}
