//! 原生进程隔离实验入口；只接收合成测试调度器的请求，不是产品 SDK/API。
//! 调度器提供的 pins 是独立可信 fixture；本模块不证明现实用户身份。

mod codec;
mod consistency;
mod consistency_exchange;
mod consistency_state;
mod exchange_export;
mod exchange_import;
mod exchange_state;
mod groups;
mod history_export;
mod history_import;
mod history_state;
mod history_transfer;
mod messaging;
mod operation;
mod permission_admission;
mod permission_apply;
mod permission_commit;
mod permission_join;
mod permission_recovery;
mod permission_state;
#[cfg(test)]
mod permission_tests;
mod permissions;
#[cfg(test)]
mod quota_tests;
mod rebuild;
mod rebuild_state;
mod rebuild_stream;
mod rebuild_stream_sync;
mod recovery_state;
mod rollback;
mod rollback_io;
mod state;
mod store;
#[cfg(test)]
mod stream_source_test_support;
mod wire;
mod wire_accept;
#[cfg(test)]
mod wire_binding_tests;
mod wire_close;
#[cfg(test)]
mod wire_closure_tests;
mod wire_closures;
mod wire_history;
mod wire_lifecycle;
#[cfg(test)]
mod wire_lifecycle_tests;
mod wire_read;
#[cfg(test)]
mod wire_read_tests;
mod wire_reads;
mod wire_receive;
mod wire_reclaim;
mod wire_reclaim_compact;
#[cfg(test)]
mod wire_reclaim_tests;
mod wire_reclaim_types;
mod wire_reclaim_validate;
mod wire_reclaimed;
mod wire_reject;
#[cfg(test)]
mod wire_rejection_tests;
mod wire_rejections;
mod wire_send_order;
#[cfg(test)]
mod wire_send_order_default_tests;
#[cfg(test)]
mod wire_send_order_test_support;
#[cfg(test)]
mod wire_send_order_tests;
#[cfg(feature = "wire-send-probe")]
pub mod wire_send_probe;
#[cfg(any(test, feature = "wire-sequence-probe"))]
mod wire_sequence_probe;
mod wire_slot_inspect;
#[cfg(test)]
mod wire_slot_inspect_tests;
#[cfg(test)]
mod wire_stream_message_tests;
mod wire_stream_source;
#[cfg(test)]
mod wire_stream_source_tests;
mod wire_sync;
mod wire_sync_types;
#[cfg(test)]
mod wire_tests;
mod wire_types;

use crate::authorization::{AuthorizationError, DeviceAuthorization};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fmt, path::PathBuf};

use codec::{decode, digest, validated_package};
use operation::Operation;
use state::DeviceState;
use store::LockedDevice;

const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 4096;

#[derive(Debug)]
pub struct LabError {
    code: &'static str,
    message: String,
}

impl From<crate::permission::PermissionError> for LabError {
    fn from(error: crate::permission::PermissionError) -> Self {
        Self::new(error.code, error.to_string())
    }
}

impl LabError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn response(&self) -> Value {
        json!({"ok":false,"error":{"code":self.code,"message":self.message}})
    }
}

impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LabError {}

fn checked<T, E: fmt::Display>(code: &'static str, result: Result<T, E>) -> Result<T, LabError> {
    result.map_err(|error| LabError::new(code, error.to_string()))
}

fn ensure(condition: bool, code: &'static str, message: &str) -> Result<(), LabError> {
    if condition {
        Ok(())
    } else {
        Err(LabError::new(code, message))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    service: String,
    account: String,
    device: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    account: String,
    device: String,
    signature_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    account: String,
    device: String,
    signature_key: String,
    key_package: String,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CrashPoint {
    #[default]
    None,
    BeforeSave,
    BeforeRename,
    AfterSave,
}

#[derive(Deserialize)]
struct Request {
    directory: PathBuf,
    service: String,
    account: String,
    device: String,
    #[serde(default)]
    failpoint: CrashPoint,
    #[serde(flatten)]
    operation: Operation,
}

/// 一次调用只处理一个请求；成功输出只包含密文、公开材料和非秘密摘要。
/// failpoint 只用于该实验二进制，直接结束进程来验证原子提交边界。
pub fn execute(input: &str) -> Result<Value, LabError> {
    ensure(input.len() <= 1024 * 1024, "input_limit", "请求超过 1 MiB")?;
    let request: Request = checked("invalid_request", serde_json::from_str(input))?;
    let context = Context {
        service: request.service.clone(),
        account: request.account.clone(),
        device: request.device.clone(),
    };
    for id in [&context.service, &context.account, &context.device] {
        codec::valid_id(id)?;
    }
    let locked = LockedDevice::open(&request.directory)?;
    if let Some(path) = std::env::var_os("RIM_ROLLBACK_ANCHOR_CONFIG") {
        return rollback::execute(&PathBuf::from(path), &locked, request, context);
    }
    execute_locked(&locked, request, context)
}

fn execute_locked(
    locked: &LockedDevice,
    request: Request,
    context: Context,
) -> Result<Value, LabError> {
    if matches!(
        request.operation,
        Operation::RebuildInit { .. } | Operation::RebuildOffer
    ) {
        return rebuild_state::candidate(locked, request, context);
    }
    let state = match locked.load(&context)? {
        Some(state) => state,
        None if matches!(request.operation, Operation::Init) => DeviceState::new(context)?,
        None => return Err(LabError::new("not_initialized", "设备尚未初始化")),
    };
    execute_state(locked, request, state)
}

fn execute_state(
    locked: &LockedDevice,
    request: Request,
    mut state: DeviceState,
) -> Result<Value, LabError> {
    rebuild_state::guard(&state, &request.operation)?;
    wire_send_order::preflight(&state, &request.operation)?;
    wire_stream_source::preflight(&state, &request.operation)?;
    // 已读诊断只观察持久状态，不因读取而提交独立的一致性冲突。
    let read_diagnostic = matches!(
        request.operation,
        Operation::WireReadPending
            | Operation::WireReadInspect
            | Operation::WireReclaimRequest { .. }
            | Operation::WireRetention { .. }
    );
    if !read_diagnostic && consistency_state::preflight(&mut state)? {
        // 发现的是与本次业务输入无关的有效冲突；先持久暂停再拒绝输出新密文。
        locked.save(&mut state, request.failpoint)?;
    }
    consistency_state::guard(&state, &request.operation)?;
    permissions::guard(&state, &request.operation)?;
    let request_digest = digest(&checked(
        "request_encoding",
        serde_json::to_vec(&request.operation),
    )?);
    let cache_key = request.operation.cache_key();
    if let Some(cached) = cache_key
        .as_ref()
        .and_then(|key| state.control_outbox.get(key))
    {
        ensure(
            cached.request_digest == request_digest,
            "conflict",
            "控制操作重复标识对应不同内容",
        )?;
        return Ok(json!({"ok":true,"result":cached.result}));
    }
    let is_wire_read = matches!(request.operation, Operation::WireRead { .. });
    let is_wire_reclaim = matches!(request.operation, Operation::WireReclaim { .. });
    let is_wire_terminal = matches!(
        request.operation,
        Operation::WireClose { .. } | Operation::WireReject { .. }
    );
    let should_save = !matches!(
        request.operation,
        Operation::Inspect
            | Operation::WireCloseRequest { .. }
            | Operation::WireReadPending
            | Operation::WireReadInspect
            | Operation::WireInspect
            | Operation::WireReclaimRequest { .. }
            | Operation::WireRetention { .. }
            | Operation::WireSlotInspect { .. }
            | Operation::PermissionInspect
            | Operation::HistoryInspect
            | Operation::ConsistencyInspect
            | Operation::ConsistencyExchangeInspect
            | Operation::SignAuthorization { .. }
    );
    if should_save {
        consistency_state::record_current(&mut state)?;
    }
    let consistency_result = matches!(
        request.operation,
        Operation::ConsistencyObserveHead { .. }
            | Operation::ConsistencyObserveFork { .. }
            | Operation::ConsistencyResume { .. }
    );
    let mut result = perform(&mut state, request.operation)?;
    if should_save {
        consistency_state::record_current(&mut state)?;
    }
    if consistency_result {
        let duplicate = result["duplicate"].clone();
        result = consistency_state::inspect(&state);
        result["duplicate"] = duplicate;
    }
    if let Some(key) = cache_key {
        ensure(
            state.control_outbox.len() < MAX_RECORDS,
            "resource_limit",
            "控制队列达到上限",
        )?;
        state.control_outbox.insert(
            key,
            state::ControlRecord {
                request_digest,
                result: result.clone(),
            },
        );
    }
    // 迟到的原终态重复只返回已存事实；不能重写快照或倒退当前尾。
    if should_save
        && !(is_wire_terminal && result["duplicate"] == true)
        && !(is_wire_read && result["marked_count"] == 0)
        && !(is_wire_reclaim && result["duplicate"] == true)
    {
        locked.save(&mut state, request.failpoint)?;
    }
    Ok(json!({"ok":true,"result":result}))
}

fn perform(state: &mut DeviceState, operation: Operation) -> Result<Value, LabError> {
    match operation {
        Operation::AnchorInspect
        | Operation::AnchorResume
        | Operation::AnchorRebuild { .. }
        | Operation::AnchorRebuildCancel { .. }
        | Operation::RebuildInit { .. }
        | Operation::RebuildOffer => Err(LabError::new(
            "anchor_required",
            "独立锚操作需要可信启动配置",
        )),
        Operation::RebuildApprove { plan } => rebuild_state::approve(state, plan),
        Operation::RebuildStreamRequest {
            plan,
            approval,
            anchor_request,
            anchor_response,
        } => rebuild_stream::request(state, plan, approval, anchor_request, anchor_response),
        Operation::RebuildStreamBind { binding } => rebuild_stream::bind(state, binding),
        Operation::RebuildStreamPull { limit } => rebuild_stream::pull(state, limit),
        Operation::RebuildStreamDownload {
            page_bytes,
            receipt,
        } => rebuild_stream_sync::download(state, page_bytes, receipt),
        Operation::ConsistencyExchangeBegin {
            source,
            verified_fingerprint,
            verification,
        } => consistency_exchange::begin(state, source, verified_fingerprint, verification),
        Operation::ConsistencyExchangeExport { request, change_id } => {
            exchange_export::export(state, request, change_id)
        }
        Operation::ConsistencyExchangeImport { package } => exchange_import::import(state, package),
        Operation::ConsistencyExchangeCancel => consistency_exchange::cancel(state),
        Operation::ConsistencyExchangeInspect => exchange_state::inspect(state),
        Operation::ConsistencyInspect => Ok(consistency_state::inspect(state)),
        Operation::ConsistencyChallenge => consistency::challenge(state),
        Operation::ConsistencyObserveHead { head } => consistency::observe_head(state, head, false),
        Operation::ConsistencyResume { head } => consistency::observe_head(state, head, true),
        Operation::ConsistencyObserveFork {
            predecessor,
            left,
            right,
        } => consistency::observe_fork(
            state,
            consistency_state::ForkEvidence {
                predecessor,
                left,
                right,
            },
        ),
        Operation::Init => Ok(state.public_identity()),
        Operation::HistoryRequest {
            transfer_id,
            source,
            selection,
            validity_secs,
        } => history_transfer::request(state, transfer_id, source, selection, validity_secs),
        Operation::HistoryExport { request } => history_export::export(state, request),
        Operation::HistoryImport {
            request,
            package,
            receipt,
        } => history_import::import(state, request, package, receipt),
        Operation::HistoryCancel { transfer_id } => history_transfer::cancel(state, transfer_id),
        Operation::HistoryInspect => history_transfer::inspect(state),
        Operation::Create { peers } => groups::create(state, peers),
        Operation::Join { welcome, pins } => groups::join(state, &welcome, pins),
        Operation::Send { id, payload } => messaging::send(state, id, payload),
        Operation::Receive { id, ciphertext } => messaging::receive(state, id, &ciphertext),
        Operation::Remove { id, member } => {
            codec::valid_id(&id)?;
            groups::remove(state, &member)
        }
        Operation::ApplyCommit { commit } => groups::apply_commit(state, &commit),
        Operation::Inspect => state.inspect(),
        Operation::PermissionBootstrap {
            checkpoint,
            relay_receipt_key,
        } => permissions::bootstrap(state, checkpoint, relay_receipt_key),
        Operation::PermissionPrepare {
            change_id,
            action,
            validity_secs,
        } => permissions::prepare(state, change_id, action, validity_secs),
        Operation::PermissionApply { change } => permissions::apply(state, change),
        Operation::PermissionInspect => Ok(permissions::inspect(state)),
        Operation::PermissionPinMember { member } => permission_admission::pin(state, member),
        Operation::PermissionPrepareAdd {
            change_id,
            member,
            key_package,
            history_policy,
            validity_secs,
        } => permission_admission::prepare(
            state,
            change_id,
            member,
            key_package,
            history_policy,
            validity_secs,
            permission_admission::JoinMode::Member,
        ),
        Operation::PermissionPrepareDevice {
            change_id,
            member,
            key_package,
            history_policy,
            validity_secs,
        } => permission_admission::prepare(
            state,
            change_id,
            member,
            key_package,
            history_policy,
            validity_secs,
            permission_admission::JoinMode::Device,
        ),
        Operation::PermissionJoinAnchor {
            checkpoint,
            relay_receipt_key,
        } => permission_join::anchor(
            state,
            checkpoint,
            relay_receipt_key,
            permission_admission::JoinMode::Member,
        ),
        Operation::PermissionDeviceJoinAnchor {
            checkpoint,
            relay_receipt_key,
        } => permission_join::anchor(
            state,
            checkpoint,
            relay_receipt_key,
            permission_admission::JoinMode::Device,
        ),
        Operation::PermissionJoinAdvance { record } => permission_join::advance(state, record),
        Operation::PermissionJoin { record, join } => permission_join::join(state, record, join),
        Operation::PermissionCloseRequest => permission_recovery::close_request(state),
        Operation::PermissionRecover { record } => permission_recovery::recover(state, record),
        Operation::WireConfigure {
            conversation_id,
            authorization_version,
            pending_limit,
        } => {
            if let Some(limit) = pending_limit {
                ensure(
                    (1..=1000).contains(&limit),
                    "resource_exhausted",
                    "待处理队列上限必须是 1—1000",
                )?;
                state.wire_sync.pending_limit = limit;
            }
            wire::configure(state, conversation_id, authorization_version)
        }
        Operation::WireInspect => wire::inspect(state),
        Operation::WireReclaimRequest {
            plan_id,
            acceptance_ids,
        } => wire_reclaim::request(state, plan_id, acceptance_ids),
        Operation::WireReclaim { receipt } => wire_reclaim::execute(state, receipt),
        Operation::WireRetention {
            receipt,
            after_seq,
            limit,
        } => wire_reclaim::retention(state, receipt, after_seq, limit),
        Operation::WireRead { event_ids } => wire_read::mark(state, event_ids),
        Operation::WireReadPending => Ok(wire_read::pending(state)),
        Operation::WireReadInspect => Ok(wire_read::inspect(state)),
        Operation::WireSendOrderEnable => wire_send_order::enable(state),
        Operation::WireReject {
            logical_message_id,
            attempt_id,
            rejection_receipt,
        } => wire_reject::reject(state, logical_message_id, attempt_id, rejection_receipt),
        Operation::WireCloseRequest {
            logical_message_id,
            attempt_id,
        } => wire_close::request(state, logical_message_id, attempt_id),
        Operation::WireClose {
            logical_message_id,
            attempt_id,
            closure_receipt,
        } => wire_close::close(state, logical_message_id, attempt_id, closure_receipt),
        Operation::WireSlotInspect { event_seq } => wire_slot_inspect::inspect(state, &event_seq),
        #[cfg(feature = "wire-sequence-probe")]
        Operation::WireSequenceSeed {
            stream_id,
            base_seq,
        } => wire_sequence_probe::seed(state, &stream_id, &base_seq),
        Operation::WireAccept {
            logical_message_id,
            attempt_id,
            acceptance_receipt,
        } => wire_accept::accept(state, logical_message_id, attempt_id, acceptance_receipt),
        Operation::WireSend {
            logical_message_id,
            attempt_id,
            payload,
            replaces_attempt_id,
            closure_id,
        } => wire::send(
            state,
            logical_message_id,
            attempt_id,
            payload,
            replaces_attempt_id,
            closure_id,
        ),
        Operation::WireReceive {
            header_bytes,
            payload_bytes,
            acceptance_id,
            acceptance_receipt,
        } => wire::receive(
            state,
            wire_types::Envelope {
                header_bytes,
                payload_bytes,
            },
            acceptance_id,
            acceptance_receipt,
        ),
        Operation::WireDownload {
            stream_id,
            events,
            next_after_seq,
            watermark,
            has_more,
        } => wire_sync::download(
            state,
            stream_id,
            events,
            next_after_seq,
            watermark,
            has_more,
        ),
        Operation::WireProcess => wire_sync::process(state),
        Operation::WireDownloadSigned {
            page_bytes,
            receipt,
        } => wire_stream_source::download(state, page_bytes, receipt),
        Operation::WireApplyDependency { control } => wire_sync::apply_dependency(state, control),
        Operation::SignAuthorization { request } => {
            ensure(
                request.service == state.context.service
                    && request.account == state.context.account
                    && request.signer_device == state.context.device,
                "wrong_context",
                "签发者上下文不匹配",
            )?;
            ensure(
                request.expected_roster_version == state.roster.version(),
                "wrong_version",
                "授权前序版本不匹配",
            )?;
            let signed = checked(
                "authorization",
                DeviceAuthorization::sign(request, &state.signer()?),
            )?;
            Ok(json!({"authorization":signed}))
        }
        Operation::Authorize {
            authorization,
            key_package,
            now_unix_secs,
        } => {
            let raw = decode(&key_package)?;
            let package = validated_package(&raw, &state.provider)?;
            let identity = codec::credential_context(package.leaf_node().credential())?;
            ensure(
                identity.service == state.context.service
                    && identity.account == state.context.account
                    && identity.device == authorization.request.new_device,
                "wrong_context",
                "新设备身份上下文不匹配",
            )?;
            state
                .roster
                .apply(
                    &authorization,
                    &raw,
                    package.leaf_node().signature_key().as_slice(),
                    now_unix_secs,
                )
                .map_err(|error| {
                    let code = match error {
                        AuthorizationError::NonceConsumed => "authorization_replay",
                        AuthorizationError::InvalidSignature => "authorization_signature",
                        _ => "authorization",
                    };
                    LabError::new(code, error.to_string())
                })?;
            Ok(json!({"roster_version":state.roster.version(),"device":identity.device}))
        }
    }
}
