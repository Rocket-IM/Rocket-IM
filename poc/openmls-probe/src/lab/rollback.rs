//! 合成独立锚协调：先消耗预约，再加载/执行；恢复只结束已经保存的结果提交。
use super::{
    checked, ensure, execute_state,
    rollback_io::{self, Config},
    store::LockedDevice,
    Context, LabError, Operation, Request,
};
use crate::rollback_anchor::{self as protocol, Action, Status};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

const GATE: &str = "anchor-gate.enc";
const JOURNAL: &str = "anchor-journal.enc";
const GATE_DOMAIN: &str = "Rockets-IM/POC/anchor-gate/v1";
const JOURNAL_DOMAIN: &str = "Rockets-IM/POC/anchor-result/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    reason: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    txn: String,
    head: String,
    target: String,
    request_digest: String,
    reserved_revision: String,
}

fn exists(path: &Path) -> Result<bool, LabError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(LabError::new("anchor_file", error.to_string())),
    }
}

fn pause(config: &Config, directory: &Path, reason: &str) -> Result<(), LabError> {
    config.save(
        &directory.join(GATE),
        GATE_DOMAIN,
        &Gate {
            reason: reason.into(),
        },
    )
}

fn fault(point: &str, exit: i32) {
    if std::env::var("RIM_ANCHOR_FAILPOINT").as_deref() == Ok(point) {
        std::process::exit(exit);
    }
}

pub(super) fn execute(
    path: &Path,
    locked: &LockedDevice,
    request: Request,
    context: Context,
) -> Result<Value, LabError> {
    let config = Config::load(path, &request.directory)?;
    let directory = request.directory.clone();
    // 网络输入可能重复、损坏或迟到。先在临时元数据上复用纯校验，拒绝不消耗预约。
    // 成功预检不授予执行许可；下面仍须独立锚Reserve并重新核对完整快照。
    super::rebuild_stream_sync::preflight(locked, &request, &context)?;
    let result = (|| {
        ensure(
            config.scope.service == context.service
                && config.scope.account == context.account
                && config.scope.device == context.device,
            "anchor_scope",
            "可信锚配置与请求设备范围不匹配",
        )?;
        let head = rollback_io::state_hash(&directory)?;
        match request.operation {
            Operation::AnchorRebuild {
                plan,
                approval,
                successor_directory,
            } => {
                return super::rebuild::execute(
                    &config,
                    locked,
                    &directory,
                    &context,
                    plan,
                    approval,
                    Some(&successor_directory),
                );
            }
            Operation::AnchorRebuildCancel { plan, approval } => {
                return super::rebuild::execute(
                    &config, locked, &directory, &context, plan, approval, None,
                );
            }
            Operation::AnchorInspect => return inspect(&config, &directory, &head),
            Operation::AnchorResume => return resume(&config, &directory, &head),
            Operation::Init => {
                return Err(LabError::new(
                    "anchor_initialization",
                    "已登记范围不能重新初始化或覆盖锚",
                ))
            }
            _ => {}
        }
        ensure(
            !exists(&directory.join(GATE))?,
            "anchor_paused",
            "独立锚门禁已暂停；需显式核验恢复",
        )?;
        // 先保存门禁，任何响应丢失或进程退出都要求显式恢复。
        pause(&config, &directory, "in_progress")?;
        let txn = rollback_io::random_hex()?;
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
        let reserved = config.rpc(Action::Reserve, &txn, &head, "absent", &observed.revision)?;
        ensure(
            reserved.status == Status::Reserved
                && reserved.head == head
                && reserved.active_txn.as_deref() == Some(&txn),
            "anchor_conflict",
            "独立锚拒绝本次唯一预约；旧快照、重复预约或并发冲突不能继续执行",
        )?;
        fault("after_reserve", 86);
        // 只能在预约后恢复 provider；从既有真实身份核对绑定，不信输入中的设备名称。
        let enrolled = locked
            .load_committed(
                &context,
                &checked("anchor_head", protocol::decode_hex(&head))?,
            )?
            .ok_or_else(|| LabError::new("anchor_state", "已登记设备缺少完整快照"))?;
        let identity: String = enrolled
            .own_signature_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        ensure(
            identity == config.scope.identity_key,
            "anchor_identity",
            "设备密码身份与登记公钥不匹配",
        )?;
        let request_digest = protocol::hash_bytes(&checked(
            "anchor_encoding",
            serde_json::to_vec(&request.operation),
        )?);
        // Err 也可能已经消耗内存密码状态；不按旧磁盘摘要释放预约。
        let output = execute_state(locked, request, enrolled)?;
        let target = locked
            .saved_commitment
            .get()
            .map(|value| value.iter().map(|byte| format!("{byte:02x}")).collect())
            .unwrap_or_else(|| head.clone());
        ensure(
            rollback_io::state_hash(&directory)? == target,
            "anchor_state_changed",
            "保存结果已被替换，不能为另一快照创建提交证明",
        )?;
        let journal = Journal {
            txn,
            head,
            target,
            request_digest,
            reserved_revision: reserved.revision,
        };
        config.save(&directory.join(JOURNAL), JOURNAL_DOMAIN, &journal)?;
        fault("after_journal", 87);
        finish(&config, &journal)?;
        fault("after_finish", 88);
        ensure(
            rollback_io::state_hash(&directory)? == journal.target,
            "anchor_state_changed",
            "输出前完整结果已被替换",
        )?;
        clear(&directory)?;
        Ok(output)
    })();
    if let Err(error) = &result {
        // 不能为记录失败覆盖 state.enc；锚本身仍保持单调承诺或未决预约。
        pause(&config, &directory, error.code)?;
    }
    result
}

fn finish(config: &Config, journal: &Journal) -> Result<(), LabError> {
    let response = config.rpc(
        Action::Finish,
        &journal.txn,
        &journal.head,
        &journal.target,
        &journal.reserved_revision,
    )?;
    ensure(
        matches!(
            response.status,
            Status::Finished | Status::FinishedDuplicate
        ) && response.head == journal.target
            && response.active_txn.is_none(),
        "anchor_conflict",
        "独立锚不接受此完整结果，保留暂停",
    )
}

fn clear(directory: &Path) -> Result<(), LabError> {
    // journal先移除；任何清理失败仍保留门禁，当前head可再经新挑战核对。
    rollback_io::remove(&directory.join(JOURNAL))?;
    rollback_io::remove(&directory.join(GATE))?;
    Ok(())
}

fn inspect(config: &Config, directory: &Path, head: &str) -> Result<Value, LabError> {
    let response = config.rpc(
        Action::Inspect,
        &rollback_io::random_hex()?,
        head,
        "absent",
        "0",
    )?;
    ensure(
        response.status == Status::Inspected,
        "anchor_response",
        "锚检查响应类型错误",
    )?;
    let mismatch = response.head != head;
    let active = response.active_txn.is_some();
    if mismatch || active || response.closure.is_some() {
        pause(
            config,
            directory,
            if response.closure.is_some() {
                "sealed"
            } else if active {
                "reserved"
            } else {
                "rollback_detected"
            },
        )?;
    }
    let paused = exists(&directory.join(GATE))?;
    let status = if let Some(closure) = response.closure {
        match closure {
            protocol::Closure::Rebuilt => "sealed",
            protocol::Closure::Cancelled => "cancelled",
        }
    } else if active {
        "reserved"
    } else if mismatch {
        "rollback_detected"
    } else if paused {
        "paused"
    } else {
        "ready"
    };
    let reason = if paused {
        // 损坏辅助记录不会放行；诊断错误保持paused，不假装没有暂停。
        match config.load_record::<Gate>(&directory.join(GATE), GATE_DOMAIN) {
            Ok(gate) => gate.reason,
            Err(_) => "gate_unreadable".into(),
        }
    } else {
        "matched_snapshot".into()
    };
    Ok(
        json!({"ok":true,"result":{"status":status,"reason":reason,"paused":paused,
        "local_head":head,"anchor_head":response.head,"active_txn":response.active_txn,
        "revision":response.revision,"scope":config.scope,"freshness":"unknown"}}),
    )
}

fn resume(config: &Config, directory: &Path, head: &str) -> Result<Value, LabError> {
    let current = config.rpc(
        Action::Inspect,
        &rollback_io::random_hex()?,
        head,
        "absent",
        "0",
    )?;
    ensure(
        current.status == Status::Inspected,
        "anchor_response",
        "锚检查响应类型错误",
    )?;
    ensure(
        current.closure.is_none(),
        "anchor_sealed",
        "此范围已永久封存或取消，不能恢复原执行许可",
    )?;
    if let Some(active) = current.active_txn {
        let journal: Journal = config
            .load_record(&directory.join(JOURNAL), JOURNAL_DOMAIN)
            .map_err(|_| {
                LabError::new(
                    "anchor_unresolved",
                    "预约已消耗但缺少可认证的完整结果；禁止重新执行密码操作",
                )
            })?;
        ensure(
            journal.txn == active
                && journal.head == current.head
                && journal.target == head
                && journal.reserved_revision == current.revision,
            "anchor_unresolved",
            "本机结果与锚未决预约不一致；不能采用旧快照或旧提交记录",
        )?;
        checked(
            "anchor_journal",
            protocol::decode_hex(&journal.request_digest),
        )?;
        finish(config, &journal)?;
    } else {
        ensure(
            current.head == head,
            "anchor_rollback",
            "本机完整快照不等于独立锚当前承诺；无法原地恢复旧状态",
        )?;
    }
    ensure(
        rollback_io::state_hash(directory)? == head,
        "anchor_state_changed",
        "恢复期间快照已被替换",
    )?;
    clear(directory)?;
    Ok(
        json!({"ok":true,"result":{"status":"resumed","local_head":head,
        "freshness":"unknown","scope":config.scope}}),
    )
}
