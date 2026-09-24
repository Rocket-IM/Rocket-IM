use js_sys::Function;
use rusqlite::{Connection, Transaction, TransactionBehavior};
use wasm_bindgen::prelude::*;

use crate::protocol::{ApiError, Checkpoint, Fault};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn monotonic_now() -> f64;
}

/// body 中的一致性单元共用 tx；任何结果必须在明确结束事务之后返回。
pub fn run<T>(
    connection: &mut Connection,
    behavior: TransactionBehavior,
    fault: Fault,
    checkpoint: Checkpoint,
    hook: Option<&Function>,
    body: impl FnOnce(&Transaction<'_>) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let tx = connection
        .transaction_with_behavior(behavior)
        .map_err(ApiError::database)?;
    let value = match body(&tx) {
        Ok(value) => value,
        Err(error) => return abort(tx, error),
    };
    if fault == Fault::WriteThenRollback {
        return abort(
            tx,
            ApiError::new("injected_rollback", "测试写入已回滚。", false),
        );
    }
    if checkpoint == Checkpoint::BeforeCommit {
        if let Err(error) = pause_for_termination(hook, "before_commit", false) {
            return abort(tx, error);
        }
    }
    if fault == Fault::RefuseCommit {
        if let Err(error) = tx.commit_hook(Some(|| true)) {
            return abort(tx, ApiError::database(error));
        }
    }
    // 保留 tx 的所有权，以便 COMMIT 失败时显式检查/回滚并报告收尾失败。
    let committed = tx.execute_batch("COMMIT");
    let cleared = tx.commit_hook(None::<fn() -> bool>);
    if let Err(error) = committed {
        return abort(
            tx,
            ApiError::new("commit_failed", "提交未确认，数据空间已暂停。", true).with_sqlite(error),
        );
    }
    if let Err(error) = cleared {
        return abort(
            tx,
            ApiError::new(
                "transaction_cleanup_failed",
                "提交后清理失败，数据空间已暂停。",
                true,
            )
            .with_sqlite(error),
        );
    }
    tx.finish()
        .map_err(|error| cleanup_failed().with_sqlite(error))?;
    if checkpoint == Checkpoint::AfterCommit {
        pause_for_termination(hook, "after_commit", true)?;
    }
    Ok(value)
}

fn abort<T>(tx: Transaction<'_>, error: ApiError) -> Result<T, ApiError> {
    // SQLite 的提交钩子拒绝可能已自动回滚；不对已结束事务再发 ROLLBACK。
    let ended = if tx.is_autocommit() {
        tx.finish()
    } else {
        tx.rollback()
    };
    ended.map_err(|error| cleanup_failed().with_sqlite(error))?;
    Err(error)
}

fn cleanup_failed() -> ApiError {
    ApiError::new(
        "transaction_cleanup_failed",
        "事务收尾失败，数据空间已暂停。",
        true,
    )
}

pub(crate) fn pause_for_termination(
    hook: Option<&Function>,
    phase: &str,
    committed: bool,
) -> Result<(), ApiError> {
    let hook = hook.ok_or_else(ApiError::invalid)?;
    hook.call1(&JsValue::UNDEFINED, &JsValue::from_str(phase))
        .map_err(|error| {
            ApiError::new("checkpoint_failed", "测试检查点通知失败。", committed).with_js(error)
        })?;
    // 仅显式 test_mode 命令可到达：让主线程在真实事务前/后终止 Worker。
    // 有界等待不会出现在普通事务；此通知不代表数据成功。
    let start = monotonic_now();
    while monotonic_now() - start < 2000.0 {
        std::hint::spin_loop();
    }
    Ok(())
}
