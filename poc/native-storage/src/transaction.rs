use rusqlite::{Connection, DropBehavior, Transaction, TransactionBehavior};

use crate::{
    diagnostics,
    model::{Error, Fault, Result},
};

fn cleanup(mut transaction: Transaction<'_>, rollback: bool) -> Result<()> {
    if rollback {
        if transaction.is_autocommit() {
            diagnostics::automatic_rollback();
        } else if let Err(error) = transaction.execute_batch("ROLLBACK") {
            let mut failure = Error::database(error);
            failure.code = "transaction_cleanup_failed".to_owned();
            failure.paused = true;
            // 禁止 Drop 再次悄悄重试并吞错；保留连接的失败状态，由暂停门禁阻止复用。
            transaction.set_drop_behavior(DropBehavior::Ignore);
            transaction.finish().map_err(|error| {
                let mut failure = Error::database(error);
                failure.code = "transaction_cleanup_failed".to_owned();
                failure.paused = true;
                failure
            })?;
            return Err(failure);
        }
    }
    transaction.finish().map_err(|error| {
        let mut failure = Error::database(error);
        failure.code = "transaction_cleanup_failed".to_owned();
        failure.paused = true;
        failure
    })
}

pub(crate) fn run<T>(
    connection: &mut Connection,
    behavior: TransactionBehavior,
    fault: Fault,
    body: impl FnOnce(&Transaction<'_>) -> Result<T>,
) -> Result<T> {
    let transaction = connection
        .transaction_with_behavior(behavior)
        .map_err(Error::database)?;
    let value = match body(&transaction) {
        Ok(value) => value,
        Err(error) => {
            cleanup(transaction, true)?;
            return Err(error);
        }
    };
    if fault == Fault::BeforeCommit {
        let error = diagnostics::checkpoint("before_commit");
        cleanup(transaction, true)?;
        error?;
        return Err(Error::new("checkpoint_unexpected_return", true));
    }
    if fault == Fault::RefuseCommit {
        if let Err(error) = transaction.commit_hook(Some(|| true)) {
            cleanup(transaction, true)?;
            return Err(Error::database(error));
        }
    }
    // 不消费 Transaction，COMMIT 出错后仍能判断自动回滚与显式收尾。
    let commit = transaction.execute_batch("COMMIT");
    let hook_clear = transaction.commit_hook(None::<fn() -> bool>);
    let cleanup_result = cleanup(transaction, commit.is_err());
    cleanup_result?;
    hook_clear.map_err(|error| {
        let mut failure = Error::database(error);
        failure.code = "transaction_cleanup_failed".to_owned();
        failure.paused = true;
        failure
    })?;
    commit.map_err(|error| {
        let mut failure = Error::database(error);
        failure.code = "commit_failed".to_owned();
        failure.paused = true;
        failure
    })?;
    if fault == Fault::AfterCommit {
        diagnostics::checkpoint("after_commit")?;
    }
    Ok(value)
}
