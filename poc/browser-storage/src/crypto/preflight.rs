//! 预约前只读业务元数据；锚门与密码预约共用同一组检查，不调用密码引擎。

use rusqlite::Transaction;

use super::{
    operations,
    query::{self, State},
    requests::Action,
};
use crate::protocol::{ApiError, Scope};

pub(crate) fn check(tx: &Transaction<'_>, scope: &Scope, action: &Action) -> Result<(), ApiError> {
    // inspect 保持原诊断语义；其锚门、完成日志和远端确认仍由协调器负责。
    if matches!(action, Action::Inspect) {
        return Ok(());
    }
    prepare(tx, scope, action).map(|_| ())
}

pub(super) fn prepare(
    tx: &Transaction<'_>,
    scope: &Scope,
    action: &Action,
) -> Result<(State, bool), ApiError> {
    // 未决预约先于 provider 读取、幂等返回及所有密码调用，不能因无效输入清除。
    if query::reservation(tx)?.is_some() {
        return Err(ApiError::new(
            "crypto_pending",
            "存在未决密码预约；本实验不提供解锁或重算。",
            false,
        ));
    }
    let state = query::load(tx, scope)?;
    let cached = operations::cached(&state, scope, action)?;
    if !cached {
        journal_capacity(tx)?;
        operations::next(&state.revision)?;
    }
    Ok((state, cached))
}

fn journal_capacity(tx: &Transaction<'_>) -> Result<(), ApiError> {
    let count: u32 = tx
        .query_row("SELECT COUNT(*) FROM crypto_journal", [], |row| row.get(0))
        .map_err(ApiError::database)?;
    if count >= 128 {
        return Err(ApiError::new(
            "crypto_limit",
            "密码实验操作日志达到上限。",
            false,
        ));
    }
    Ok(())
}
