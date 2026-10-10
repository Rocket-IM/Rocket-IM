//! 单连接的显式预约与最终提交；任何未决预约都阻止新的密码操作。

use js_sys::Function;
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde_json::Value;

use super::{
    model::hash,
    operations, preflight,
    query::{self, Reservation, State},
    requests::{Action, Request, TestCheckpoint, TestFault},
};
use crate::{
    protocol::{ApiError, Checkpoint, Fault, Scope},
    transaction,
};

pub(crate) use super::schema::initialize_schema;

/// 锚校验与完成日志只能借用当前业务事务，不能自行提交或跨网络等待。
pub(crate) struct Hooks<'a> {
    pub before: &'a dyn Fn(&Transaction<'_>) -> Result<(), ApiError>,
    pub complete: &'a dyn Fn(&Transaction<'_>, Value) -> Result<Value, ApiError>,
}

enum Prepared {
    Cached(Value),
    Reserved(Box<State>, Reservation),
}

pub(crate) fn execute(
    connection: &mut Connection,
    scope: &Scope,
    request: Request,
    hook: Option<&Function>,
) -> Result<Value, ApiError> {
    execute_completed(connection, scope, request, hook, None)
}

pub(crate) fn execute_completed(
    connection: &mut Connection,
    scope: &Scope,
    request: Request,
    hook: Option<&Function>,
    hooks: Option<&Hooks<'_>>,
) -> Result<Value, ApiError> {
    if request.test.checkpoint.is_some() && hook.is_none() {
        return Err(ApiError::invalid());
    }
    if matches!(request.action, Action::Inspect) {
        return transaction::run(
            connection,
            if hooks.is_some() {
                TransactionBehavior::Immediate
            } else {
                TransactionBehavior::Deferred
            },
            Fault::None,
            Checkpoint::None,
            None,
            |tx| {
                if let Some(hooks) = hooks {
                    (hooks.before)(tx)?;
                }
                let pending = query::reservation(tx)?;
                complete(
                    tx,
                    query::load(tx, scope)?.snapshot(scope, pending.as_ref(), "none"),
                    hooks,
                )
            },
        );
    }
    if matches!(request.action, Action::Download { .. }) {
        return download(connection, scope, request, hook, hooks);
    }
    let reserve_fault = if request.test.fault == Some(TestFault::ReserveRefuse) {
        Fault::RefuseCommit
    } else {
        Fault::None
    };
    let prepared = transaction::run(
        connection,
        TransactionBehavior::Immediate,
        reserve_fault,
        Checkpoint::None,
        None,
        |tx| {
            if let Some(hooks) = hooks {
                (hooks.before)(tx)?;
            }
            let (state, cached) = preflight::prepare(tx, scope, &request.action)?;
            if cached {
                return Ok(Prepared::Cached(complete(
                    tx,
                    state.snapshot(scope, None, "none"),
                    hooks,
                )?));
            }
            let attempt_id = match &request.action {
                Action::Send { attempt_id, .. } => attempt_id.clone(),
                Action::ProcessNext => {
                    let sequence = operations::next(&state.processing_cursor)?;
                    state
                        .events
                        .iter()
                        .find(|event| event.sequence == sequence)
                        .map(|event| event.event_id.clone())
                        .ok_or_else(query::corrupt)?
                }
                _ => request.action.operation().into(),
            };
            let reservation = Reservation {
                operation: request.action.operation().into(),
                attempt_id,
                input_hash: hash(query::serialized(&request.action)?.as_bytes()),
                base_revision: state.revision.clone(),
                base_provider_hash: state.provider_hash(),
            };
            tx.execute("INSERT INTO crypto_reservation(singleton, operation, attempt_id, input_hash, base_revision, base_provider_hash)
            VALUES (1, ?1, ?2, ?3, ?4, ?5)", params![reservation.operation, reservation.attempt_id,
            reservation.input_hash, reservation.base_revision, reservation.base_provider_hash]).map_err(ApiError::database)?;
            Ok(Prepared::Reserved(Box::new(state), reservation))
        },
    )?;
    let (mut state, reservation) = match prepared {
        Prepared::Cached(value) => return Ok(value),
        Prepared::Reserved(state, reservation) => (state, reservation),
    };
    if request.test.fault == Some(TestFault::LoseReservationTable) {
        // 仅显式测试的 Send 可到达：预约已提交、MLS 尚未调用；不提供任意 SQL 入口。
        transaction::run(
            connection,
            TransactionBehavior::Immediate,
            Fault::None,
            Checkpoint::None,
            None,
            |tx| {
                tx.execute_batch("DROP TABLE crypto_reservation")
                    .map_err(ApiError::database)
            },
        )?;
        return Err(ApiError::new(
            "crypto_injected_failure",
            "测试预约表丢失；已有密码空间必须拒绝重开。",
            true,
        ));
    }
    if request.test.checkpoint == Some(TestCheckpoint::AfterReserve) {
        transaction::pause_for_termination(hook, "after_reserve", true)?;
    }
    // 仅从已经确认提交的预约推进一次候选，结果从不提前穿过 FFI。
    let change = operations::apply(&mut state, scope, &request.action)?;
    if request.test.fault == Some(TestFault::AfterCrypto) {
        return Err(ApiError::new(
            "crypto_injected_failure",
            "候选密码操作后注入失败，预约保持未决。",
            true,
        ));
    }
    if request.test.checkpoint == Some(TestCheckpoint::AfterCrypto) {
        transaction::pause_for_termination(hook, "after_crypto", true)?;
    }
    state.revision = operations::next(&state.revision)?;
    let fault = if request.test.fault == Some(TestFault::RefuseCommit) {
        Fault::RefuseCommit
    } else {
        Fault::None
    };
    let checkpoint = match request.test.checkpoint {
        Some(TestCheckpoint::BeforeCommit) => Checkpoint::BeforeCommit,
        Some(TestCheckpoint::AfterCommit) => Checkpoint::AfterCommit,
        _ => Checkpoint::None,
    };
    transaction::run(
        connection,
        TransactionBehavior::Immediate,
        fault,
        checkpoint,
        hook,
        |tx| {
            if query::reservation(tx)?.as_ref() != Some(&reservation) {
                return Err(query::corrupt());
            }
            let before = query::load(tx, scope)?;
            if before.revision != reservation.base_revision
                || before.provider_hash() != reservation.base_provider_hash
            {
                return Err(query::corrupt());
            }
            persist(tx, &state)?;
            if request.test.fault == Some(TestFault::AfterSql) {
                tx.execute(
                    "INSERT INTO crypto_intentionally_missing_table(value) VALUES (1)",
                    [],
                )
                .map_err(ApiError::database)?;
                return Err(query::corrupt());
            }
            let result = journal(
                tx,
                &state,
                scope,
                &reservation.operation,
                &reservation.attempt_id,
                &reservation.input_hash,
                change,
            )?;
            if tx
                .execute("DELETE FROM crypto_reservation WHERE singleton = 1", [])
                .map_err(ApiError::database)?
                != 1
            {
                return Err(query::corrupt());
            }
            complete(tx, result, hooks)
        },
    )
}

fn complete(
    tx: &Transaction<'_>,
    value: Value,
    hooks: Option<&Hooks<'_>>,
) -> Result<Value, ApiError> {
    if let Some(hooks) = hooks {
        (hooks.complete)(tx, value)
    } else {
        Ok(value)
    }
}

fn journal(
    tx: &Transaction<'_>,
    state: &State,
    scope: &Scope,
    operation: &str,
    attempt: &str,
    input_hash: &str,
    change: &str,
) -> Result<Value, ApiError> {
    let result = state.snapshot(scope, None, change);
    // 摘要仅记录本次已提交结果，不能充当独立反回滚锚或存储认证。
    tx.execute("INSERT INTO crypto_journal(revision, operation, attempt_id, input_hash, provider_hash, result_hash)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![state.revision, operation, attempt, input_hash,
        state.provider_hash(), hash(query::serialized(&result)?.as_bytes())]).map_err(ApiError::database)?;
    Ok(result)
}

fn download(
    connection: &mut Connection,
    scope: &Scope,
    request: Request,
    hook: Option<&Function>,
    hooks: Option<&Hooks<'_>>,
) -> Result<Value, ApiError> {
    let Action::Download { event } = &request.action else {
        return Err(ApiError::invalid());
    };
    let fault = if request.test.fault == Some(TestFault::RefuseCommit) {
        Fault::RefuseCommit
    } else {
        Fault::None
    };
    let checkpoint = match request.test.checkpoint {
        Some(TestCheckpoint::BeforeCommit) => Checkpoint::BeforeCommit,
        Some(TestCheckpoint::AfterCommit) => Checkpoint::AfterCommit,
        _ => Checkpoint::None,
    };
    transaction::run(
        connection,
        TransactionBehavior::Immediate,
        fault,
        checkpoint,
        hook,
        |tx| {
            if let Some(hooks) = hooks {
                (hooks.before)(tx)?;
            }
            let (mut state, cached) = preflight::prepare(tx, scope, &request.action)?;
            if cached {
                return complete(tx, state.snapshot(scope, None, "none"), hooks);
            }
            let change = operations::apply(&mut state, scope, &request.action)?;
            state.revision = operations::next(&state.revision)?;
            persist(tx, &state)?;
            if request.test.fault == Some(TestFault::AfterSql) {
                tx.execute(
                    "INSERT INTO crypto_intentionally_missing_table(value) VALUES (1)",
                    [],
                )
                .map_err(ApiError::database)?;
                return Err(query::corrupt());
            }
            let value = journal(
                tx,
                &state,
                scope,
                "download",
                &event.event_id,
                &hash(query::serialized(&request.action)?.as_bytes()),
                change,
            )?;
            complete(tx, value, hooks)
        },
    )
}

fn persist(tx: &Transaction<'_>, state: &State) -> Result<(), ApiError> {
    let identity = state.identity.as_ref().map(query::serialized).transpose()?;
    if tx
        .execute(
            "UPDATE crypto_meta SET revision = ?1, identity_json = ?2, conversation = ?3,
        provider = ?4, welcome = ?5, encryptions = ?6, decryptions = ?7, download_cursor = ?8,
        processing_cursor = ?9 WHERE singleton = 1",
            params![
                state.revision,
                identity,
                state.conversation,
                state.provider,
                state.welcome,
                state.encryptions,
                state.decryptions,
                state.download_cursor,
                state.processing_cursor
            ],
        )
        .map_err(ApiError::database)?
        != 1
    {
        return Err(query::corrupt());
    }
    // 集合有严格小上限；完整投影替换与 provider、双游标共用外层同一事务。
    tx.execute_batch(
        "DELETE FROM crypto_outbox; DELETE FROM crypto_events; DELETE FROM crypto_messages;
        DELETE FROM crypto_receipts;",
    )
    .map_err(ApiError::database)?;
    for item in &state.outbox {
        tx.execute(
            "INSERT INTO crypto_outbox(attempt_id, message_id, record_json) VALUES (?1, ?2, ?3)",
            params![item.attempt_id, item.message_id, query::serialized(item)?],
        )
        .map_err(ApiError::database)?;
    }
    for item in &state.events {
        tx.execute(
            "INSERT INTO crypto_events(sequence, event_id, record_json) VALUES (?1, ?2, ?3)",
            params![item.sequence, item.event_id, query::serialized(item)?],
        )
        .map_err(ApiError::database)?;
    }
    for item in &state.messages {
        tx.execute("INSERT INTO crypto_messages(sequence, event_id, message_id, record_json) VALUES (?1, ?2, ?3, ?4)",
            params![item.sequence, item.event_id, item.message_id, query::serialized(item)?]).map_err(ApiError::database)?;
    }
    for item in &state.receipts {
        tx.execute(
            "INSERT INTO crypto_receipts(event_id, record_json) VALUES (?1, ?2)",
            params![item, query::serialized(item)?],
        )
        .map_err(ApiError::database)?;
    }
    Ok(())
}
