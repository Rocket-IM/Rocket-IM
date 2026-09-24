use js_sys::Function;
use rusqlite::{params, Connection, Transaction, TransactionBehavior};

use crate::{
    protocol::{
        parse_revision, validate_id, ApiError, Checkpoint, Fault, Put, Record, Scope, Snapshot,
        MAX_RECORDS, MAX_VALUE_BYTES,
    },
    transaction,
};

pub fn initialize(
    connection: &mut Connection,
    scope: &Scope,
    seed_v1: bool,
    fail_migration: bool,
) -> Result<(), ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Immediate,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| {
            let version = schema_version(tx)?;
            match version {
                0 => {
                    if fail_migration {
                        return Err(ApiError::new(
                            "migration_requires_v1",
                            "迁移故障需要已有 v1 数据库。",
                            false,
                        ));
                    }
                    create_schema(tx, scope, seed_v1)?;
                }
                1 => {
                    validate_schema(tx, 1)?;
                    read_snapshot(tx, scope)?;
                    if !seed_v1 {
                        tx.execute_batch("ALTER TABLE records ADD COLUMN updated_revision TEXT NOT NULL DEFAULT '0';
                        UPDATE records SET updated_revision = (SELECT revision FROM scope_state WHERE singleton = 1);
                        PRAGMA user_version = 2;")
                        .map_err(ApiError::database)?;
                        validate_schema(tx, 2)?;
                        if fail_migration {
                            return Err(ApiError::new(
                                "migration_failed",
                                "测试迁移已回滚。",
                                false,
                            ));
                        }
                    }
                }
                2 => {
                    if seed_v1 {
                        return Err(ApiError::new(
                            "seed_requires_v1_or_empty",
                            "v1 测试不能覆盖现有 v2 数据库。",
                            false,
                        ));
                    }
                    if fail_migration {
                        return Err(ApiError::new(
                            "migration_requires_v1",
                            "迁移故障需要已有 v1 数据库。",
                            false,
                        ));
                    }
                }
                _ => {
                    return Err(ApiError::new(
                        "unsupported_schema",
                        "数据库版本不受支持。",
                        true,
                    ))
                }
            }
            let version = schema_version(tx)?;
            validate_schema(tx, version)?;
            read_snapshot(tx, scope)?;
            Ok(())
        },
    )
}

fn create_schema(tx: &Transaction<'_>, scope: &Scope, seed_v1: bool) -> Result<(), ApiError> {
    // 初始化结构、账号归属、数据和版本必须在外层同一个显式事务提交。
    tx.execute_batch(
        "CREATE TABLE scope_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        service TEXT NOT NULL, account TEXT NOT NULL, revision TEXT NOT NULL);
        CREATE TABLE records (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
        PRAGMA user_version = 1;",
    )
    .map_err(ApiError::database)?;
    tx.execute(
        "INSERT INTO scope_state(singleton, service, account, revision) VALUES (1, ?1, ?2, ?3)",
        params![
            scope.service,
            scope.account,
            if seed_v1 { "1" } else { "0" }
        ],
    )
    .map_err(ApiError::database)?;
    if seed_v1 {
        tx.execute(
            "INSERT INTO records(key, value) VALUES (?1, ?2)",
            params!["seed", "from-v1"],
        )
        .map_err(ApiError::database)?;
    } else {
        tx.execute_batch("ALTER TABLE records ADD COLUMN updated_revision TEXT NOT NULL DEFAULT '0'; PRAGMA user_version = 2;")
            .map_err(ApiError::database)?;
    }
    Ok(())
}

pub fn snapshot(connection: &mut Connection, scope: &Scope) -> Result<Snapshot, ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Deferred,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| read_snapshot(tx, scope),
    )
}

pub fn read_fault(connection: &mut Connection, scope: &Scope) -> Result<Snapshot, ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Deferred,
        Fault::None,
        Checkpoint::None,
        None,
        |tx| {
            let snapshot = read_snapshot(tx, scope)?;
            // 仅测试命令可达：先完成真实读取，再由不存在的固定表触发 SQL 错误。
            // 不改表或伪造失败结果，交由统一事务入口回滚，快照不得提前交付。
            tx.query_row(
                "SELECT value FROM __rockets_probe_missing_read_table",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(ApiError::database)?;
            Ok(snapshot)
        },
    )
}

pub fn put(
    connection: &mut Connection,
    scope: &Scope,
    put: Put,
    hook: Option<&Function>,
) -> Result<Snapshot, ApiError> {
    transaction::run(
        connection,
        TransactionBehavior::Immediate,
        put.fault,
        put.checkpoint,
        hook,
        |tx| {
            let current = read_snapshot(tx, scope)?;
            if current.schema_version != 2 {
                return Err(ApiError::new(
                    "migration_required",
                    "v1 测试库需要关闭后正常打开以完成迁移。",
                    false,
                ));
            }
            if current.revision != put.expected_revision {
                return Err(ApiError::new(
                    "revision_conflict",
                    "数据版本已改变，请先重新查询。",
                    false,
                ));
            }
            if current.records.len() >= MAX_RECORDS
                && !current.records.iter().any(|record| record.key == put.key)
            {
                return Err(ApiError::new(
                    "capacity_exceeded",
                    "记录数量达到上限。",
                    false,
                ));
            }
            let revision = parse_revision(&current.revision)?
                .checked_add(1)
                .ok_or_else(|| ApiError::new("revision_exhausted", "版本号已耗尽。", false))?
                .to_string();
            tx.execute("INSERT INTO records(key, value, updated_revision) VALUES (?1, ?2, ?3)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_revision = excluded.updated_revision",
            params![put.key, put.value, revision]).map_err(ApiError::database)?;
            let updated = tx
                .execute(
                    "UPDATE scope_state SET revision = ?1 WHERE singleton = 1 AND revision = ?2",
                    params![revision, current.revision],
                )
                .map_err(ApiError::database)?;
            if updated != 1 {
                return Err(corrupt());
            }
            read_snapshot(tx, scope)
        },
    )
}

fn schema_version(tx: &Transaction<'_>) -> Result<u32, ApiError> {
    tx.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(ApiError::database)
}

fn validate_schema(tx: &Transaction<'_>, version: u32) -> Result<(), ApiError> {
    let mut statement = tx
        .prepare("PRAGMA table_info(records)")
        .map_err(ApiError::database)?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(ApiError::database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::database)?;
    let expected: &[&str] = match version {
        1 => &["key", "value"],
        2 => &["key", "value", "updated_revision"],
        _ => return Err(corrupt()),
    };
    if names != expected {
        return Err(corrupt());
    }
    Ok(())
}

fn read_snapshot(tx: &Transaction<'_>, scope: &Scope) -> Result<Snapshot, ApiError> {
    let version = schema_version(tx)?;
    validate_schema(tx, version)?;
    let (service, account, revision) = tx
        .query_row(
            "SELECT service, account, revision FROM scope_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(ApiError::database)?;
    if service != scope.service || account != scope.account || parse_revision(&revision).is_err() {
        return Err(corrupt());
    }
    let mut statement = tx
        .prepare("SELECT key, value FROM records ORDER BY key LIMIT ?1")
        .map_err(ApiError::database)?;
    let records = statement
        .query_map([MAX_RECORDS as i64 + 1], |row| {
            Ok(Record {
                key: row.get(0)?,
                value: row.get(1)?,
            })
        })
        .map_err(ApiError::database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::database)?;
    if records.len() > MAX_RECORDS
        || records
            .iter()
            .any(|record| validate_id(&record.key).is_err() || record.value.len() > MAX_VALUE_BYTES)
    {
        return Err(corrupt());
    }
    Ok(Snapshot {
        service,
        account,
        schema_version: version,
        revision,
        records,
        sqlite_version: rusqlite::version().into(),
    })
}

fn corrupt() -> ApiError {
    ApiError::new("storage_corrupt", "数据结构、归属或保存状态不合法。", true)
}
