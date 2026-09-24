use rusqlite::{OptionalExtension, Transaction};

use crate::model::{revision, valid_id, Error, Record, Result, Scope, Snapshot};

pub(crate) const SCOPE_SCHEMA: &str = "CREATE TABLE scope (id INTEGER NOT NULL PRIMARY KEY CHECK(id=1), service TEXT NOT NULL, account TEXT NOT NULL, revision TEXT NOT NULL)";
pub(crate) const RECORDS_V1: &str =
    "CREATE TABLE records (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)";
pub(crate) const RECORDS_V2: &str = "CREATE TABLE records (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL, updated_revision TEXT NOT NULL DEFAULT '0')";

pub(crate) fn schema_version(tx: &Transaction<'_>) -> Result<u32> {
    let value: i64 = tx
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(Error::database)?;
    u32::try_from(value).map_err(|_| Error::new("schema_mismatch", false))
}

pub(crate) fn storage_mode(tx: &Transaction<'_>) -> Result<(String, i64)> {
    let journal: String = tx
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(Error::database)?;
    let synchronous: i64 = tx
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(Error::database)?;
    if journal != "delete" || synchronous != 2 {
        return Err(Error::new("unsupported_storage_mode", false));
    }
    Ok((journal, synchronous))
}

fn validate_schema(tx: &Transaction<'_>, version: u32) -> Result<()> {
    if !matches!(version, 1 | 2) || schema_version(tx)? != version {
        return Err(Error::new("schema_mismatch", false));
    }
    for (table, expected_sql) in [
        ("scope", SCOPE_SCHEMA),
        (
            "records",
            if version == 1 { RECORDS_V1 } else { RECORDS_V2 },
        ),
    ] {
        let sql: Option<String> = tx
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(Error::database)?;
        // 该隔离格式只接受自己创建的固定 DDL，不能放行相同列名但不同约束或排序规则。
        if sql.as_deref() != Some(expected_sql) {
            return Err(Error::new("schema_mismatch", false));
        }
    }
    let mut statement = tx
        .prepare("SELECT type,name,tbl_name FROM sqlite_schema ORDER BY type,name")
        .map_err(Error::database)?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    let expected_objects = vec![
        ("index", "sqlite_autoindex_records_1", "records"),
        ("table", "records", "records"),
        ("table", "scope", "scope"),
    ];
    if objects
        .iter()
        .map(|(kind, name, table)| (kind.as_str(), name.as_str(), table.as_str()))
        .collect::<Vec<_>>()
        != expected_objects
    {
        return Err(Error::new("schema_mismatch", false));
    }
    validate_columns(
        tx,
        "PRAGMA table_xinfo(scope)",
        &[
            ("id", "INTEGER", 1),
            ("service", "TEXT", 0),
            ("account", "TEXT", 0),
            ("revision", "TEXT", 0),
        ],
    )?;
    let mut columns = vec![("key", "TEXT", 1), ("value", "TEXT", 0)];
    if version == 2 {
        columns.push(("updated_revision", "TEXT", 0));
    }
    validate_columns(tx, "PRAGMA table_xinfo(records)", &columns)
}

fn validate_columns(tx: &Transaction<'_>, sql: &str, expected: &[(&str, &str, i64)]) -> Result<()> {
    let mut statement = tx.prepare(sql).map_err(Error::database)?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    if actual.len() != expected.len()
        || !actual.iter().zip(expected).all(
            |((name, kind, not_null, pk, hidden), (wanted_name, wanted_kind, wanted_pk))| {
                name == wanted_name
                    && kind == wanted_kind
                    && *not_null == 1
                    && pk == wanted_pk
                    && *hidden == 0
            },
        )
    {
        return Err(Error::new("schema_mismatch", false));
    }
    Ok(())
}

pub(crate) fn read_snapshot(tx: &Transaction<'_>, scope: &Scope, version: u32) -> Result<Snapshot> {
    validate_schema(tx, version)?;
    let mut statement = tx
        .prepare("SELECT id,service,account,revision FROM scope ORDER BY id LIMIT 2")
        .map_err(Error::database)?;
    let scopes = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    if scopes.len() != 1 || scopes[0].0 != 1 {
        return Err(Error::new("database_corrupt", false));
    }
    let (_, service, account, current) = &scopes[0];
    if !valid_id(service) || !valid_id(account) {
        return Err(Error::new("database_corrupt", false));
    }
    if service != &scope.service || account != &scope.account {
        return Err(Error::new("scope_mismatch", false));
    }
    let current_revision = revision(current).map_err(|_| Error::new("database_corrupt", false))?;
    let sql = if version == 1 {
        "SELECT key,value FROM records ORDER BY key COLLATE BINARY LIMIT 129"
    } else {
        "SELECT key,value,updated_revision FROM records ORDER BY key COLLATE BINARY LIMIT 129"
    };
    let mut statement = tx.prepare(sql).map_err(Error::database)?;
    let records = statement
        .query_map([], |row| {
            Ok(Record {
                key: row.get(0)?,
                value: row.get(1)?,
                updated_revision: if version == 1 {
                    current.clone()
                } else {
                    row.get(2)?
                },
            })
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    if records.len() > 128 {
        return Err(Error::new("database_corrupt", false));
    }
    for record in &records {
        let updated = revision(&record.updated_revision)
            .map_err(|_| Error::new("database_corrupt", false))?;
        if !valid_id(&record.key)
            || record.value.len() > 4096
            || updated == 0
            || updated > current_revision
        {
            return Err(Error::new("database_corrupt", false));
        }
    }
    let (journal_mode, synchronous) = storage_mode(tx)?;
    let sqlite_version = tx
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .map_err(Error::database)?;
    Ok(Snapshot {
        service: service.clone(),
        account: account.clone(),
        revision: current.clone(),
        schema_version: version,
        records,
        sqlite_version,
        journal_mode,
        synchronous,
    })
}
