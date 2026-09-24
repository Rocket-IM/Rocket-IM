use std::{path::Path, time::Duration};

use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};

use crate::{
    diagnostics,
    model::{revision, valid_id, Error, Fault, OpenOptions, Put, Result, Scope, Snapshot},
    schema::{read_snapshot, schema_version, storage_mode, RECORDS_V1, RECORDS_V2, SCOPE_SCHEMA},
    transaction,
};

pub struct Store {
    connection: Connection,
    scope: Scope,
    schema_version: u32,
    paused: bool,
}

impl Store {
    pub fn open(path: &Path, scope: Scope, options: OpenOptions) -> Result<Self> {
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            return Err(Error::new("invalid_path", false));
        }
        if !valid_id(&scope.service) || !valid_id(&scope.account) {
            return Err(Error::new("invalid_scope", false));
        }
        if options.seed_v1 && options.fail_migration {
            return Err(Error::new("invalid_options", false));
        }
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(Error::database)?;
        diagnostics::install(&connection);
        connection
            .busy_timeout(Duration::from_millis(100))
            .map_err(Error::database)?;
        let schema_version = transaction::run(
            &mut connection,
            TransactionBehavior::Immediate,
            Fault::None,
            |tx| {
                storage_mode(tx)?;
                let mut version = schema_version(tx)?;
                if version == 0 {
                    if options.fail_migration {
                        return Err(Error::new("invalid_options", false));
                    }
                    let objects: i64 = tx
                        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
                        .map_err(Error::database)?;
                    if objects != 0 {
                        return Err(Error::new("schema_mismatch", false));
                    }
                    version = if options.seed_v1 { 1 } else { 2 };
                    tx.execute_batch(SCOPE_SCHEMA).map_err(Error::database)?;
                    tx.execute_batch(if version == 1 { RECORDS_V1 } else { RECORDS_V2 })
                        .map_err(Error::database)?;
                    tx.execute(
                        "INSERT INTO scope (id,service,account,revision) VALUES (1,?1,?2,?3)",
                        params![
                            scope.service,
                            scope.account,
                            if version == 1 { "1" } else { "0" }
                        ],
                    )
                    .map_err(Error::database)?;
                    if version == 1 {
                        tx.execute("INSERT INTO records (key,value) VALUES ('seed','v1')", [])
                            .map_err(Error::database)?;
                        tx.execute_batch("PRAGMA user_version=1")
                            .map_err(Error::database)?;
                    } else {
                        tx.execute_batch("PRAGMA user_version=2")
                            .map_err(Error::database)?;
                    }
                }
                if options.seed_v1 && version != 1 {
                    return Err(Error::new("schema_mismatch", false));
                }
                let prior = read_snapshot(tx, &scope, version)?;
                if version == 1 && !options.seed_v1 {
                    tx.execute_batch(
                        "ALTER TABLE records ADD COLUMN updated_revision TEXT NOT NULL DEFAULT '0'",
                    )
                    .map_err(Error::database)?;
                    tx.execute("UPDATE records SET updated_revision=?1", [&prior.revision])
                        .map_err(Error::database)?;
                    tx.execute_batch("PRAGMA user_version=2")
                        .map_err(Error::database)?;
                    if options.fail_migration {
                        sql_fault(tx)?;
                    }
                    version = 2;
                    read_snapshot(tx, &scope, version)?;
                } else if options.fail_migration {
                    return Err(Error::new("invalid_options", false));
                }
                Ok(version)
            },
        )?;
        Ok(Self {
            connection,
            scope,
            schema_version,
            paused: false,
        })
    }

    pub fn snapshot(&mut self, fault: Fault) -> Result<Snapshot> {
        self.ensure_active()?;
        if !matches!(fault, Fault::None | Fault::ReadAfterSnapshot) {
            return Err(Error::new("invalid_fault", false));
        }
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            Fault::None,
            |tx| {
                let snapshot = read_snapshot(tx, &self.scope, self.schema_version)?;
                if fault == Fault::ReadAfterSnapshot {
                    tx.query_row(
                        "SELECT value FROM rockets_probe_missing_read_table",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(Error::database)?;
                }
                Ok(snapshot)
            },
        );
        self.finish(result)
    }

    pub fn put(&mut self, put: Put) -> Result<Snapshot> {
        self.ensure_active()?;
        if self.schema_version != 2 {
            return Err(Error::new("migration_required", false));
        }
        if put.fault == Fault::ReadAfterSnapshot {
            return Err(Error::new("invalid_fault", false));
        }
        let expected = revision(&put.expected_revision)?;
        if !valid_id(&put.key) {
            return Err(Error::new("invalid_key", false));
        }
        if put.value.len() > 4096 {
            return Err(Error::new("invalid_value", false));
        }
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            put.fault,
            |tx| {
                let previous = read_snapshot(tx, &self.scope, self.schema_version)?;
                if previous.revision != put.expected_revision {
                    return Err(Error::new("revision_conflict", false));
                }
                let next = expected
                    .checked_add(1)
                    .ok_or_else(|| Error::new("revision_exhausted", false))?
                    .to_string();
                if previous.records.len() == 128
                    && !previous.records.iter().any(|record| record.key == put.key)
                {
                    return Err(Error::new("record_limit", false));
                }
                tx.execute("INSERT INTO records (key,value,updated_revision) VALUES (?1,?2,?3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_revision=excluded.updated_revision", params![put.key, put.value, next]).map_err(Error::database)?;
                if put.fault == Fault::SqlAfterWrite {
                    sql_fault(tx)?;
                }
                let changed = tx
                    .execute(
                        "UPDATE scope SET revision=?1 WHERE id=1 AND revision=?2",
                        params![next, put.expected_revision],
                    )
                    .map_err(Error::database)?;
                if changed != 1 {
                    return Err(Error::new("revision_conflict", false));
                }
                read_snapshot(tx, &self.scope, self.schema_version)
            },
        );
        self.finish(result)
    }

    pub fn close(self) -> Result<()> {
        self.connection.close().map_err(|(_, error)| {
            let mut failure = Error::database(error);
            failure.paused = true;
            failure
        })
    }

    fn ensure_active(&self) -> Result<()> {
        if self.paused {
            Err(Error::new("paused", true))
        } else {
            Ok(())
        }
    }

    fn finish<T>(&mut self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result {
            self.paused |= error.paused;
        }
        result
    }
}

fn sql_fault(tx: &Transaction<'_>) -> Result<()> {
    tx.execute(
        "INSERT INTO rockets_probe_missing_table (value) VALUES (1)",
        [],
    )
    .map(|_| ())
    .map_err(Error::database)
}
