//! 普通、独立锚与重建候选的开库校验；只在所属 Rust 数据库线程执行。
use super::Store;
use crate::{
    crypto::{
        anchor::{client::Client as AnchorClient, database as anchor_db, rebuild_store},
        contract::{validate_id, Scope},
        query, schema,
    },
    diagnostics,
    model::{Error, Fault as SqlFault, Result},
    transaction,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::{fs, path::Path, time::Duration};

impl Store {
    pub(crate) fn open(path: &Path, scope: Scope, create: bool) -> Result<Self> {
        Self::open_inner(path, scope, create, None, None, false, |_| Ok(()))
    }
    pub(crate) fn open_bound(path: &Path, scope: Scope, client: AnchorClient) -> Result<Self> {
        Self::open_inner(path, scope, false, Some(client), None, false, |_| Ok(()))
    }
    pub(crate) fn open_rebuild(
        path: &Path,
        scope: Scope,
        client: AnchorClient,
        slot: Option<rebuild_store::State>,
    ) -> Result<Self> {
        Self::open_inner(
            path,
            scope,
            slot.is_some(),
            Some(client),
            slot,
            true,
            |_| Ok(()),
        )
    }
    #[cfg(feature = "protected-storage")]
    pub(crate) fn open_protected(
        path: &Path,
        scope: Scope,
        create: bool,
        protection: crate::protection::Guard,
    ) -> Result<Self> {
        Self::open_inner(path, scope, create, None, None, false, |connection| {
            protection.install(connection)
        })
    }
    #[cfg(feature = "protected-storage")]
    pub(crate) fn open_protected_bound(
        path: &Path,
        scope: Scope,
        client: AnchorClient,
        protection: crate::protection::Guard,
    ) -> Result<Self> {
        Self::open_inner(
            path,
            scope,
            false,
            Some(client),
            None,
            false,
            |connection| protection.install(connection),
        )
    }
    #[cfg(feature = "protected-storage")]
    pub(crate) fn open_protected_rebuild(
        path: &Path,
        scope: Scope,
        client: AnchorClient,
        slot: Option<rebuild_store::State>,
        protection: crate::protection::Guard,
    ) -> Result<Self> {
        Self::open_inner(
            path,
            scope,
            slot.is_some(),
            Some(client),
            slot,
            true,
            |connection| protection.install(connection),
        )
    }
    fn open_inner(
        path: &Path,
        scope: Scope,
        create: bool,
        mut anchor: Option<AnchorClient>,
        slot: Option<rebuild_store::State>,
        rebuild: bool,
        install: impl FnOnce(&Connection) -> Result<()>,
    ) -> Result<Self> {
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            return Err(Error::new("invalid_path", false));
        }
        for value in [&scope.service, &scope.account, &scope.device] {
            validate_id(value)?;
        }
        if create {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path).map_err(|error| {
                Error::new(
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        "crypto_store_exists"
                    } else {
                        "crypto_store_create_failed"
                    },
                    false,
                )
            })?;
        } else {
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| Error::new("crypto_store_missing", false))?;
            if !metadata.file_type().is_file() || metadata.len() == 0 {
                return Err(Error::new("crypto_store_invalid", true));
            }
        }
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(Error::database)?;
        // 不读取SQLite页就安装保护；第一个显式事务核验真实schema与密钥。
        install(&connection)?;
        diagnostics::install(&connection);
        connection
            .busy_timeout(Duration::from_millis(100))
            .map_err(Error::database)?;
        transaction::run(
            &mut connection,
            TransactionBehavior::Immediate,
            SqlFault::None,
            |tx| {
                if let Some(slot) = &slot {
                    rebuild_store::create(
                        tx,
                        &scope,
                        anchor.as_ref().ok_or_else(schema::corrupt)?,
                        slot,
                    )?;
                } else if create {
                    schema::create(tx, &scope)?;
                } else {
                    schema::validate(tx)?;
                }
                if rebuild {
                    let state =
                        rebuild_store::load(tx, anchor.as_ref().ok_or_else(schema::corrupt)?)?;
                    if state.stage != "initializing" {
                        anchor = Some(rebuild_store::new_client(&state)?);
                    }
                }
                match &anchor {
                    Some(client) => {
                        anchor_db::load(tx, client)?;
                    }
                    None if schema::version(tx)? >= 4 => {
                        return Err(Error::new("anchor_required", true))
                    }
                    None => {}
                }
                let pending = query::pending(tx)?;
                let meta = query::load(tx, &scope)?;
                // 重开仅验证不透明字节；不实例化 OpenMLS，也不删除未决预约。
                query::provider(tx, &meta)?;
                query::inspect(&scope, meta, pending).map(|_| ())
            },
        )?;
        Ok(Self {
            connection,
            scope,
            paused: false,
            anchor: anchor.map(|client| anchor_db::Binding {
                client,
                permit: None,
            }),
        })
    }
}
