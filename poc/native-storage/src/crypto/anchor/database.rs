//! 锚的本地门与恢复日志：签名内容只在所属业务事务内保存。
#[path = "begin.rs"]
mod begin;
use rusqlite::{Transaction, TransactionBehavior};
use serde::Serialize;

use super::{
    client::Client,
    commitment,
    contract::{Gate, Journal, Local, StoredResult},
};
use crate::{
    crypto::{contract::Reservation, model, query, schema, store::Store},
    model::{Error, Fault, Result},
    transaction,
};

pub(crate) struct Binding {
    pub(crate) client: Client,
    pub(crate) permit: Option<Gate>,
}
fn blocked() -> Error {
    Error::new("anchor_local_unresolved", true)
}
fn mismatch() -> Error {
    Error::new("anchor_binding_mismatch", true)
}

pub(crate) fn read_mode(tx: &Transaction<'_>, binding: Option<&Binding>) -> Result<()> {
    if let Some(binding) = binding {
        load(tx, &binding.client).map(|_| ())
    } else if schema::version(tx)? >= 4 {
        Err(Error::new("anchor_required", true))
    } else {
        Ok(())
    }
}
pub(crate) fn read_head(
    tx: &Transaction<'_>,
    binding: Option<&Binding>,
    expected_head: &str,
) -> Result<()> {
    let binding = binding.ok_or_else(|| Error::new("anchor_binding_missing", true))?;
    super::rebuild_store::require_active(tx, &binding.client)?;
    let local = load(tx, &binding.client)?;
    if local.head != expected_head {
        return Err(Error::new("anchor_head_mismatch", true));
    }
    if local.gate.is_some() || local.journal.is_some() || query::pending(tx)?.is_some() {
        return Err(blocked());
    }
    Ok(())
}

pub(crate) fn load(tx: &Transaction<'_>, client: &Client) -> Result<Local> {
    schema::validate(tx)?;
    if !matches!(schema::version(tx)?, 4 | 5) {
        return Err(Error::new("anchor_binding_missing", true));
    }
    if schema::version(tx)? == 5 {
        super::rebuild_store::load(tx, client)?;
    }
    let oversized: i64 = tx.query_row("SELECT count(*) FROM anchor_control WHERE length(binding)>64 OR length(gate_json)>262144 OR length(journal_json)>524288", [], |row| row.get(0)).map_err(Error::database)?;
    if oversized != 0 {
        return Err(blocked());
    }
    let mut statement = tx
        .prepare("SELECT singleton,binding,gate_json,journal_json FROM anchor_control LIMIT 2")
        .map_err(Error::database)?;
    let values = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(Error::database)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::database)?;
    if values.len() != 1 {
        return Err(mismatch());
    }
    let (singleton, binding, gate, journal) = &values[0];
    if *singleton != 1 || binding != &client.fingerprint() {
        return Err(mismatch());
    }
    let gate: Option<Gate> = gate
        .as_deref()
        .map(|text| client.verify_local(text))
        .transpose()?;
    let journal: Option<Journal> = journal
        .as_deref()
        .map(|text| client.verify_local(text))
        .transpose()?;
    if let Some(gate) = &gate {
        validate_gate(gate, client)?;
    }
    if let Some(journal) = &journal {
        if gate.as_ref() != Some(&journal.gate)
            || !query::valid_hash(&journal.target)
            || !matches!(journal.result.kind.as_str(), "execute" | "download")
        {
            return Err(blocked());
        }
    }
    Ok(Local {
        head: commitment::head(tx, false)?,
        gate,
        journal,
    })
}
fn validate_gate(gate: &Gate, client: &Client) -> Result<()> {
    if gate.binding != client.fingerprint()
        || !crate::model::valid_id(&gate.txn)
        || !query::valid_hash(&gate.base)
        || !query::valid_hash(&gate.input)
    {
        return Err(blocked());
    }
    if let Some(revision) = &gate.reserved_revision {
        crate::model::revision(revision).map_err(|_| blocked())?;
    }
    Ok(())
}
fn active<'a>(tx: &Transaction<'_>, binding: &'a Binding) -> Result<&'a Gate> {
    let permit = binding.permit.as_ref().ok_or_else(blocked)?;
    let local = load(tx, &binding.client)?;
    if local.gate.as_ref() != Some(permit)
        || local.journal.is_some()
        || permit.reserved_revision.is_none()
    {
        return Err(blocked());
    }
    Ok(permit)
}
/// 首次读或写与缓存命中均须经过；已有密码预约仅在先核对精确预约后投影为空表。
pub(crate) fn before(
    tx: &Transaction<'_>,
    binding: Option<&Binding>,
    pending: Option<&Reservation>,
) -> Result<()> {
    let Some(binding) = binding else {
        if schema::version(tx)? >= 4 {
            return Err(Error::new("anchor_required", true));
        }
        return Ok(());
    };
    super::rebuild_store::require_active(tx, &binding.client)?;
    let gate = active(tx, binding)?;
    if query::pending(tx)?.as_ref() != pending {
        return Err(Error::new("crypto_pending", true));
    }
    if commitment::head(tx, pending.is_some())? != gate.base {
        return Err(Error::new("anchor_head_mismatch", true));
    }
    Ok(())
}
pub(crate) fn complete<T: Serialize>(
    tx: &Transaction<'_>,
    binding: Option<&Binding>,
    kind: &str,
    value: &T,
) -> Result<()> {
    let Some(binding) = binding else {
        return Ok(());
    };
    let gate = active(tx, binding)?.clone();
    if query::pending(tx)?.is_some() {
        return Err(blocked());
    }
    let journal = Journal {
        gate,
        target: commitment::head(tx, false)?,
        result: StoredResult {
            kind: kind.into(),
            value: serde_json::to_value(value).map_err(|_| blocked())?,
        },
    };
    if tx
        .execute(
            "UPDATE anchor_control SET journal_json=?1 WHERE singleton=1 AND journal_json IS NULL",
            [binding.client.sign_local(&journal)?],
        )
        .map_err(Error::database)?
        != 1
    {
        return Err(blocked());
    }
    Ok(())
}

impl Store {
    pub(crate) fn bind_anchor(&mut self, client: &Client) -> Result<Local> {
        self.ensure_active()?;
        if self.anchor.is_some() {
            return Err(Error::new("anchor_already_bound", true));
        }
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            Fault::None,
            |tx| {
                schema::validate(tx)?;
                if schema::version(tx)? != 3 {
                    return Err(Error::new("anchor_already_bound", true));
                }
                if query::pending(tx)?.is_some() {
                    return Err(Error::new("crypto_pending", true));
                }
                let meta = query::load(tx, &self.scope)?;
                let identity = meta
                    .identity
                    .ok_or_else(|| Error::new("crypto_not_initialized", false))?;
                let identity_key = model::decode(&identity.identity_key)?
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let expected = client.scope();
                if expected.service != self.scope.service
                    || expected.account != self.scope.account
                    || expected.device != self.scope.device
                    || expected.identity_key != identity_key
                {
                    return Err(mismatch());
                }
                tx.execute_batch(schema::ANCHOR_CONTROL)
                    .map_err(Error::database)?;
                tx.execute(
                    "INSERT INTO anchor_control(singleton,binding) VALUES(1,?1)",
                    [client.fingerprint()],
                )
                .map_err(Error::database)?;
                tx.execute(
                    "UPDATE crypto_meta SET format=?1 WHERE singleton=1",
                    [schema::ANCHOR_FORMAT],
                )
                .map_err(Error::database)?;
                tx.execute_batch("PRAGMA user_version=4")
                    .map_err(Error::database)?;
                load(tx, client)
            },
        );
        let local = self.finish(result, false)?;
        self.anchor = Some(Binding {
            client: client.clone(),
            permit: None,
        });
        Ok(local)
    }
    pub(crate) fn anchor_local(&mut self) -> Result<Local> {
        let binding = self
            .anchor
            .as_ref()
            .ok_or_else(|| Error::new("anchor_binding_missing", true))?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            Fault::None,
            |tx| load(tx, &binding.client),
        );
        self.finish(result, false)
    }
    pub(crate) fn anchor_reserved(&mut self, gate: &Gate, revision: &str) -> Result<Gate> {
        self.ensure_active()?;
        let binding = self
            .anchor
            .as_ref()
            .ok_or_else(|| Error::new("anchor_binding_missing", true))?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            Fault::None,
            |tx| {
                let local = load(tx, &binding.client)?;
                if local.gate.as_ref() != Some(gate)
                    || local.journal.is_some()
                    || local.head != gate.base
                    || gate.reserved_revision.is_some()
                    || query::pending(tx)?.is_some()
                {
                    return Err(blocked());
                }
                let mut reserved = gate.clone();
                reserved.reserved_revision = Some(revision.into());
                validate_gate(&reserved, &binding.client)?;
                tx.execute(
                    "UPDATE anchor_control SET gate_json=?1 WHERE singleton=1",
                    [binding.client.sign_local(&reserved)?],
                )
                .map_err(Error::database)?;
                Ok(reserved)
            },
        );
        self.finish(result, false)
    }
    pub(crate) fn anchor_activate(&mut self, gate: &Gate) -> Result<()> {
        self.ensure_active()?;
        let binding = self
            .anchor
            .as_ref()
            .ok_or_else(|| Error::new("anchor_binding_missing", true))?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            Fault::None,
            |tx| {
                let local = load(tx, &binding.client)?;
                if local.gate.as_ref() != Some(gate)
                    || local.journal.is_some()
                    || local.head != gate.base
                    || gate.reserved_revision.is_none()
                    || query::pending(tx)?.is_some()
                {
                    return Err(blocked());
                }
                Ok(())
            },
        );
        self.finish(result, false)?;
        self.anchor.as_mut().ok_or_else(blocked)?.permit = Some(gate.clone());
        Ok(())
    }
    /// 只接受已持久化、签名匹配的最终日志；绝不提供清空未决门的捷径。
    pub(crate) fn anchor_clear(&mut self, gate: &Gate, target: &str) -> Result<()> {
        let binding = self
            .anchor
            .as_ref()
            .ok_or_else(|| Error::new("anchor_binding_missing", true))?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            Fault::None,
            |tx| {
                let local = load(tx, &binding.client)?;
                let journal = local.journal.ok_or_else(blocked)?;
                if local.gate.as_ref() != Some(gate)
                    || journal.gate != *gate
                    || journal.target != target
                    || local.head != target
                    || query::pending(tx)?.is_some()
                {
                    return Err(blocked());
                }
                tx.execute(
                    "UPDATE anchor_control SET gate_json=NULL,journal_json=NULL WHERE singleton=1",
                    [],
                )
                .map_err(Error::database)?;
                Ok(())
            },
        );
        self.finish(result, false)?;
        self.anchor.as_mut().ok_or_else(blocked)?.permit = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "database_tests.rs"]
mod tests;
