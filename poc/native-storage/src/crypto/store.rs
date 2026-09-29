//! 只在数据库线程使用：持久预约确认后才向协调线程交付 provider。
#[path = "download_store.rs"]
mod download;
#[path = "store_open.rs"]
mod opening;
#[path = "persistence.rs"]
pub(crate) mod persistence;

use super::{
    anchor::database as anchor_db,
    contract::{
        validate_id, Action, Candidate, Fault, Inspect, Outcome, Preparation, Prepared,
        ReceiveValue, Request, Reservation, Scope,
    },
    query,
};
use crate::{
    model::{Error, Fault as SqlFault, Result},
    transaction,
};
use rusqlite::{params, Connection, TransactionBehavior};

pub(crate) struct Store {
    pub(super) connection: Connection,
    pub(super) scope: Scope,
    pub(super) paused: bool,
    pub(super) anchor: Option<anchor_db::Binding>,
}

impl Store {
    pub(crate) fn inspect(&mut self) -> Result<Inspect> {
        if !self.connection.is_autocommit() {
            return Err(Error::new("transaction_cleanup_failed", true));
        }
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            SqlFault::None,
            |tx| {
                anchor_db::read_mode(tx, self.anchor.as_ref())?;
                let pending = query::pending(tx)?;
                let meta = query::load(tx, &self.scope)?;
                query::provider(tx, &meta)?;
                query::inspect(&self.scope, meta, pending)
            },
        );
        self.finish(result, false)
    }

    /// 只读取已共同提交的接收结果；未决预约期间也不返回候选正文。
    pub(crate) fn received(&mut self, sequence: &str) -> Result<ReceiveValue> {
        self.received_inner(sequence, None)
    }
    pub(crate) fn received_anchored(
        &mut self,
        sequence: &str,
        expected_head: &str,
    ) -> Result<ReceiveValue> {
        self.received_inner(sequence, Some(expected_head))
    }
    fn received_inner(
        &mut self,
        sequence: &str,
        expected_head: Option<&str>,
    ) -> Result<ReceiveValue> {
        super::contract::receive_sequence(sequence)?;
        if !self.connection.is_autocommit() {
            return Err(Error::new("transaction_cleanup_failed", true));
        }
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            SqlFault::None,
            |tx| {
                if let Some(head) = expected_head {
                    anchor_db::read_head(tx, self.anchor.as_ref(), head)?;
                } else {
                    anchor_db::read_mode(tx, self.anchor.as_ref())?;
                    if self.anchor.is_some() {
                        return Err(Error::new("anchor_required", true));
                    }
                }
                let meta = query::load(tx, &self.scope)?;
                query::receive::value(&meta, sequence)
            },
        );
        // 正常缺失在读事务结束后映射；不会解除本实例已有的密码暂停门。
        self.finish(result, false)?
            .ok_or_else(|| Error::new("receive_not_found", false))
    }

    pub(crate) fn prepare(&mut self, request: &Request) -> Result<Preparation> {
        self.ensure_preparable()?;
        validate_id(&request.request_id)?;
        request.action.validate()?;
        let input_hash = persistence::input_hash(request)?;
        let fault = if request.fault == Fault::ReserveRefuse {
            SqlFault::RefuseCommit
        } else {
            SqlFault::None
        };
        enum Reserved {
            Cached(Outcome),
            Pending(Reservation),
        }
        let reserved = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            fault,
            |tx| {
                anchor_db::before(tx, self.anchor.as_ref(), None)?;
                // 此门必须早于结果缓存、provider BLOB 读取以及所有密码调用。
                if query::pending(tx)?.is_some() {
                    return Err(Error::new("crypto_pending", true));
                }
                let meta = query::load(tx, &self.scope)?;
                if let Some(outcome) =
                    super::preflight::request(&meta, &self.scope, request, &input_hash)?
                {
                    anchor_db::complete(tx, self.anchor.as_ref(), "execute", &outcome)?;
                    return Ok(Reserved::Cached(outcome));
                }
                let reservation = Reservation {
                    request_id: request.request_id.clone(),
                    operation: request.action.operation().into(),
                    input_hash: input_hash.clone(),
                    base_revision: meta.revision,
                    base_provider_hash: meta.provider_hash,
                };
                tx.execute("INSERT INTO crypto_pending(singleton,request_id,operation,input_hash,base_revision,base_provider_hash) VALUES(1,?1,?2,?3,?4,?5)",params![reservation.request_id,reservation.operation,reservation.input_hash,reservation.base_revision,reservation.base_provider_hash]).map_err(Error::database)?;
                Ok(Reserved::Pending(reservation))
            },
        );
        let reservation = match self.finish(reserved, false)? {
            Reserved::Cached(value) => return Ok(Preparation::Cached(value)),
            Reserved::Pending(value) => value,
        };
        // 独立短读事务位于已确认的预约 COMMIT 之后，读取失败仍保留预约。
        let prepared = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            SqlFault::None,
            |tx| {
                let meta = persistence::check_reservation(tx, &self.scope, &reservation)?;
                anchor_db::before(tx, self.anchor.as_ref(), Some(&reservation))?;
                let duplicate = if let Action::Receive { sequence, envelope } = &request.action {
                    query::receive::duplicate(&meta, sequence, envelope)?
                } else {
                    None
                };
                let provider = query::provider(tx, &meta)?;
                Ok(Prepared {
                    reservation,
                    provider,
                    identity: meta.identity,
                    conversation: meta.conversation,
                    encryptions: meta.encryptions,
                    processed_cursor: meta.processed_cursor,
                    decryptions: meta.decryptions,
                    duplicate,
                })
            },
        );
        self.finish(prepared, true)
            .map(|prepared| Preparation::Reserved(Box::new(prepared)))
    }

    pub(crate) fn commit(
        &mut self,
        request: &Request,
        reservation: &Reservation,
        candidate: Candidate,
    ) -> Result<Outcome> {
        self.ensure_active()?;
        let fault = match request.fault {
            Fault::RefuseCommit => SqlFault::RefuseCommit,
            Fault::BeforeCommit => SqlFault::BeforeCommit,
            Fault::AfterCommit => SqlFault::AfterCommit,
            _ => SqlFault::None,
        };
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            fault,
            |tx| {
                persistence::check_reservation(tx, &self.scope, reservation)?;
                anchor_db::before(tx, self.anchor.as_ref(), Some(reservation))?;
                let outcome = persistence::save(tx, &self.scope, request, reservation, candidate)?;
                anchor_db::complete(tx, self.anchor.as_ref(), "execute", &outcome)?;
                Ok(outcome)
            },
        );
        self.finish(result, true)
    }

    pub(crate) fn close(self) -> Result<()> {
        self.connection.close().map_err(|(_, error)| {
            let mut failure = Error::database(error);
            failure.paused = true;
            failure
        })
    }

    fn ensure_preparable(&mut self) -> Result<()> {
        if !self.connection.is_autocommit() {
            return Err(Error::new("transaction_cleanup_failed", true));
        }
        if !self.paused {
            return Ok(());
        }
        // 已收尾但本实例仍暂停时，只诊断持久预约，绝不解除本地门禁或读取 provider。
        let pending = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            SqlFault::None,
            query::pending,
        );
        let pending = self.finish(pending, false)?;
        Err(Error::new(
            if pending.is_some() {
                "crypto_pending"
            } else {
                "crypto_paused"
            },
            true,
        ))
    }

    pub(super) fn ensure_active(&self) -> Result<()> {
        if self.paused || !self.connection.is_autocommit() {
            Err(Error::new("crypto_paused", true))
        } else {
            Ok(())
        }
    }
    pub(super) fn finish<T>(&mut self, result: Result<T>, reserved: bool) -> Result<T> {
        result.map_err(|mut error| {
            if matches!(
                error.code.as_str(),
                "commit_failed" | "transaction_cleanup_failed"
            ) || !self.connection.is_autocommit()
            {
                self.paused = true;
            }
            if reserved || self.paused {
                error.paused = true;
            }
            error
        })
    }
}
