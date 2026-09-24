//! 原始下载批次与游标共同提交；与密码 revision、候选计算和明文交付分离。
use super::Store;
use crate::{
    crypto::{
        anchor::database as anchor_db,
        contract::{
            receive_sequence, validate_id, Action, DownloadOutcome, DownloadRequest, Fault, Request,
        },
        model::{self, Envelope},
        query::{self, Meta},
        schema::corrupt,
    },
    model::{revision, Error, Fault as SqlFault, Result},
    transaction,
};
use rusqlite::{params, Transaction, TransactionBehavior};

impl Store {
    pub(crate) fn download(&mut self, request: &DownloadRequest) -> Result<DownloadOutcome> {
        self.ensure_preparable()?;
        request.validate()?;
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
                anchor_db::before(tx, self.anchor.as_ref(), None)?;
                // 下载重试也不能遮盖一次未完成的密码处理。
                if query::pending(tx)?.is_some() {
                    return Err(Error::new("crypto_pending", true));
                }
                let meta = query::load(tx, &self.scope)?;
                if meta.conversation.is_none() {
                    return Err(Error::new("crypto_no_group", false));
                }
                let mut cursor = revision(&meta.download_cursor)?;
                let mut additions = Vec::new();
                for record in &request.records {
                    let envelope = &record.envelope;
                    if envelope.service != self.scope.service
                        || Some(&envelope.conversation) != meta.conversation.as_ref()
                    {
                        return Err(Error::new("crypto_scope_mismatch", false));
                    }
                    if let Some(old) = meta
                        .downloads
                        .iter()
                        .find(|v| v.summary.sequence == record.sequence)
                    {
                        if old.envelope != *envelope {
                            return Err(Error::new("download_sequence_conflict", false));
                        }
                        continue;
                    }
                    if revision(&record.sequence)? != cursor.checked_add(1).ok_or_else(corrupt)? {
                        return Err(Error::new("download_gap", false));
                    }
                    if meta.downloads.len() + additions.len() >= query::LIMIT {
                        return Err(Error::new("crypto_limit", false));
                    }
                    cursor += 1;
                    additions.push(record);
                }
                for record in &additions {
                    insert(tx, &record.sequence, &record.envelope)?;
                    if request.fault == Fault::AfterSql {
                        // 故障位于原始记录写入后、下载游标更新前，核验同一事务回滚。
                        tx.execute(
                            "INSERT INTO crypto_intentionally_missing_table(value) VALUES(1)",
                            [],
                        )
                        .map_err(Error::database)?;
                        return Err(corrupt());
                    }
                }
                if !additions.is_empty() {
                    update_cursor(tx, &meta.download_cursor, &cursor.to_string())?;
                }
                let after = query::load(tx, &self.scope)?;
                let outcome = DownloadOutcome {
                    download_cursor: after.download_cursor,
                    processed_cursor: after.processed_cursor,
                    added: additions.len(),
                    cached: additions.is_empty(),
                };
                anchor_db::complete(tx, self.anchor.as_ref(), "download", &outcome)?;
                Ok(outcome)
            },
        );
        self.finish(result, false)
    }

    /// 宿主只选择序号，密文由 Rust 从已提交的原始记录解析，随后复用接收预约链。
    pub(crate) fn process_request(
        &mut self,
        request_id: &str,
        sequence: &str,
        fault: Fault,
    ) -> Result<Request> {
        self.ensure_preparable()?;
        validate_id(request_id)?;
        receive_sequence(sequence)?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            SqlFault::None,
            |tx| {
                anchor_db::before(tx, self.anchor.as_ref(), None)?;
                if query::pending(tx)?.is_some() {
                    return Err(Error::new("crypto_pending", true));
                }
                let meta = query::load(tx, &self.scope)?;
                Ok(meta
                    .downloads
                    .into_iter()
                    .find(|v| v.summary.sequence == sequence)
                    .map(|record| Request {
                        request_id: request_id.into(),
                        action: Action::Receive {
                            sequence: sequence.into(),
                            envelope: record.envelope,
                        },
                        fault,
                    }))
            },
        );
        self.finish(result, false)?
            .ok_or_else(|| Error::new("download_not_found", false))
    }
}

fn insert(tx: &Transaction<'_>, sequence: &str, envelope: &Envelope) -> Result<()> {
    tx.execute("INSERT INTO crypto_downloads(sequence,envelope_hash,ciphertext_hash,envelope_json) VALUES(?1,?2,?3,?4)", params![sequence, query::receive::envelope_hash(envelope)?, model::hash(&model::decode(&envelope.ciphertext)?), query::serialized(envelope)?]).map_err(Error::database)?;
    Ok(())
}

fn update_cursor(tx: &Transaction<'_>, previous: &str, next: &str) -> Result<()> {
    if tx
        .execute(
            "UPDATE crypto_meta SET download_cursor=?1 WHERE singleton=1 AND download_cursor=?2",
            params![next, previous],
        )
        .map_err(Error::database)?
        != 1
    {
        return Err(corrupt());
    }
    Ok(())
}

/// 旧 Receive 入口在同一最终提交事务中保存原始记录，绝不提前推进下载游标。
pub(super) fn save_receive(
    tx: &Transaction<'_>,
    meta: &Meta,
    sequence: &str,
    envelope: &Envelope,
) -> Result<()> {
    query::download::check_receive(meta, sequence, envelope)?;
    if meta
        .downloads
        .iter()
        .any(|v| v.summary.sequence == sequence)
    {
        return Ok(());
    }
    insert(tx, sequence, envelope)?;
    update_cursor(tx, &meta.download_cursor, sequence)
}
