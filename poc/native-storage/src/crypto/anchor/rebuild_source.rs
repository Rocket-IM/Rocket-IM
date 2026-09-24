//! 旧范围只封住迟到写入；健康来源通过原锚事务提交真实 Add 及批准证明。
use super::{
    client::Client, commitment, database, error, healthy, protocol, rebuild_protocol::Plan,
    AnchoredClient,
};
use crate::{
    crypto::{
        contract::{Action, Fault, Request},
        engine::Engine,
        model::Identity,
        query,
        store::Store,
        Metrics, Reply,
    },
    model::{Fault as SqlFault, Result},
    transaction,
};
use rusqlite::TransactionBehavior;
use serde_json::{json, Value};

impl AnchoredClient {
    pub fn rebuild_checkpoint(&mut self) -> Reply {
        let mut metrics = Metrics::default();
        let result = (|| {
            let (local, remote) = self.state()?;
            healthy(&local, &remote)?;
            let head = local.head;
            let provider = self
                .inner
                .database
                .call(move |store| store.rebuild_source_provider(&head))?;
            metrics.provider_restores += 1;
            let engine = Engine::restore(&provider, &self.inner.scope)?;
            Ok(
                json!({"checkpoint":engine.checkpoint()?,"identity":engine.identity(),"group_id":engine.group_id()?}),
            )
        })();
        self.inner.reply(result, metrics, vec![])
    }
    /// 显式确认精确计划；签名、Add与Welcome仅经原共同提交和锚Finish后交付。
    pub fn rebuild_approve(
        &mut self,
        plan: Value,
        peer: Identity,
        confirmed: &str,
        fault: Fault,
        anchor_fault: super::contract::AnchorFault,
    ) -> Reply {
        let parsed =
            serde_json::from_value::<Plan>(plan.clone()).map_err(|_| error("rebuild_plan_invalid"));
        let plan = match parsed.and_then(|value| {
            if value.digest()? != confirmed {
                return Err(error("rebuild_confirmation_required"));
            }
            Ok(value)
        }) {
            Ok(value) => value,
            Err(e) => return self.inner.reply(Err(e), Metrics::default(), vec![]),
        };
        let request = Request {
            request_id: plan.rebuild_id.clone(),
            action: Action::RebuildAdd {
                plan: json!(plan),
                peer,
            },
            fault,
        };
        self.run(
            json!({"rebuild_approve":request}),
            "execute",
            anchor_fault,
            move |inner| inner.execute_authorized(request),
        )
    }
}

impl Store {
    pub(crate) fn rebuild_source_provider(&mut self, head: &str) -> Result<Vec<u8>> {
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            SqlFault::None,
            |tx| {
                database::read_head(tx, self.anchor.as_ref(), head)?;
                let meta = query::load(tx, &self.scope)?;
                query::provider(tx, &meta)?.ok_or_else(|| error("crypto_not_initialized"))
            },
        );
        self.finish(result, false)
    }
    /// 同事务确认没有完整日志后封住当前许可；保留原密码预约和全部业务内容。
    pub(crate) fn rebuild_fence(&mut self, old: &Client) -> Result<Value> {
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            SqlFault::None,
            |tx| {
                let local = database::load(tx, old)?;
                if local.journal.is_some() {
                    return Err(error("anchor_recovery_required"));
                }
                let mut gate = local
                    .gate
                    .ok_or_else(|| error("rebuild_old_not_unresolved"))?;
                let reserved = gate
                    .reserved_revision
                    .clone()
                    .ok_or_else(|| error("rebuild_old_not_reserved"))?;
                let pending = query::pending(tx)?;
                if commitment::head(tx, pending.is_some())? != gate.base {
                    return Err(error("anchor_head_mismatch"));
                }
                if let Some(pending) = &pending {
                    let meta = query::load(tx, &self.scope)?;
                    if pending.base_revision != meta.revision
                        || pending.base_provider_hash != meta.provider_hash
                    {
                        return Err(error("rebuild_old_state_changed"));
                    }
                }
                let meta = query::load(tx, &self.scope)?;
                let conversation = meta
                    .conversation
                    .ok_or_else(|| error("rebuild_old_group_required"))?;
                if gate.rebuild_fence.is_none() {
                    gate.rebuild_fence = Some(protocol::random_hex()?);
                    tx.execute(
                        "UPDATE anchor_control SET gate_json=?1 WHERE singleton=1",
                        [old.sign_local(&gate)?],
                    )
                    .map_err(crate::model::Error::database)?;
                }
                Ok(json!({"head":gate.base,"txn":gate.txn,"revision":reserved,
                "conversation":conversation,"local_head":local.head,"fence":gate.rebuild_fence}))
            },
        );
        self.finish(result, false)
    }
}
