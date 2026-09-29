//! 预约前校验与本地门共同提交；业务拒绝不产生可遗留的预约。
use super::*;
use crate::crypto::{anchor::rebuild_store, preflight::Input};

impl Store {
    #[cfg(test)]
    pub(crate) fn anchor_begin(&mut self, txn: &str, input: &str) -> Result<Gate> {
        self.anchor_begin_inner(txn, input, false, None)
    }
    pub(crate) fn anchor_begin_rebuild(&mut self, txn: &str, input: &str) -> Result<Gate> {
        self.anchor_begin_inner(txn, input, true, None)
    }
    pub(crate) fn anchor_begin_checked(
        &mut self,
        txn: &str,
        input: &str,
        operation: &Input,
    ) -> Result<Gate> {
        self.anchor_begin_inner(txn, input, false, Some(operation))
    }
    fn anchor_begin_inner(
        &mut self,
        txn: &str,
        input: &str,
        rebuilding: bool,
        operation: Option<&Input>,
    ) -> Result<Gate> {
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
                if rebuilding {
                    let state = rebuild_store::load(tx, &binding.client)?;
                    if state.stage != "linked" {
                        return Err(blocked());
                    }
                } else {
                    rebuild_store::require_active(tx, &binding.client)?;
                }
                let local = load(tx, &binding.client)?;
                if local.gate.is_some() || local.journal.is_some() || query::pending(tx)?.is_some()
                {
                    return Err(blocked());
                }
                // 与本地门写入共用 IMMEDIATE 事务；并发者不能在预检后抢先改变业务 head。
                if let Some(operation) = operation {
                    operation.check(tx, &self.scope)?;
                }
                let gate = Gate {
                    binding: binding.client.fingerprint(),
                    txn: txn.into(),
                    input: input.into(),
                    base: local.head,
                    reserved_revision: None,
                    rebuild_fence: None,
                };
                validate_gate(&gate, &binding.client)?;
                tx.execute(
                    "UPDATE anchor_control SET gate_json=?1 WHERE singleton=1",
                    [binding.client.sign_local(&gate)?],
                )
                .map_err(Error::database)?;
                Ok(gate)
            },
        );
        self.finish(result, false)
    }
}
