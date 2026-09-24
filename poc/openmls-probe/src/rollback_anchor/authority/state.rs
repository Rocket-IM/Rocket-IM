//! 单范围预约寄存器及单层后继路由；所有冲突保持原有承诺。
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rollback_anchor) struct Transaction {
    pub(in crate::rollback_anchor) txn: String,
    pub(in crate::rollback_anchor) base: String,
    pub(in crate::rollback_anchor) target: String,
    pub(in crate::rollback_anchor) reservation_revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rollback_anchor) struct State {
    pub(in crate::rollback_anchor) protocol_version: String,
    pub(in crate::rollback_anchor) scope: Scope,
    pub(in crate::rollback_anchor) client_public_key: String,
    pub(in crate::rollback_anchor) anchor_seed: String,
    pub(in crate::rollback_anchor) head: String,
    pub(in crate::rollback_anchor) revision: u64,
    pub(in crate::rollback_anchor) active: Option<Transaction>,
    pub(in crate::rollback_anchor) last: Option<Transaction>,
    #[serde(default)]
    pub(in crate::rollback_anchor) rebuild_trust: Option<rebuild::RebuildTrust>,
    #[serde(default)]
    pub(in crate::rollback_anchor) rebuild_link: Option<rebuild::Link>,
}

impl State {
    pub(in crate::rollback_anchor) fn validate(&self) -> Result<(), AnchorError> {
        if self.protocol_version != PROTOCOL {
            return Err(invalid());
        }
        self.scope.validate()?;
        decode_hex(&self.client_public_key)?;
        decode_hex(&self.anchor_seed)?;
        validate_head(&self.head)?;
        if let Some(active) = &self.active {
            decode_hex(&active.txn)?;
            if active.base != self.head
                || active.target != "absent"
                || active.reservation_revision != self.revision
                || active.reservation_revision == 0
            {
                return Err(invalid());
            }
        }
        if let Some(last) = &self.last {
            decode_hex(&last.txn)?;
            validate_head(&last.base)?;
            decode_hex(&last.target)?;
            if last.target != self.head
                || last.reservation_revision == 0
                || last.reservation_revision >= self.revision
                || self.active.as_ref().is_some_and(|a| a.txn == last.txn)
            {
                return Err(invalid());
            }
        }
        rebuild::validate_link(self)
    }

    /// 所有冲突与重复保持原状态；仅首次 reserve/finish 推进修订号。
    pub(in crate::rollback_anchor) fn apply(
        &mut self,
        request: &Request,
    ) -> Result<(Status, bool), AnchorError> {
        if request.scope != self.scope {
            return Err(AnchorError::new("anchor_scope", "请求与独立锚固定范围不同"));
        }
        let expected_revision = validate_revision(&request.expected_revision)?;
        if self.rebuild_link.is_some() && request.action != Action::Inspect {
            return Ok((Status::Conflict, false));
        }
        let status = match request.action {
            Action::Inspect => return Ok((Status::Inspected, false)),
            Action::Reserve => {
                if let Some(active) = &self.active {
                    let status = if active.txn == request.txn
                        && active.base == request.head
                        && active.reservation_revision.checked_sub(1) == Some(expected_revision)
                    {
                        Status::ReservedDuplicate
                    } else {
                        Status::Conflict
                    };
                    return Ok((status, false));
                }
                if self.head != request.head
                    || self.revision != expected_revision
                    || self.last.as_ref().is_some_and(|t| t.txn == request.txn)
                {
                    return Ok((Status::Conflict, false));
                }
                if self.revision > u64::MAX - 2 {
                    return Err(AnchorError::new(
                        "anchor_capacity",
                        "锚修订号不足以预约并完成，保持暂停",
                    ));
                }
                Status::Reserved
            }
            Action::Finish => {
                if self.last.as_ref().is_some_and(|t| {
                    t.txn == request.txn
                        && t.base == request.head
                        && t.target == request.target
                        && t.reservation_revision == expected_revision
                }) {
                    return Ok((Status::FinishedDuplicate, false));
                }
                if !self.active.as_ref().is_some_and(|t| {
                    t.txn == request.txn
                        && t.base == request.head
                        && t.reservation_revision == expected_revision
                }) {
                    return Ok((Status::Conflict, false));
                }
                Status::Finished
            }
        };
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| AnchorError::new("anchor_capacity", "锚修订号达到上限，保持暂停"))?;
        let transaction = Transaction {
            txn: request.txn.clone(),
            base: request.head.clone(),
            target: request.target.clone(),
            reservation_revision: if request.action == Action::Reserve {
                revision
            } else {
                expected_revision
            },
        };
        match request.action {
            Action::Reserve => self.active = Some(transaction),
            Action::Finish => {
                self.head = request.target.clone();
                self.last = Some(transaction);
                self.active = None;
            }
            Action::Inspect => return Err(invalid()),
        }
        self.revision = revision;
        Ok((status, true))
    }

    pub(super) fn register(&self, scope: &Scope) -> Result<&Self, AnchorError> {
        if *scope == self.scope {
            return Ok(self);
        }
        self.rebuild_link
            .as_ref()
            .filter(|link| link.child.scope == *scope)
            .map(|link| link.child.as_ref())
            .ok_or_else(|| AnchorError::new("anchor_scope", "请求与独立锚固定范围不同"))
    }

    pub(super) fn route(&mut self, request: &Request) -> Result<(Status, bool), AnchorError> {
        if request.scope == self.scope {
            return self.apply(request);
        }
        let link = self
            .rebuild_link
            .as_mut()
            .filter(|link| link.child.scope == request.scope)
            .ok_or_else(|| AnchorError::new("anchor_scope", "请求与独立锚固定范围不同"))?;
        if link.cancelled && request.action != Action::Inspect {
            return Ok((Status::Conflict, false));
        }
        link.child.apply(request)
    }
}
