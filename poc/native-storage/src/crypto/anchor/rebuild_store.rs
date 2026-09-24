//! 重建候选只存在新 SQLite 范围；签名控制、预约与业务结果均由同一所有者提交。
use rusqlite::{params, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{client::Client, commitment, database};
use crate::{
    crypto::{
        contract::{Action, Candidate, Outcome, Prepared, Request, Reservation, Scope},
        model, query, schema,
        store::{persistence, Store},
    },
    model::{Error, Fault, Result},
    transaction,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub stage: String,
    pub input_hash: String,
    pub details: Value,
}

fn blocked() -> Error {
    Error::new("rebuild_state_unresolved", true)
}
fn validate(state: &State) -> Result<()> {
    if !matches!(
        state.stage.as_str(),
        "initializing" | "prepared" | "planned" | "linked" | "joining" | "joined" | "active"
    ) || !query::valid_hash(&state.input_hash)
        || !state.details.is_object()
        || query::serialized(state)?.len() > 240 * 1024
    {
        return Err(blocked());
    }
    Ok(())
}
pub(crate) fn load(tx: &Transaction<'_>, client: &Client) -> Result<State> {
    schema::validate(tx)?;
    if schema::version(tx)? != 5 {
        return Err(Error::new("rebuild_store_required", true));
    }
    let (count, oversized): (i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(sum(CASE WHEN singleton!=1 OR length(state_json)>524288 THEN 1 ELSE 0 END),0) FROM rebuild_control",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(Error::database)?;
    if count != 1 || oversized != 0 {
        return Err(blocked());
    }
    let json: String = tx
        .query_row(
            "SELECT state_json FROM rebuild_control WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(Error::database)?;
    let state: State = client.verify_control(&json)?;
    validate(&state)?;
    if client.config.rebuild_origin.is_some()
        && (state.stage == "initializing"
            || new_client(&state)?.fingerprint() != client.fingerprint())
    {
        return Err(Error::new("rebuild_scope_mismatch", true));
    }
    Ok(state)
}
pub(crate) fn require_active(tx: &Transaction<'_>, client: &Client) -> Result<()> {
    if schema::version(tx)? == 5 && load(tx, client)?.stage != "active" {
        return Err(Error::new("rebuild_approval_required", true));
    }
    Ok(())
}
pub(crate) fn new_client(state: &State) -> Result<Client> {
    Client::new(
        serde_json::from_value(
            state
                .details
                .get("new_config")
                .cloned()
                .ok_or_else(blocked)?,
        )
        .map_err(|_| blocked())?,
    )
}
fn initialize_request() -> Request {
    Request {
        request_id: "rebuild-initialize".into(),
        action: Action::Initialize {},
        fault: Default::default(),
    }
}
fn reserve(
    tx: &Transaction<'_>,
    request: &Request,
    revision: &str,
    provider_hash: &str,
) -> Result<Reservation> {
    let reservation = Reservation {
        request_id: request.request_id.clone(),
        operation: request.action.operation().into(),
        input_hash: model::hash(query::serialized(&request.action)?.as_bytes()),
        base_revision: revision.into(),
        base_provider_hash: provider_hash.into(),
    };
    tx.execute("INSERT INTO crypto_pending(singleton,request_id,operation,input_hash,base_revision,base_provider_hash) VALUES(1,?1,?2,?3,?4,?5)", params![reservation.request_id,reservation.operation,reservation.input_hash,reservation.base_revision,reservation.base_provider_hash]).map_err(Error::database)?;
    Ok(reservation)
}
pub(crate) fn create(
    tx: &Transaction<'_>,
    scope: &Scope,
    signer: &Client,
    slot: &State,
) -> Result<()> {
    validate(slot)?;
    if slot.stage != "initializing"
        || signer.scope().service != scope.service
        || signer.scope().account != scope.account
        || signer.scope().device == scope.device
    {
        return Err(blocked());
    }
    schema::create(tx, scope)?;
    tx.execute_batch(schema::ANCHOR_CONTROL)
        .map_err(Error::database)?;
    tx.execute_batch(schema::REBUILD_CONTROL)
        .map_err(Error::database)?;
    tx.execute(
        "INSERT INTO anchor_control(singleton,binding) VALUES(1,?1)",
        [signer.fingerprint()],
    )
    .map_err(Error::database)?;
    tx.execute(
        "INSERT INTO rebuild_control(singleton,state_json) VALUES(1,?1)",
        [signer.sign_local(slot)?],
    )
    .map_err(Error::database)?;
    tx.execute(
        "UPDATE crypto_meta SET format=?1 WHERE singleton=1",
        [schema::REBUILD_FORMAT],
    )
    .map_err(Error::database)?;
    tx.execute_batch("PRAGMA user_version=5")
        .map_err(Error::database)?;
    reserve(tx, &initialize_request(), "0", "")?;
    load(tx, signer).map(|_| ())
}
fn transition(expected: &State, next: &State, from: &str, to: &str) -> Result<()> {
    validate(next)?;
    if expected.stage != from || next.stage != to || expected.input_hash != next.input_hash {
        return Err(blocked());
    }
    let before = expected.details.as_object().ok_or_else(blocked)?;
    if before
        .iter()
        .any(|(key, value)| next.details.get(key) != Some(value))
    {
        return Err(Error::new("rebuild_plan_conflict", true));
    }
    Ok(())
}
fn validate_join_request(state: &State, request: &Request) -> Result<()> {
    let plan: super::rebuild_protocol::Plan =
        serde_json::from_value(state.details.get("plan").cloned().ok_or_else(blocked)?)
            .map_err(|_| blocked())?;
    plan.validate()?;
    let new = new_client(state)?;
    let Action::CreateGroup { conversation, peer } = &request.action else {
        return Err(blocked());
    };
    if request.request_id != "rebuild-join"
        || conversation != &plan.trust.checkpoint.conversation_id
        || peer.service != plan.trust.checkpoint.service_id
        || peer.account != plan.trust.authorizer.account_id
        || peer.device != plan.trust.authorizer.device_id
        || peer.identity_key != plan.trust.authorizer.signature_key
        || new.scope() != &plan.successor_scope
        || new.client_public_key != plan.successor_client_public_key
        || new.config.anchor_public_key != plan.anchor_public_key
    {
        return Err(Error::new("rebuild_join_binding", true));
    }
    // 已入群批准者不再发布自己的 KeyPackage；新设备包由计划和 admission 单独核验。
    if !peer.key_package.is_empty() {
        model::decode(&peer.key_package)?;
    }
    Ok(())
}
fn write(
    tx: &Transaction<'_>,
    verifier: &Client,
    expected: &State,
    next: &State,
    signer: &Client,
) -> Result<()> {
    if load(tx, verifier)? != *expected {
        return Err(Error::new("rebuild_state_conflict", true));
    }
    let signed = signer.sign_local(next)?;
    if verifier.verify_control::<State>(&signed)? != *next {
        return Err(blocked());
    }
    if tx
        .execute(
            "UPDATE rebuild_control SET state_json=?1 WHERE singleton=1",
            [signed],
        )
        .map_err(Error::database)?
        != 1
    {
        return Err(blocked());
    }
    Ok(())
}

impl Store {
    pub(crate) fn rebuild_state(&mut self) -> Result<State> {
        let binding = self.anchor.as_ref().ok_or_else(blocked)?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Deferred,
            Fault::None,
            |tx| load(tx, &binding.client),
        );
        self.finish(result, false)
    }
    pub(crate) fn rebuild_replace_state(
        &mut self,
        expected: &State,
        next: &State,
        signer: &Client,
    ) -> Result<State> {
        self.ensure_active()?;
        let to = match expected.stage.as_str() {
            "prepared" => "planned",
            "planned" => "linked",
            "joined" => "active",
            _ => return Err(blocked()),
        };
        transition(expected, next, &expected.stage, to)?;
        let binding = self.anchor.as_ref().ok_or_else(blocked)?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            Fault::None,
            |tx| {
                let local = database::load(tx, &binding.client)?;
                if query::pending(tx)?.is_some() || local.gate.is_some() || local.journal.is_some()
                {
                    return Err(blocked());
                }
                write(tx, &binding.client, expected, next, signer)?;
                Ok(next.clone())
            },
        );
        self.finish(result, false)
    }
    pub(crate) fn rebuild_initialize(
        &mut self,
        expected: &State,
        candidate: Candidate,
        next: &State,
        signer: &Client,
        fault: Fault,
    ) -> Result<Outcome> {
        self.ensure_active()?;
        transition(expected, next, "initializing", "prepared")?;
        let new = new_client(next)?;
        if new.scope().service != self.scope.service
            || new.scope().account != self.scope.account
            || new.scope().device != self.scope.device
            || new.scope().identity_key
                != super::protocol::encode_hex(&model::decode(&candidate.identity.identity_key)?)
            || new.verify_control::<State>(&signer.sign_local(next)?)? != *next
        {
            return Err(Error::new("rebuild_scope_mismatch", true));
        }
        let binding = self.anchor.as_ref().ok_or_else(blocked)?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            fault,
            |tx| {
                let request = initialize_request();
                let pending = query::pending(tx)?.ok_or_else(blocked)?;
                let local = database::load(tx, &binding.client)?;
                if local.gate.is_some() || local.journal.is_some() || pending.base_revision != "0" {
                    return Err(blocked());
                }
                write(tx, &binding.client, expected, next, signer)?;
                let outcome = persistence::save(tx, &self.scope, &request, &pending, candidate)?;
                tx.execute(
                    "UPDATE anchor_control SET binding=?1 WHERE singleton=1",
                    [new.fingerprint()],
                )
                .map_err(Error::database)?;
                database::load(tx, &new)?;
                Ok(outcome)
            },
        );
        let outcome = self.finish(result, true)?;
        self.anchor = Some(database::Binding {
            client: new,
            permit: None,
        });
        Ok(outcome)
    }
    /// 原远端 Reserve 已确认后才能预约入群；返回值仅交给 Rust 协调线程。
    pub(crate) fn rebuild_prepare_join(
        &mut self,
        expected: &State,
        next: &State,
        request: &Request,
        signer: &Client,
    ) -> Result<Prepared> {
        self.ensure_active()?;
        transition(expected, next, "linked", "joining")?;
        validate_join_request(expected, request)?;
        let binding = self.anchor.as_ref().ok_or_else(blocked)?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            Fault::None,
            |tx| {
                let local = database::load(tx, &binding.client)?;
                let gate = binding.permit.as_ref().ok_or_else(blocked)?;
                if local.gate.as_ref() != Some(gate)
                    || gate.reserved_revision.is_none()
                    || local.journal.is_some()
                    || query::pending(tx)?.is_some()
                    || local.head != gate.base
                {
                    return Err(blocked());
                }
                let meta = query::load(tx, &self.scope)?;
                if meta.revision != "1" || meta.identity.is_none() || meta.conversation.is_some() {
                    return Err(blocked());
                }
                write(tx, &binding.client, expected, next, signer)?;
                let reservation = reserve(tx, request, &meta.revision, &meta.provider_hash)?;
                let provider = query::provider(tx, &meta)?;
                Ok(Prepared {
                    reservation,
                    provider,
                    identity: meta.identity,
                    conversation: None,
                    encryptions: meta.encryptions,
                    processed_cursor: meta.processed_cursor,
                    decryptions: meta.decryptions,
                    duplicate: None,
                })
            },
        );
        self.finish(result, true)
    }
    pub(crate) fn rebuild_join(
        &mut self,
        expected: &State,
        request: &Request,
        candidate: Candidate,
        next: &State,
        signer: &Client,
        fault: Fault,
    ) -> Result<Outcome> {
        self.ensure_active()?;
        transition(expected, next, "joining", "joined")?;
        validate_join_request(expected, request)?;
        let binding = self.anchor.as_ref().ok_or_else(blocked)?;
        let result = transaction::run(
            &mut self.connection,
            TransactionBehavior::Immediate,
            fault,
            |tx| {
                let local = database::load(tx, &binding.client)?;
                let gate = binding.permit.as_ref().ok_or_else(blocked)?;
                let pending = query::pending(tx)?.ok_or_else(blocked)?;
                if local.gate.as_ref() != Some(gate)
                    || gate.reserved_revision.is_none()
                    || local.journal.is_some()
                    || commitment::head(tx, true)? != gate.base
                {
                    return Err(blocked());
                }
                write(tx, &binding.client, expected, next, signer)?;
                let outcome = persistence::save(tx, &self.scope, request, &pending, candidate)?;
                database::complete(tx, Some(binding), "execute", &outcome)?;
                Ok(outcome)
            },
        );
        self.finish(result, true)
    }
}

#[cfg(test)]
#[path = "rebuild_store_tests.rs"]
mod tests;
