//! 新范围的可恢复协调器：只公开计划与公钥，未批准的候选不交付业务能力。
#[path = "rebuild_activate.rs"]
mod activate;
#[cfg(feature = "protected-storage")]
#[path = "rebuild_protected.rs"]
mod protected;
use super::{
    client::{Client as Remote, Config, ControlTrust},
    error, protocol,
    rebuild_protocol::{self as wire, Plan},
    rebuild_store::{self, State},
    AnchoredClient,
};
use crate::{
    crypto::{
        contract::{Candidate, DownloadRequest, Fault, Outcome, Request, Scope},
        db_thread::Database,
        engine::Engine,
        model::{self, Identity},
        Metrics, Reply,
    },
    model::{Fault as SqlFault, Result},
};
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct RebuildClient {
    old: AnchoredClient,
    candidate: Option<AnchoredClient>,
    path: PathBuf,
    scope: Scope,
    input: String,
    #[cfg(feature = "protected-storage")]
    new_locator: Option<String>,
}
impl RebuildClient {
    pub fn open_json(old_path: PathBuf, config: &str, path: PathBuf, device: &str) -> Result<Self> {
        validate_paths(&old_path, &path, device)?;
        let old = AnchoredClient::open_json(old_path, config)?;
        let mut this = Self::from_old(old, path, device)?;
        if this.path.exists() {
            this.load_candidate(None)?;
        }
        Ok(this)
    }
    fn from_old(old: AnchoredClient, path: PathBuf, device: &str) -> Result<Self> {
        let old_scope = old.remote.scope();
        if device == old_scope.device {
            return Err(error("rebuild_device_reused"));
        }
        let scope = Scope {
            service: old_scope.service.clone(),
            account: old_scope.account.clone(),
            device: device.into(),
        };
        let input = protocol::hash(
            &serde_json::to_vec(&(old.remote.fingerprint(), &path, &scope))
                .map_err(|_| error("encoding_failed"))?,
        );
        Ok(Self {
            old,
            candidate: None,
            path,
            scope,
            input,
            #[cfg(feature = "protected-storage")]
            new_locator: None,
        })
    }
    pub fn startup(&mut self) -> (String, Vec<String>) {
        if let Some(candidate) = &mut self.candidate {
            candidate.startup()
        } else {
            self.old.startup()
        }
    }
    fn load_candidate(&mut self, slot: Option<State>) -> Result<()> {
        let mut database = self.open_candidate_database(slot)?;
        let state = database.call(|store| store.rebuild_state())?;
        if state.input_hash != self.input {
            return Err(error("rebuild_plan_conflict"));
        }
        let remote = if state.stage == "initializing" {
            self.old.remote.clone()
        } else {
            rebuild_store::new_client(&state)?
        };
        self.candidate = Some(AnchoredClient {
            inner: crate::crypto::Client {
                database,
                scope: self.scope.clone(),
            },
            remote,
        });
        Ok(())
    }
    #[cfg(not(feature = "protected-storage"))]
    fn open_candidate_database(&self, slot: Option<State>) -> Result<Database> {
        Database::open_rebuild(
            self.path.clone(),
            self.scope.clone(),
            self.old.remote.clone(),
            slot,
        )
    }
    fn candidate(&mut self) -> Result<&mut AnchoredClient> {
        self.candidate
            .as_mut()
            .ok_or_else(|| error("rebuild_prepare_required"))
    }
    fn state(&mut self) -> Result<State> {
        self.candidate()?
            .inner
            .database
            .call(|store| store.rebuild_state())
    }
    fn save_state(&mut self, before: &State, after: State) -> Result<State> {
        let signer = self.old.remote.clone();
        let before = before.clone();
        self.candidate()?
            .inner
            .database
            .call(move |store| store.rebuild_replace_state(&before, &after, &signer))
    }
    fn reply(&mut self, result: Result<Value>, metrics: Metrics, events: Vec<Value>) -> Reply {
        if let Some(candidate) = &mut self.candidate {
            let mut reply = candidate.inner.reply(result, metrics, events);
            reply
                .trace
                .extend(std::mem::take(&mut self.old.inner.database.trace));
            reply
        } else {
            self.old.inner.reply(result, metrics, events)
        }
    }
    pub fn prepare(&mut self, fault: &str) -> Reply {
        let mut metrics = Metrics::default();
        let result = if matches!(
            fault,
            "none" | "after_slot" | "after_identity" | "after_plan"
        ) {
            self.prepare_inner(fault, &mut metrics)
        } else {
            Err(error("rebuild_fault_invalid"))
        };
        self.reply(result, metrics, vec![])
    }
    fn prepare_inner(&mut self, fault: &str, metrics: &mut Metrics) -> Result<Value> {
        let mut created = false;
        if self.candidate.is_none() {
            let old = self.old.remote.clone();
            let trust = old
                .config
                .rebuild_trust
                .clone()
                .ok_or_else(|| error("rebuild_trust_not_pinned"))?;
            trust.validate(old.scope())?;
            let signer = old.clone();
            let evidence = self
                .old
                .inner
                .database
                .call(move |store| store.rebuild_fence(&signer))?;
            let observed = old.rpc(
                protocol::Action::Inspect,
                field(&evidence, "txn")?,
                field(&evidence, "head")?,
                "absent",
                "0",
            )?;
            if observed.head != field(&evidence, "head")?
                || observed.active_txn.as_deref() != Some(field(&evidence, "txn")?)
                || observed.revision != field(&evidence, "revision")?
            {
                return Err(error("rebuild_old_state_changed"));
            }
            self.load_candidate(Some(State {
                stage: "initializing".into(),
                input_hash: self.input.clone(),
                details: json!({"old":evidence}),
            }))?;
            created = true;
            pause(fault, "after_slot", metrics)?;
        }
        let mut state = self.state()?;
        if state.stage == "initializing" {
            if !created {
                return Err(error("rebuild_initialization_unresolved"));
            }
            metrics.provider_news += 1;
            let engine = Engine::new(&self.scope)?;
            let identity = engine.identity();
            let old = &self.old.remote;
            let config = Config {
                program: old.config.program.clone(),
                directory: old.config.directory.clone(),
                scope: protocol::Scope {
                    service: self.scope.service.clone(),
                    account: self.scope.account.clone(),
                    device: self.scope.device.clone(),
                    identity_key: protocol::encode_hex(&model::decode(&identity.identity_key)?),
                    store_id: protocol::random_hex()?,
                },
                anchor_public_key: old.config.anchor_public_key.clone(),
                client_seed: protocol::random_hex()?,
                rebuild_trust: None,
                rebuild_origin: Some(ControlTrust {
                    client_public_key: old.client_public_key.clone(),
                    fingerprint: old.fingerprint(),
                }),
            };
            let remote = Remote::new(config.clone())?;
            let mut next = state.clone();
            next.stage = "prepared".into();
            next.details["new_config"] = json!(config);
            next.details["identity"] = json!(identity);
            let candidate = Candidate {
                provider: engine.export()?,
                identity: identity.clone(),
                conversation: None,
                encryptions: "0".into(),
                processed_cursor: "0".into(),
                decryptions: "0".into(),
                outcome: Outcome {
                    revision: "1".into(),
                    kind: "initialize".into(),
                    cached: false,
                    value: json!(identity),
                },
            };
            let signer = self.old.remote.clone();
            let previous = state.clone();
            let saved = next.clone();
            self.candidate()?.inner.database.call(move |store| {
                store.rebuild_initialize(&previous, candidate, &saved, &signer, SqlFault::None)
            })?;
            self.candidate()?.remote = remote;
            state = next;
            pause(fault, "after_identity", metrics)?;
        }
        if state.stage == "prepared" {
            let remote = self.candidate()?.remote.clone();
            let head = self
                .candidate()?
                .inner
                .database
                .call(|store| store.anchor_local())?
                .head;
            let old = &self.old.remote;
            let evidence = &state.details["old"];
            let identity: Identity = serde_json::from_value(state.details["identity"].clone())
                .map_err(|_| error("rebuild_identity"))?;
            let conversation = field(evidence, "conversation")?;
            let plan = Plan {
                protocol_version: wire::PROTOCOL.into(),
                rebuild_id: protocol::random_hex()?,
                old_scope: old.scope().clone(),
                old_head: field(evidence, "head")?.into(),
                old_txn: field(evidence, "txn")?.into(),
                old_revision: field(evidence, "revision")?.into(),
                old_conversation_id: conversation.into(),
                old_group_id: group_id(&self.scope.service, conversation),
                anchor_public_key: old.config.anchor_public_key.clone(),
                successor_scope: remote.scope().clone(),
                successor_head: head,
                successor_client_public_key: remote.client_public_key.clone(),
                key_package_sha256: protocol::hash(&model::decode(&identity.key_package)?),
                trust: old
                    .config
                    .rebuild_trust
                    .clone()
                    .ok_or_else(|| error("rebuild_trust_not_pinned"))?,
            };
            plan.validate()?;
            let mut next = state.clone();
            next.stage = "planned".into();
            next.details["plan"] = json!(plan);
            state = self.save_state(&state, next)?;
            pause(fault, "after_plan", metrics)?;
        }
        public(&state)
    }
    pub fn status(&mut self) -> Reply {
        let result = self.state().and_then(|state| public(&state));
        self.reply(result, Metrics::default(), vec![])
    }
    fn active(&mut self) -> Result<&mut AnchoredClient> {
        if self.state()?.stage != "active" {
            return Err(error("rebuild_approval_required"));
        }
        self.candidate()
    }
    pub fn execute(&mut self, request: Request, fault: super::contract::AnchorFault) -> Reply {
        match self.active() {
            Ok(client) => client.execute(request, fault),
            Err(e) => self.reply(Err(e), Metrics::default(), vec![]),
        }
    }
    pub fn download(
        &mut self,
        request: DownloadRequest,
        fault: super::contract::AnchorFault,
    ) -> Reply {
        match self.active() {
            Ok(client) => client.download(request, fault),
            Err(e) => self.reply(Err(e), Metrics::default(), vec![]),
        }
    }
    pub fn process(
        &mut self,
        id: &str,
        sequence: &str,
        fault: Fault,
        anchor: super::contract::AnchorFault,
    ) -> Reply {
        match self.active() {
            Ok(client) => client.process(id, sequence, fault, anchor),
            Err(e) => self.reply(Err(e), Metrics::default(), vec![]),
        }
    }
    pub fn received(&mut self, sequence: &str) -> Reply {
        match self.active() {
            Ok(client) => client.received(sequence),
            Err(e) => self.reply(Err(e), Metrics::default(), vec![]),
        }
    }
    pub fn inspect(&mut self) -> Reply {
        match self.active() {
            Ok(client) => client.inspect(),
            Err(e) => self.reply(Err(e), Metrics::default(), vec![]),
        }
    }
    pub fn recover(&mut self) -> Reply {
        match self.active() {
            Ok(client) => client.recover(),
            Err(e) => self.reply(Err(e), Metrics::default(), vec![]),
        }
    }
    pub fn close(&mut self) -> Reply {
        let result = self
            .old
            .inner
            .database
            .close()
            .and_then(|()| match &mut self.candidate {
                Some(client) => client.inner.database.close(),
                None => Ok(()),
            })
            .map(|()| Value::Null);
        self.reply(result, Metrics::default(), vec![])
    }
}
fn validate_paths(old_path: &std::path::Path, path: &std::path::Path, device: &str) -> Result<()> {
    crate::crypto::contract::validate_id(device)?;
    if !path.is_absolute() || path == old_path || path.to_str().is_none_or(|v| v.len() > 4096) {
        return Err(error("rebuild_path"));
    }
    Ok(())
}
fn public(state: &State) -> Result<Value> {
    Ok(
        json!({"stage":state.stage,"identity":state.details.get("identity"),"plan":state.details.get("plan"),
        "plan_sha256":state.details.get("plan").map(|p|serde_json::from_value::<Plan>(p.clone()).map_err(|_|error("rebuild_plan_invalid"))?.digest()).transpose()?}),
    )
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| error("rebuild_state_invalid"))
}
fn pause(actual: &str, target: &str, metrics: &Metrics) -> Result<()> {
    if actual == target {
        crate::crypto::checkpoint(target, metrics)?;
    }
    Ok(())
}
fn group_id(service: &str, conversation: &str) -> String {
    let mut raw = b"Rocket-IM/native-crypto/group/v1\0".to_vec();
    for value in [service, conversation] {
        raw.extend_from_slice(&(value.len() as u16).to_be_bytes());
        raw.extend_from_slice(value.as_bytes());
    }
    model::encode(&raw)
}
