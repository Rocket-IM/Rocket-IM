//! 单安装槽权威；离线批准CAS、永久旧scope墓碑、有界历史，响应仅在提交后签署。
use super::*;
use serde_json::{json, Value};
use std::path::PathBuf;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub protocol_version: String,
    pub slot: String,
    pub approval_key: String,
    pub response_seed: String,
    pub generation: u64,
    pub current: Option<Manifest>,
    pub disabled: bool,
    pub retired: Vec<Manifest>,
    pub last: Option<SignedRecord>,
}
impl State {
    pub(super) fn validate(&self) -> Result<()> {
        check(
            self.protocol_version == "rim-startup-authority-1" && self.retired.len() <= 64,
            "startup_state",
        )?;
        types::id(&self.slot)?;
        receipts::validate_key(&self.approval_key)?;
        check(
            public(&self.response_seed)? != self.approval_key,
            "startup_root_separation",
        )?;
        if let Some(m) = &self.current {
            m.validate()?;
            check(
                m.slot == self.slot && types::decimal(&m.generation)? <= self.generation,
                "startup_state",
            )?;
        } else {
            check(
                self.generation == 0 && !self.disabled && self.retired.is_empty(),
                "startup_state",
            )?;
        }
        Ok(())
    }
    pub(super) fn apply(&mut self, proof: SignedRecord) -> Result<()> {
        let a: Approval = verify(&proof, APPROVAL_DOMAIN, &self.approval_key)?;
        check(
            a.protocol_version == "rim-startup-approval-1" && a.slot == self.slot,
            "startup_scope",
        )?;
        if self.last.as_ref() == Some(&proof) {
            return Ok(());
        }
        check(!self.disabled, "startup_disabled")?;
        let previous = self
            .current
            .as_ref()
            .map(Manifest::hash)
            .transpose()?
            .unwrap_or_else(|| "absent".into());
        check(
            types::decimal(&a.previous_generation)? == self.generation
                && a.previous_sha256 == previous,
            "startup_cas",
        )?;
        let next = self.generation.checked_add(1).ok_or_else(error)?;
        match a.action.as_str() {
            "install" | "rotate" => {
                check(
                    (a.action == "install") == self.current.is_none(),
                    "startup_action",
                )?;
                let m = a.manifest.ok_or_else(error)?;
                m.validate()?;
                check(
                    m.slot == self.slot && types::decimal(&m.generation)? == next,
                    "startup_generation",
                )?;
                check(
                    !self.retired.iter().any(|s| {
                        s.scope.identity_key == m.scope.identity_key
                            || s.scope.store_id == m.scope.store_id
                            || s.anchor_public_key == m.anchor_public_key
                    }),
                    "startup_retired",
                )?;
                if let Some(old) = &self.current {
                    check(self.retired.len() < 64, "startup_capacity")?;
                    check(
                        old.roots.service_id == m.roots.service_id
                            && old.scope.identity_key != m.scope.identity_key
                            && old.scope.store_id != m.scope.store_id
                            && old.anchor_public_key != m.anchor_public_key,
                        "startup_successor_required",
                    )?;
                    self.retired.push(old.clone());
                }
                let response_key = public(&self.response_seed)?;
                let anchor_key = STANDARD.encode(
                    crate::rollback_anchor::decode_hex(&m.anchor_public_key)
                        .map_err(|_| error())?,
                );
                check(
                    [&self.approval_key, &response_key].iter().all(|key| {
                        **key != m.roots.business_key
                            && **key != m.roots.receipt_key
                            && **key != anchor_key
                    }),
                    "startup_root_separation",
                )?;
                self.current = Some(m);
            }
            "disable" => {
                check(
                    self.current.is_some() && a.manifest.is_none(),
                    "startup_action",
                )?;
                self.disabled = true;
            }
            _ => return Err(error()),
        }
        self.generation = next;
        self.last = Some(proof);
        self.validate()
    }
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Init {
        directory: PathBuf,
        slot: String,
        approval_key: String,
        response_seed: String,
    },
    Apply {
        directory: PathBuf,
        approval: SignedRecord,
        #[serde(default)]
        failpoint: String,
    },
    Check {
        directory: PathBuf,
        slot: String,
        challenge: String,
    },
    // 仅离线批准装置使用，线上权威不会读取或持有批准私钥。
    Sign {
        approval: Box<Approval>,
        seed: String,
    },
    PublicKey {
        seed: String,
    },
}
pub fn execute(input: &str) -> Result<Value> {
    check(input.len() <= LIMIT, "startup_limit")?;
    let command: Command = serde_json::from_str(input).map_err(|_| error())?;
    match command {
        Command::PublicKey { seed } => {
            Ok(json!({"ok":true,"result":{"public_key":public(&seed)?}}))
        }
        Command::Sign { approval, seed } => {
            Ok(json!({"ok":true,"result":{"approval":sign(&approval, APPROVAL_DOMAIN, &seed)?}}))
        }
        Command::Init {
            directory,
            slot,
            approval_key,
            response_seed,
        } => {
            let state = State {
                protocol_version: "rim-startup-authority-1".into(),
                slot,
                approval_key,
                response_seed,
                generation: 0,
                current: None,
                disabled: false,
                retired: vec![],
                last: None,
            };
            state.validate()?;
            let store = storage::Store::create(&directory)?;
            store.save(&state, "")?;
            Ok(json!({"ok":true,"result":{"public_key":public(&state.response_seed)?}}))
        }
        Command::Apply {
            directory,
            approval,
            failpoint,
        } => {
            check(
                ["", "before_save", "before_rename", "after_save"].contains(&failpoint.as_str()),
                "startup_failpoint",
            )?;
            let store = storage::Store::open(&directory)?;
            let mut state = store.load()?;
            state.apply(approval)?;
            store.save(&state, &failpoint)?;
            Ok(
                json!({"ok":true,"result":{"generation":state.generation.to_string(),"disabled":state.disabled}}),
            )
        }
        Command::Check {
            directory,
            slot,
            challenge,
        } => {
            types::hash(&challenge)?;
            let store = storage::Store::open(&directory)?;
            let state = store.load()?;
            check(state.slot == slot, "startup_scope")?;
            let response = Response {
                protocol_version: "rim-startup-response-1".into(),
                slot,
                challenge,
                generation: state.generation.to_string(),
                manifest_sha256: state
                    .current
                    .as_ref()
                    .map(Manifest::hash)
                    .transpose()?
                    .unwrap_or_else(|| "absent".into()),
                disabled: state.disabled,
            };
            Ok(
                json!({"ok":true,"response":sign(&response, RESPONSE_DOMAIN, &state.response_seed)?}),
            )
        }
    }
}
