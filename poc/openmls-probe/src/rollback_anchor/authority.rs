//! synthetic_local 隔离锚进程；本机控制器能同时回滚本目录，因此不构成独立故障域证明。
use super::storage::LockedAnchor;
use super::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

mod state;
pub(super) use state::State;

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Failpoint {
    #[default]
    None,
    BeforeSave,
    BeforeRename,
    AfterSave,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Init {
        directory: PathBuf,
        scope: Scope,
        client_public_key: String,
        anchor_seed: String,
        head: String,
        #[serde(default)]
        rebuild_trust: Option<rebuild::RebuildTrust>,
    },
    Request {
        directory: PathBuf,
        request: Signed,
        #[serde(default)]
        failpoint: Failpoint,
    },
    PublicKey {
        seed: String,
    },
    SignRequest {
        seed: String,
        request: Request,
    },
    Rebuild {
        directory: PathBuf,
        plan: rebuild::Plan,
        approval: Signed,
        client_proof: Signed,
        challenge: String,
        #[serde(default)]
        failpoint: Failpoint,
    },
    CancelRebuild {
        directory: PathBuf,
        plan: rebuild::Plan,
        approval: Signed,
        client_proof: Signed,
        challenge: String,
        #[serde(default)]
        failpoint: Failpoint,
    },
    InspectRebuild {
        directory: PathBuf,
        plan: rebuild::Plan,
        approval: Signed,
        client_proof: Signed,
        challenge: String,
        #[serde(default)]
        failpoint: Failpoint,
    },
}

fn initialize(directory: &Path, state: State) -> Result<Value, AnchorError> {
    state.validate()?;
    let _anchor = LockedAnchor::initialize(directory, &state)?;
    Ok(
        json!({"ok":true,"anchor_public_key":public_key(&decode_hex(&state.anchor_seed)?),"scope":state.scope,"head":state.head,"client_public_key":state.client_public_key,"assurance":"synthetic_local"}),
    )
}

/// 一次调用只处理一个有界请求；成功写盘和目录 fsync 后才签出确认。
pub fn execute(input: &str) -> Result<Value, AnchorError> {
    if input.len() > INPUT_LIMIT {
        return Err(invalid());
    }
    match serde_json::from_str::<Command>(input).map_err(|_| invalid())? {
        Command::PublicKey { seed } => Ok(
            json!({"ok":true,"public_key":public_key(&decode_hex(&seed)?),"assurance":"synthetic_local"}),
        ),
        Command::SignRequest { seed, request } => Ok(
            json!({"ok":true,"request":sign_request(&request, &decode_hex(&seed)?)?,"assurance":"synthetic_local"}),
        ),
        Command::Init {
            directory,
            scope,
            client_public_key,
            anchor_seed,
            head,
            rebuild_trust,
        } => initialize(
            &directory,
            State {
                protocol_version: PROTOCOL.to_owned(),
                scope,
                client_public_key,
                anchor_seed,
                head,
                revision: 0,
                active: None,
                last: None,
                rebuild_trust,
                rebuild_link: None,
            },
        ),
        Command::Request {
            directory,
            request: signed,
            failpoint,
        } => {
            let anchor = LockedAnchor::open(&directory)?;
            let mut state = anchor.load()?;
            // 未认证字段只选择已固定公钥；实际动作必须随后完整验签和再次匹配范围。
            let untrusted: Request =
                serde_json::from_slice(&decode_base64(&signed.statement_bytes, STATEMENT_LIMIT)?)
                    .map_err(|_| invalid())?;
            let request = verify_request(
                &signed,
                &state.register(&untrusted.scope)?.client_public_key,
            )?;
            let environment = std::env::var("RIM_AUTHORITY_FAILPOINT").unwrap_or_default();
            if ![
                "",
                "none",
                "before_save",
                "after_reserve_save",
                "after_finish_save",
            ]
            .contains(&environment.as_str())
            {
                return Err(invalid());
            }
            let (status, changed) = state.route(&request)?;
            if changed {
                if environment == "before_save" {
                    std::process::exit(91);
                }
                anchor.save(&state, failpoint)?;
                match (environment.as_str(), request.action) {
                    ("after_reserve_save", Action::Reserve) => std::process::exit(89),
                    ("after_finish_save", Action::Finish) => std::process::exit(90),
                    _ => {}
                }
            }
            let register = state.register(&request.scope)?;
            let response = Response {
                protocol_version: PROTOCOL.to_owned(),
                scope: register.scope.clone(),
                challenge: request.challenge,
                request_sha256: request_digest(&signed)?,
                action: request.action,
                status,
                head: register.head.clone(),
                active_txn: register.active.as_ref().map(|t| t.txn.clone()),
                revision: register.revision.to_string(),
                closure: if request.scope == state.scope && state.rebuild_link.is_some() {
                    Some(Closure::Rebuilt)
                } else if state
                    .rebuild_link
                    .as_ref()
                    .is_some_and(|link| link.cancelled && request.scope == link.child.scope)
                {
                    Some(Closure::Cancelled)
                } else {
                    None
                },
            };
            Ok(
                json!({"ok":true,"response":sign_response(&response, &decode_hex(&state.anchor_seed)?)?}),
            )
        }
        Command::Rebuild {
            directory,
            plan,
            approval,
            client_proof,
            challenge,
            failpoint,
        } => execute_rebuild(
            &directory,
            plan,
            &approval,
            &client_proof,
            &challenge,
            rebuild::Action::Link,
            failpoint,
        ),
        Command::CancelRebuild {
            directory,
            plan,
            approval,
            client_proof,
            challenge,
            failpoint,
        } => execute_rebuild(
            &directory,
            plan,
            &approval,
            &client_proof,
            &challenge,
            rebuild::Action::Cancel,
            failpoint,
        ),
        Command::InspectRebuild {
            directory,
            plan,
            approval,
            client_proof,
            challenge,
            failpoint,
        } => execute_rebuild(
            &directory,
            plan,
            &approval,
            &client_proof,
            &challenge,
            rebuild::Action::Inspect,
            failpoint,
        ),
    }
}

fn execute_rebuild(
    directory: &Path,
    plan: rebuild::Plan,
    approval: &Signed,
    client_proof: &Signed,
    challenge: &str,
    action: rebuild::Action,
    failpoint: Failpoint,
) -> Result<Value, AnchorError> {
    let anchor = LockedAnchor::open(directory)?;
    let mut state = anchor.load()?;
    let (response, changed) =
        rebuild::apply(&mut state, plan, approval, client_proof, challenge, action)?;
    if changed {
        anchor.save(&state, failpoint)?;
    }
    Ok(json!({"ok":true,"response":response}))
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
