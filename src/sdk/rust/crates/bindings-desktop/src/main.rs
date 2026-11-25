//! 有界 JSONL 桥接；只调用公开 SDK，不含 SQL、密码实现、测试身份或故障命令。
use rocket_im_sdk::persistent::network::{
    AuthenticationResult, NetworkOptions, NetworkRecoveryCommand, NetworkSession,
};
use rocket_im_sdk::persistent::*;
use serde::Deserialize;
mod input;
use serde_json::{json, Value as Json};
use std::{
    io::{self, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
    sync::mpsc::RecvTimeoutError,
    time::Duration,
};
const VERSION: &str = env!("CARGO_PKG_VERSION");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    id: String,
    operation: Operation,
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Execute {
        request_id: String,
        action: Action,
    },
    RecoverRequest {
        request_id: String,
        action: Action,
    },
    Recovery {
        command: RecoveryCommand,
    },
    Connect {
        options: NetworkOptions,
    },
    Disconnect,
    AuthenticationResult {
        request_id: String,
        result: AuthenticationResult,
    },
    NetworkState,
    NetworkRecovery {
        command: NetworkRecoveryCommand,
    },
    NetworkUnavailable {
        sequence: String,
    },
    State,
    Capacity,
    ReserveCapacity,
    CapacityWorkset,
    PrepareCapacityWorkset,
    PrepareNextCapacityWorkset {
        previous: String,
    },
    CreateBackup {
        path: PathBuf,
    },
    RestoreBackup {
        path: PathBuf,
    },
    History {
        query: HistoryQuery,
    },
    JoiningMaterial,
    Request {
        request_id: String,
    },
    Message {
        sender_account: String,
        sender_device: String,
        message_id: String,
    },
    Close,
    Logout,
    #[cfg(feature = "test-hooks")]
    AuditProtection,
}
fn output(value: Json) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &value)?;
    out.write_all(b"\n")?;
    out.flush()
}
fn error(code: &str, paused: bool) -> Error {
    Error {
        code: code.into(),
        paused,
    }
}
fn execute(
    device: &mut PersistentDevice,
    scope: &Scope,
    operation: Operation,
    network: &mut Option<NetworkSession>,
) -> Result<(Json, Vec<Json>)> {
    let mut events = Vec::new();
    let value = match operation {
        Operation::Execute { request_id, action } => {
            let outcome = device.execute(request_id.clone(), action)?;
            if !outcome.cached {
                events.push(json!({"scope": scope, "request_id": request_id,
                "revision": outcome.revision, "kind": "local_commit"}));
            }
            json!(outcome)
        }
        Operation::RecoverRequest { request_id, action } => {
            let outcome = device.recover_request(request_id.clone(), action)?;
            if !outcome.cached {
                events.push(json!({"scope":scope,"request_id":request_id,"revision":outcome.revision,"kind":"local_commit"}));
            }
            json!(outcome)
        }
        Operation::Recovery { command } => {
            let result = device.recovery(command)?;
            if let Some(commit) = &result.commit {
                events.push(json!({"scope":scope,"request_id":commit.context,"revision":commit.revision,"kind":"context_changed"}));
            }
            json!(result)
        }
        Operation::Connect { options } => {
            if network.is_some() {
                return Err(error("already_connected", false));
            }
            let session = NetworkSession::connect(device, options)?;
            let value = json!(session.state(device)?);
            *network = Some(session);
            value
        }
        Operation::Disconnect => {
            network.take();
            json!(NetworkSession::offline_state(device)?)
        }
        Operation::AuthenticationResult { request_id, result } => {
            network
                .as_mut()
                .ok_or_else(|| error("stale_authentication", false))?
                .complete_authentication(&request_id, result)?;
            Json::Null
        }
        Operation::NetworkState => json!(match network.as_ref() {
            Some(n) => n.state(device)?,
            None => NetworkSession::offline_state(device)?,
        }),
        Operation::NetworkRecovery { command } => json!(device.network_recovery(command)?),
        Operation::NetworkUnavailable { sequence } => json!(device.network_unavailable(sequence)?),
        Operation::State => json!(device.state()?),
        Operation::Capacity => json!(device.capacity()?),
        Operation::ReserveCapacity => json!(device.reserve_capacity()?),
        Operation::CapacityWorkset => json!(device.capacity_workset()?),
        Operation::PrepareCapacityWorkset => json!(device.prepare_capacity_workset()?),
        Operation::PrepareNextCapacityWorkset { previous } => {
            json!(device.prepare_next_capacity_workset(previous)?)
        }
        Operation::CreateBackup { path } => {
            if network.is_some() {
                return Err(error("backup_disconnect_required", false));
            }
            json!(device.create_backup(path)?)
        }
        Operation::RestoreBackup { .. } => return Err(error("backup_close_required", false)),
        Operation::History { query } => json!(device.history(query)?),
        Operation::JoiningMaterial => json!(device.joining_material()?),
        Operation::Request { request_id } => json!(device.request(request_id)?),
        Operation::Message {
            sender_account,
            sender_device,
            message_id,
        } => json!(device.message(sender_account, sender_device, message_id)?),
        Operation::Close => {
            network.take();
            device.close()?;
            Json::Null
        }
        Operation::Logout => {
            network.take();
            device.logout()?;
            Json::Null
        }
        #[cfg(feature = "test-hooks")]
        Operation::AuditProtection => device.audit_protection()?,
    };
    Ok((value, events))
}
fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 || !matches!(args[5].as_str(), "create" | "open" | "logout" | "restore") {
        return output(json!({"ready":false,"error":error("invalid_options",false)}));
    }
    let scope = Scope {
        service: args[2].clone(),
        account: args[3].clone(),
        device: args[4].clone(),
    };
    let mut device = if args[5] == "restore" {
        None
    } else {
        match PersistentDevice::open_protected(
            PathBuf::from(&args[1]),
            scope.clone(),
            args[5] == "create",
            PathBuf::from(&args[6]),
        ) {
            Ok(d) => Some(d),
            Err(e) if e.code == "logged_out" && args[5] == "logout" => None,
            Err(e) => return output(json!({"ready":false,"error":e})),
        }
    };
    output(
        json!({"ready":true,"protocol":3,"version":VERSION,"scope":scope,
        "test_hooks":cfg!(feature="test-hooks"),
        "runtime":{"pid":std::process::id(),"os":std::env::consts::OS,"arch":std::env::consts::ARCH}}),
    )?;
    let input = input::start();
    let mut network: Option<NetworkSession> = None;
    loop {
        if let (Some(session), Some(device)) = (network.as_mut(), device.as_mut()) {
            let result = session.tick(device);
            for event in session.take_authentication_events() {
                output(json!({"event":event}))?;
            }
            match result {
                Ok(Some(state)) => {
                    output(json!({"event":{"kind":"network_state","scope":scope,"state":state}}))?
                }
                Ok(None) => {}
                Err(e) => {
                    output(json!({"event":{"kind":"network_error","scope":scope,"error":e}}))?;
                    network.take();
                }
            }
        }
        let line = match input.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let request = match serde_json::from_slice::<Input>(&line) {
            Ok(request) => request,
            Err(_) => {
                // 可关联的坏参数明确失败，保持有效实例；不可关联的坏帧终止传输。
                let Ok(raw) = serde_json::from_slice::<Json>(&line) else {
                    break;
                };
                let Some(id) = raw
                    .get("id")
                    .and_then(Json::as_str)
                    .filter(|id| !id.is_empty() && id.len() <= 64)
                else {
                    break;
                };
                output(
                    json!({"id":id,"ok":false,"result":null,"error":error("invalid_request",false),"events":[]}),
                )?;
                continue;
            }
        };
        if request.id.is_empty() || request.id.len() > 64 {
            break;
        }
        let closing = matches!(request.operation, Operation::Close | Operation::Logout);
        let result = catch_unwind(AssertUnwindSafe(|| {
            if let Some(device) = device.as_mut() {
                if !closing {
                    device.check_access()?;
                }
                let result = execute(device, &scope, request.operation, &mut network)?;
                if !closing {
                    device.check_access()?;
                }
                Ok(result)
            } else if let Operation::RestoreBackup { path } = request.operation {
                if args[5] != "restore" {
                    return Err(error("invalid_options", false));
                }
                let info = PersistentDevice::restore_backup(
                    PathBuf::from(&args[1]),
                    scope.clone(),
                    PathBuf::from(&args[6]),
                    path,
                )?;
                Ok((json!(info), vec![]))
            } else if matches!(request.operation, Operation::Logout) {
                PersistentDevice::confirm_logout(
                    PathBuf::from(&args[1]),
                    scope.clone(),
                    PathBuf::from(&args[6]),
                )?;
                Ok((Json::Null, vec![]))
            } else if matches!(request.operation, Operation::Close) {
                Ok((Json::Null, vec![]))
            } else {
                Err(error("logged_out", true))
            }
        }));
        let panicked = result.is_err();
        let result = result.unwrap_or_else(|_| Err(error("runtime_panicked", true)));
        let reply = match result {
            Ok((value, events)) => {
                json!({"id":request.id,"ok":true,"result":value,"error":null,"events":events})
            }
            Err(e) => json!({"id":request.id,"ok":false,"result":null,"error":e,"events":[]}),
        };
        output(reply)?;
        if closing || panicked {
            break;
        }
    }
    if let Some(device) = device.as_mut() {
        let _ = device.close();
    }
    Ok(())
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    if run().is_err() {
        std::process::exit(1);
    }
}
