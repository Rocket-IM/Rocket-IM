//! 原生密码收发持久化 JSONL 验收装置，不向接入方发布；内存 peer 只作测试。
use rocket_native_storage_probe::{
    crypto::{
        contract::{DownloadRequest, Fault, Request, Scope},
        model::{Envelope, Identity},
        Client, MemoryPeer, Metrics,
    },
    model::{Error, Result},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env,
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    thread,
};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Download {
        id: String,
        request: DownloadRequest,
    },
    Process {
        id: String,
        request_id: String,
        sequence: String,
        #[serde(default)]
        fault: Fault,
    },
    Execute {
        id: String,
        request: Request,
    },
    Inspect {
        id: String,
    },
    Received {
        id: String,
        sequence: String,
    },
    PeerSend {
        id: String,
        message_id: String,
        text: String,
    },
    Close {
        id: String,
    },
    PeerIdentity {
        id: String,
    },
    PeerJoin {
        id: String,
        conversation: String,
        peer: Identity,
        welcome: String,
    },
    PeerReceive {
        id: String,
        envelope: Envelope,
    },
}
impl Command {
    fn id(&self) -> &str {
        match self {
            Self::Execute { id, .. }
            | Self::Download { id, .. }
            | Self::Process { id, .. }
            | Self::Received { id, .. }
            | Self::PeerSend { id, .. }
            | Self::Inspect { id }
            | Self::Close { id }
            | Self::PeerIdentity { id }
            | Self::PeerJoin { id, .. }
            | Self::PeerReceive { id, .. } => id,
        }
    }
}

fn emit(value: Value) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &value).map_err(|_| Error::new("control_io_failed", false))?;
    writeln!(out)
        .and_then(|()| out.flush())
        .map_err(|_| Error::new("control_io_failed", false))
}
fn reject(id: &str, code: &str) -> Value {
    json!({"id":id,"ok":false,"result":null,"error":Error::new(code,false),"events":[],"metrics":Metrics::default(),"trace":[]})
}
fn main() {
    if let Err(error) = run() {
        let _ = emit(json!({"ready":false,"error":error,"trace":[]}));
        std::process::exit(1);
    }
}
fn open_client(
    path: PathBuf,
    scope: Scope,
    create: bool,
    locator_path: Option<&str>,
) -> Result<Client> {
    let Some(locator_path) = locator_path else {
        return Client::open(path, scope, create);
    };
    #[cfg(feature = "protected-storage")]
    {
        let mut locator = String::new();
        std::fs::File::open(locator_path)
            .and_then(|file| file.take(16385).read_to_string(&mut locator))
            .map_err(|_| Error::new("protected_locator", true))?;
        if locator.len() > 16384 {
            return Err(Error::new("protected_locator", true));
        }
        Client::open_protected(path, scope, &locator, create)
    }
    #[cfg(not(feature = "protected-storage"))]
    {
        let _ = locator_path;
        Err(Error::new("protected_storage_unavailable", true))
    }
}
fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 4 {
        return Err(Error::new("invalid_arguments", false));
    }
    let mut flags = args[4..].iter();
    let mut create = false;
    let mut test_mode = false;
    let mut is_peer = false;
    let mut locator_path = None;
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "--create" => create = true,
            "--test-mode" => test_mode = true,
            "--memory-peer" => is_peer = true,
            "--protected" if locator_path.is_none() => {
                locator_path = Some(
                    flags
                        .next()
                        .filter(|value| !value.starts_with("--"))
                        .ok_or_else(|| Error::new("invalid_arguments", false))?
                        .as_str(),
                );
            }
            _ => return Err(Error::new("invalid_arguments", false)),
        }
    }
    if is_peer && locator_path.is_some() {
        return Err(Error::new("invalid_arguments", false));
    }
    if is_peer && !test_mode {
        return Err(Error::new("test_mode_required", false));
    }
    let scope = Scope {
        service: args[1].clone(),
        account: args[2].clone(),
        device: args[3].clone(),
    };
    let mut peer = if is_peer {
        Some(MemoryPeer::new(&scope)?)
    } else {
        None
    };
    let mut client = if is_peer {
        None
    } else {
        Some(open_client(
            PathBuf::from(&args[0]),
            scope,
            create,
            locator_path,
        )?)
    };
    let (worker, trace) = client
        .as_mut()
        .map_or(("memory-peer".into(), vec![]), Client::startup);
    let caller = format!("{:?}", thread::current().id());
    emit(json!({"ready":true,"worker_thread":worker,"caller_thread":caller,"trace":trace}))?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut line = String::new();
        let size = (&mut input)
            .take(262145)
            .read_line(&mut line)
            .map_err(|_| Error::new("control_io_failed", false))?;
        if size == 0 {
            break;
        }
        if size > 262144 || !line.ends_with('\n') {
            emit(reject("", "request_too_large_or_incomplete"))?;
            break;
        }
        let command: Command = match serde_json::from_str(&line) {
            Ok(command) => command,
            Err(_) => {
                emit(reject("", "invalid_request"))?;
                continue;
            }
        };
        let id = command.id().to_owned();
        if id.is_empty() || id.len() > 128 || id.contains('\0') {
            emit(reject("", "invalid_request_id"))?;
            continue;
        }
        let closing = matches!(command, Command::Close { .. });
        let mut reply = if let Some(client) = &mut client {
            match command {
                Command::Execute { request, .. } if !test_mode && request.fault != Fault::None => {
                    Ok(reject(&id, "test_mode_required"))
                }
                Command::Execute { request, .. } => serde_json::to_value(client.execute(request)),
                Command::Download { request, .. } if !test_mode && request.fault != Fault::None => {
                    Ok(reject(&id, "test_mode_required"))
                }
                Command::Download { request, .. } => serde_json::to_value(client.download(request)),
                Command::Process { fault, .. } if !test_mode && fault != Fault::None => {
                    Ok(reject(&id, "test_mode_required"))
                }
                Command::Process {
                    request_id,
                    sequence,
                    fault,
                    ..
                } => serde_json::to_value(client.process(&request_id, &sequence, fault)),
                Command::Inspect { .. } => serde_json::to_value(client.inspect()),
                Command::Received { sequence, .. } => {
                    serde_json::to_value(client.received(&sequence))
                }
                Command::Close { .. } => serde_json::to_value(client.close()),
                _ => Ok(reject(&id, "invalid_command")),
            }
            .map_err(|_| Error::new("encoding_failed", true))?
        } else if let Some(peer) = &mut peer {
            let result = match command {
                Command::PeerIdentity { .. } => Ok(json!(peer.identity())),
                Command::PeerSend {
                    message_id, text, ..
                } => peer
                    .send(&message_id, &text)
                    .map(|envelope| json!(envelope)),
                Command::PeerJoin {
                    conversation,
                    peer: identity,
                    welcome,
                    ..
                } => peer
                    .join(&conversation, &identity, &welcome)
                    .map(|()| Value::Null),
                Command::PeerReceive { envelope, .. } => {
                    peer.receive(&envelope).map(|plain| json!(plain))
                }
                Command::Close { .. } => Ok(Value::Null),
                _ => Err(Error::new("invalid_command", false)),
            };
            match result {
                Ok(value) => {
                    json!({"ok":true,"result":value,"error":null,"events":[],"metrics":Metrics::default(),"trace":[]})
                }
                Err(error) => {
                    json!({"ok":false,"result":null,"error":error,"events":[],"metrics":Metrics::default(),"trace":[]})
                }
            }
        } else {
            return Err(Error::new("closed", false));
        };
        reply["id"] = json!(id);
        reply["worker_thread"] = json!(worker);
        reply["caller_thread"] = json!(caller);
        emit(reply)?;
        if closing {
            break;
        }
    }
    if let Some(client) = &mut client {
        let closed = client.close();
        if let Some(error) = closed.error {
            return Err(error);
        }
    }
    Ok(())
}
