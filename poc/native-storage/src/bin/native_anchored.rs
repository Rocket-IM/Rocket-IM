//! 必填外置可信配置的原生锚验收入口；普通 v3 入口不作为降级备选。
use rocket_native_storage_probe::{
    crypto::{
        anchor::{contract::AnchorFault, AnchoredClient},
        contract::{DownloadRequest, Fault, Request},
        Metrics, Reply,
    },
    model::{Error, Result},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env,
    fs::File,
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    thread,
};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Execute {
        id: String,
        request: Request,
        #[serde(default)]
        anchor_fault: AnchorFault,
    },
    Download {
        id: String,
        request: DownloadRequest,
        #[serde(default)]
        anchor_fault: AnchorFault,
    },
    Process {
        id: String,
        request_id: String,
        sequence: String,
        #[serde(default)]
        fault: Fault,
        #[serde(default)]
        anchor_fault: AnchorFault,
    },
    Inspect {
        id: String,
    },
    Status {
        id: String,
    },
    Received {
        id: String,
        sequence: String,
    },
    Recover {
        id: String,
    },
    RebuildCheckpoint {
        id: String,
    },
    RebuildApprove {
        id: String,
        plan: Value,
        peer: rocket_native_storage_probe::crypto::model::Identity,
        confirm_plan_sha256: String,
        #[serde(default)]
        fault: Fault,
        #[serde(default)]
        anchor_fault: AnchorFault,
    },
    Close {
        id: String,
    },
}
impl Command {
    fn id(&self) -> &str {
        match self {
            Self::Execute { id, .. }
            | Self::Download { id, .. }
            | Self::Process { id, .. }
            | Self::Inspect { id }
            | Self::Status { id }
            | Self::Received { id, .. }
            | Self::Recover { id }
            | Self::RebuildCheckpoint { id }
            | Self::RebuildApprove { id, .. }
            | Self::Close { id } => id,
        }
    }
    fn faulted(&self) -> bool {
        match self {
            Self::RebuildApprove {
                fault,
                anchor_fault,
                ..
            } => *fault != Fault::None || *anchor_fault != AnchorFault::None,
            Self::Execute {
                request,
                anchor_fault,
                ..
            } => request.fault != Fault::None || *anchor_fault != AnchorFault::None,
            Self::Download {
                request,
                anchor_fault,
                ..
            } => request.fault != Fault::None || *anchor_fault != AnchorFault::None,
            Self::Process {
                fault,
                anchor_fault,
                ..
            } => *fault != Fault::None || *anchor_fault != AnchorFault::None,
            _ => false,
        }
    }
}
fn emit(value: Value) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &value).map_err(|_| Error::new("control_io_failed", true))?;
    writeln!(out)
        .and_then(|()| out.flush())
        .map_err(|_| Error::new("control_io_failed", true))
}
fn reject(id: &str, code: &str) -> Value {
    json!({"id":id,"ok":false,"result":null,"error":Error::new(code,true),"events":[],"metrics":Metrics::default(),"trace":[]})
}
fn main() {
    if let Err(error) = run() {
        let _ = emit(json!({"ready":false,"error":error,"trace":[]}));
        std::process::exit(1);
    }
}
fn bind_client(db: PathBuf, data: &str, protected: bool) -> Result<Value> {
    if !protected {
        return AnchoredClient::bind_json(db, data);
    }
    #[cfg(feature = "protected-storage")]
    {
        // 受保护配置只从有界标准输入读取，不能经参数或明文配置旁文件传入。
        let mut config = String::new();
        let size = io::stdin()
            .lock()
            .take(16385)
            .read_line(&mut config)
            .map_err(|_| Error::new("control_io_failed", true))?;
        if size > 16384 || !config.ends_with('\n') {
            return Err(Error::new("anchor_config", true));
        }
        AnchoredClient::bind_protected(db, data, &config)
    }
    #[cfg(not(feature = "protected-storage"))]
    {
        Err(Error::new("protected_storage_unavailable", true))
    }
}
fn open_client(db: PathBuf, data: &str, protected: bool) -> Result<AnchoredClient> {
    if !protected {
        return AnchoredClient::open_json(db, data);
    }
    #[cfg(feature = "protected-storage")]
    {
        AnchoredClient::open_protected(db, data)
    }
    #[cfg(not(feature = "protected-storage"))]
    {
        Err(Error::new("protected_storage_unavailable", true))
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() < 2
        || args[2..]
            .iter()
            .any(|v| !matches!(v.as_str(), "--bind" | "--test-mode" | "--protected"))
    {
        return Err(Error::new("anchor_config", true));
    }
    let protected_count = args[2..].iter().filter(|v| *v == "--protected").count();
    if protected_count > 1 {
        return Err(Error::new("invalid_arguments", false));
    }
    let protected = protected_count == 1;
    #[cfg(not(feature = "protected-storage"))]
    if protected {
        return Err(Error::new("protected_storage_unavailable", true));
    }
    let config_path = PathBuf::from(&args[1]);
    let mut data = String::new();
    File::open(&config_path)
        .and_then(|f| f.take(16385).read_to_string(&mut data))
        .map_err(|_| Error::new("anchor_config", true))?;
    if data.len() > 16384 {
        return Err(Error::new("anchor_config", true));
    }
    let db = PathBuf::from(&args[0]);
    if args.iter().skip(2).any(|v| v == "--bind") {
        return emit(json!({"ok":true,"result":bind_client(db,&data,protected)?}));
    }
    let test_mode = args.iter().skip(2).any(|v| v == "--test-mode");
    let mut client = open_client(db, &data, protected)?;
    let (worker, trace) = client.startup();
    let caller = format!("{:?}", thread::current().id());
    emit(json!({"ready":true,"worker_thread":worker,"caller_thread":caller,"trace":trace}))?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut line = String::new();
        let size = (&mut input)
            .take(262145)
            .read_line(&mut line)
            .map_err(|_| Error::new("control_io_failed", true))?;
        if size == 0 {
            break;
        }
        if size > 262144 || !line.ends_with('\n') {
            emit(reject("", "request_too_large_or_incomplete"))?;
            break;
        }
        let command: Command = match serde_json::from_str(&line) {
            Ok(v) => v,
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
        if !test_mode && command.faulted() {
            emit(reject(&id, "test_mode_required"))?;
            continue;
        }
        let closing = matches!(command, Command::Close { .. });
        let reply: Reply = match command {
            Command::Execute {
                request,
                anchor_fault,
                ..
            } => client.execute(request, anchor_fault),
            Command::Download {
                request,
                anchor_fault,
                ..
            } => client.download(request, anchor_fault),
            Command::Process {
                request_id,
                sequence,
                fault,
                anchor_fault,
                ..
            } => client.process(&request_id, &sequence, fault, anchor_fault),
            Command::Inspect { .. } => client.inspect(),
            Command::Status { .. } => client.status(),
            Command::Received { sequence, .. } => client.received(&sequence),
            Command::Recover { .. } => client.recover(),
            Command::RebuildCheckpoint { .. } => client.rebuild_checkpoint(),
            Command::RebuildApprove {
                plan,
                peer,
                confirm_plan_sha256,
                fault,
                anchor_fault,
                ..
            } => client.rebuild_approve(plan, peer, &confirm_plan_sha256, fault, anchor_fault),
            Command::Close { .. } => client.close(),
        };
        let mut reply =
            serde_json::to_value(reply).map_err(|_| Error::new("encoding_failed", true))?;
        reply["id"] = json!(id);
        reply["caller_thread"] = json!(caller);
        emit(reply)?;
        if closing {
            break;
        }
    }
    let closed = client.close();
    if let Some(error) = closed.error {
        return Err(error);
    }
    Ok(())
}
