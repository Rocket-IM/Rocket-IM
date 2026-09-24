//! 原生安全重建控制入口：旧可信配置、新SQLite路径与明确新设备标识。
use rockets_native_storage_probe::{
    crypto::{
        anchor::{contract::AnchorFault, RebuildClient},
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
    Prepare {
        id: String,
        #[serde(default = "no_fault")]
        fault: String,
    },
    Activate {
        id: String,
        material: Value,
        #[serde(default = "no_fault")]
        fault: String,
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
            | Self::Prepare { id, .. }
            | Self::Activate { id, .. }
            | Self::Close { id } => id,
        }
    }
    fn faulted(&self) -> bool {
        match self {
            Self::Prepare { fault, .. } | Self::Activate { fault, .. } => fault != "none",
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
fn no_fault() -> String {
    "none".into()
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
fn read_config(path: &str) -> Result<String> {
    let mut data = String::new();
    File::open(path)
        .and_then(|file| file.take(16385).read_to_string(&mut data))
        .map_err(|_| Error::new("anchor_config", true))?;
    if data.len() > 16384 {
        return Err(Error::new("anchor_config", true));
    }
    Ok(data)
}
fn open_client(args: &[String], locator_path: Option<&str>) -> Result<RebuildClient> {
    if let Some(locator_path) = locator_path {
        #[cfg(feature = "protected-storage")]
        {
            return RebuildClient::open_protected(
                PathBuf::from(&args[0]),
                &read_config(&args[1])?,
                PathBuf::from(&args[2]),
                &read_config(locator_path)?,
                &args[3],
            );
        }
        #[cfg(not(feature = "protected-storage"))]
        {
            let _ = locator_path;
            return Err(Error::new("protected_storage_unavailable", true));
        }
    }
    RebuildClient::open_json(
        PathBuf::from(&args[0]),
        &read_config(&args[1])?,
        PathBuf::from(&args[2]),
        &args[3],
    )
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() < 4 {
        return Err(Error::new("invalid_arguments", false));
    }
    let mut flags = args[4..].iter();
    let mut test_mode = false;
    let mut locator_path = None;
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "--test-mode" => test_mode = true,
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
    let mut client = open_client(&args, locator_path)?;
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
            Command::Prepare { fault, .. } => client.prepare(&fault),
            Command::Activate {
                material, fault, ..
            } => client.activate(material, &fault),
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
