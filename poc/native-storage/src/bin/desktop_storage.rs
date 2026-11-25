//! Node 桌面存储实验的有界公开进程边界；不接受故障、内存对端或 SQL 命令。
use rocket_native_storage_probe::{
    crypto::{
        contract::{Action, DownloadRecord, DownloadRequest, Fault, Request, Scope},
        model::{Envelope, Identity},
        Client, Reply,
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

const VERSION: &str = "0.1.0-stage0.1";
const MAX_LINE: u64 = 262_144;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Initialize {
        request_id: String,
    },
    CreateGroup {
        request_id: String,
        conversation: String,
        peer: Identity,
    },
    Send {
        request_id: String,
        attempt_id: String,
        message_id: String,
        text: String,
    },
    Receive {
        request_id: String,
        sequence: String,
        envelope: Envelope,
    },
    Download {
        records: Vec<DownloadRecord>,
    },
    Process {
        request_id: String,
        sequence: String,
    },
    Received {
        sequence: String,
    },
    State {},
    Close {},
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    id: String,
    operation: Operation,
}
fn emit(value: Value) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &value).map_err(|_| Error::new("ipc_write_failed", true))?;
    writeln!(output)
        .and_then(|()| output.flush())
        .map_err(|_| Error::new("ipc_write_failed", true))
}
fn error_value(error: Error) -> Value {
    json!({"code":error.code,"paused":error.paused})
}
fn reject(id: &str, error: Error) -> Value {
    json!({"id":id,"ok":false,"result":null,"error":error_value(error),"events":[]})
}
fn execute(client: &mut Client, request_id: String, action: Action) -> Reply {
    client.execute(Request {
        request_id,
        action,
        fault: Fault::None,
    })
}
fn dispatch(client: &mut Client, operation: Operation) -> Reply {
    match operation {
        Operation::Initialize { request_id } => execute(client, request_id, Action::Initialize {}),
        Operation::CreateGroup {
            request_id,
            conversation,
            peer,
        } => execute(
            client,
            request_id,
            Action::CreateGroup { conversation, peer },
        ),
        Operation::Send {
            request_id,
            attempt_id,
            message_id,
            text,
        } => execute(
            client,
            request_id,
            Action::Send {
                attempt_id,
                message_id,
                text,
            },
        ),
        Operation::Receive {
            request_id,
            sequence,
            envelope,
        } => execute(client, request_id, Action::Receive { sequence, envelope }),
        Operation::Download { records } => client.download(DownloadRequest {
            records,
            fault: Fault::None,
        }),
        Operation::Process {
            request_id,
            sequence,
        } => client.process(&request_id, &sequence, Fault::None),
        Operation::Received { sequence } => client.received(&sequence),
        Operation::State {} => {
            let mut reply = client.inspect();
            // 宿主只取得业务状态；provider/诊断摘要和计数不属于此包的 API。
            if let Some(state) = &reply.result {
                reply.result = Some(json!({
                    "scope":state["scope"], "revision":state["revision"],
                    "identity":state["identity"], "conversation":state["conversation"],
                    "pending":!state["pending"].is_null(), "outbox":state["outbox"],
                    "processed_cursor":state["processed_cursor"],
                    "download_cursor":state["download_cursor"],
                    "received_count":state["inbox"].as_array().map_or(0, Vec::len)
                }));
            }
            reply
        }
        Operation::Close {} => client.close(),
    }
}
fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 5 || !matches!(args[4].as_str(), "create" | "open") {
        return Err(Error::new("invalid_arguments", false));
    }
    let scope = Scope {
        service: args[1].clone(),
        account: args[2].clone(),
        device: args[3].clone(),
    };
    let mut client = Client::open(PathBuf::from(&args[0]), scope.clone(), args[4] == "create")?;
    let (database_thread, _) = client.startup();
    emit(
        json!({"ready":true,"protocol":1,"version":VERSION,"scope":scope,
        "runtime":{"pid":std::process::id(),"os":env::consts::OS,"arch":env::consts::ARCH,
            "databaseThread":database_thread,"coordinatorThread":format!("{:?}",thread::current().id())}}),
    )?;
    let mut input = io::stdin().lock();
    loop {
        let mut line = String::new();
        let size = (&mut input)
            .take(MAX_LINE + 1)
            .read_line(&mut line)
            .map_err(|_| Error::new("ipc_read_failed", true))?;
        if size == 0 {
            break;
        }
        if size as u64 > MAX_LINE || !line.ends_with('\n') {
            emit(reject(
                "",
                Error::new("request_too_large_or_incomplete", false),
            ))?;
            break;
        }
        let command: Command = match serde_json::from_str(&line) {
            Ok(command) => command,
            Err(_) => {
                emit(reject("", Error::new("invalid_request", false)))?;
                continue;
            }
        };
        if command.id.is_empty() || command.id.len() > 128 || command.id.contains('\0') {
            emit(reject("", Error::new("invalid_request_id", false)))?;
            continue;
        }
        let closing = matches!(command.operation, Operation::Close {});
        let reply = dispatch(&mut client, command.operation);
        emit(json!({"id":command.id,"ok":reply.ok,"result":reply.result,
            "error":reply.error.map(error_value),"events":reply.events}))?;
        if closing {
            break;
        }
    }
    if let Some(error) = client.close().error {
        return Err(error);
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        let _ = emit(json!({"ready":false,"error":error_value(error)}));
        std::process::exit(1);
    }
}
