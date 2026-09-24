//! JSONL 命令行验收装置；仅 --test-mode 接受故障、种子库与第二连接读锁。
use std::{
    env,
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    sync::mpsc::{Receiver, TryRecvError},
    thread,
    time::Duration,
};

use rockets_native_storage_probe::{
    model::{Error, Fault, OpenOptions, Put, Scope},
    Change, Engine, Reply,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Snapshot {
        id: String,
        #[serde(default)]
        fault: Fault,
    },
    Put {
        id: String,
        expected_revision: String,
        key: String,
        value: String,
        #[serde(default)]
        fault: Fault,
    },
    Subscribe {
        id: String,
    },
    Unsubscribe {
        id: String,
    },
    Close {
        id: String,
    },
}

fn emit(value: serde_json::Value) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &value)?;
    writeln!(output)?;
    output.flush()
}

fn drain(receiver: &Option<Receiver<Change>>) -> (Vec<Change>, bool) {
    let mut events = vec![];
    let Some(receiver) = receiver else {
        return (events, false);
    };
    loop {
        match receiver.try_recv() {
            Ok(event) => events.push(event),
            Err(TryRecvError::Empty) => return (events, false),
            Err(TryRecvError::Disconnected) => return (events, true),
        }
    }
}

fn respond(id: String, reply: Reply, receiver: &Option<Receiver<Change>>) -> io::Result<()> {
    let (events, disconnected) = drain(receiver);
    let (result, error) = match reply.result {
        Ok(value) => (value, None),
        Err(error) => (None, Some(error)),
    };
    emit(
        json!({"id":id,"ok":error.is_none(),"result":result,"error":error,
        "events":events,"subscription_disconnected":disconnected,
        "notification":reply.notification,"trace":reply.trace,"worker_thread":reply.worker_thread,
        "caller_thread":format!("{:?}",thread::current().id())}),
    )
}

fn reject(id: String, code: &str) -> io::Result<()> {
    emit(
        json!({"id":id,"ok":false,"result":null,"error":Error::new(code,false),
                "trace":[],"events":[],"subscription_disconnected":false,"notification":"idle"}),
    )
}

fn main() {
    if let Err(error) = run() {
        let _ = emit(json!({"ready":false,"error":error,"trace":[]}));
        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 3 {
        return Err(Error::new("invalid_arguments", false));
    }
    let path = PathBuf::from(&args[0]);
    let flags = &args[3..];
    let allowed = [
        "--test-mode",
        "--seed-v1",
        "--fail-migration",
        "--hold-reader",
    ];
    if flags.iter().any(|flag| !allowed.contains(&flag.as_str())) {
        return Err(Error::new("invalid_arguments", false));
    }
    let test_mode = flags.iter().any(|flag| flag == "--test-mode");
    let has = |flag: &str| flags.iter().any(|value| value == flag);
    if !test_mode && flags.iter().any(|flag| flag != "--test-mode") {
        return Err(Error::new("test_mode_required", false));
    }
    if has("--hold-reader") {
        return hold_reader(path);
    }
    let engine = Engine::open(
        path,
        Scope {
            service: args[1].clone(),
            account: args[2].clone(),
        },
        OpenOptions {
            seed_v1: has("--seed-v1"),
            fail_migration: has("--fail-migration"),
        },
    )?;
    emit(json!({"ready":true,"trace":engine.startup.trace,"worker_thread":engine.startup.worker_thread,
                "caller_thread":format!("{:?}",thread::current().id())})).map_err(io_error)?;
    let client = engine.client();
    let mut subscriber = None;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut line = String::new();
        let length = (&mut input)
            .take(32769)
            .read_line(&mut line)
            .map_err(io_error)?;
        if length == 0 {
            break;
        }
        if length > 32768 || !line.ends_with('\n') {
            reject(String::new(), "request_too_large_or_incomplete").map_err(io_error)?;
            break;
        }
        let request: Request = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => {
                reject(String::new(), "invalid_request").map_err(io_error)?;
                continue;
            }
        };
        let (id, fault) = match &request {
            Request::Put { id, fault, .. } | Request::Snapshot { id, fault } => (id, *fault),
            Request::Subscribe { id } | Request::Unsubscribe { id } | Request::Close { id } => {
                (id, Fault::None)
            }
        };
        if id.is_empty() || id.len() > 128 || id.contains('\0') {
            reject(String::new(), "invalid_request_id").map_err(io_error)?;
            continue;
        }
        if !test_mode && fault != Fault::None {
            reject(id.clone(), "test_mode_required").map_err(io_error)?;
            continue;
        }
        let closing = matches!(request, Request::Close { .. });
        let (id, reply) = match request {
            Request::Snapshot { id, fault } => (id, client.snapshot(fault)),
            Request::Put {
                id,
                expected_revision,
                key,
                value,
                fault,
            } => (
                id,
                client.put(Put {
                    expected_revision,
                    key,
                    value,
                    fault,
                }),
            ),
            Request::Subscribe { id } => {
                let (reply, receiver) = client.subscribe();
                if reply.result.is_ok() {
                    subscriber = Some(receiver);
                }
                (id, reply)
            }
            Request::Unsubscribe { id } => {
                let reply = client.unsubscribe();
                subscriber = None;
                (id, reply)
            }
            Request::Close { id } => (id, client.close()),
        };
        respond(id, reply, &subscriber).map_err(io_error)?;
        if closing {
            break;
        }
    }
    engine.close()
}

fn io_error(_: io::Error) -> Error {
    Error::new("control_io_failed", false)
}

fn hold_reader(path: PathBuf) -> Result<(), Error> {
    // 仅测试装置的第二个 Rust 连接；不提供宿主 SQL 入口或生产多连接实现。
    let mut connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(Error::database)?;
    let transaction = connection.transaction().map_err(Error::database)?;
    let read = transaction.query_row("SELECT revision FROM scope WHERE id = 1", [], |row| {
        row.get::<_, String>(0)
    });
    if let Err(error) = read {
        transaction.rollback().map_err(Error::database)?;
        connection
            .close()
            .map_err(|(_, error)| Error::database(error))?;
        return Err(Error::database(error));
    }
    let diagnostic = (|| -> io::Result<()> {
        let mut output = io::stderr().lock();
        writeln!(
            output,
            "{}",
            json!({"checkpoint":"reader_held","pid":std::process::id()})
        )?;
        output.flush()
    })();
    if diagnostic.is_err() {
        transaction.rollback().map_err(Error::database)?;
        connection
            .close()
            .map_err(|(_, error)| Error::database(error))?;
        return Err(Error::new("control_io_failed", false));
    }
    thread::sleep(Duration::from_secs(10));
    transaction.rollback().map_err(Error::database)?;
    connection
        .close()
        .map_err(|(_, error)| Error::database(error))?;
    Err(Error::new("checkpoint_timeout", false))
}
