use std::{cell::RefCell, io::Write, time::Duration};

use rusqlite::{
    trace::{TraceEvent, TraceEventCodes},
    Connection,
};

use crate::model::{Error, Result};

thread_local! {
    static TRACE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn record(keyword: &str) {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if trace.len() < 4096 {
            trace.push(keyword.to_owned());
        } else if trace.len() == 4096 {
            trace.push("TRACE_TRUNCATED".to_owned());
        }
    });
}

pub(crate) fn install(connection: &Connection) {
    connection.trace_v2(
        TraceEventCodes::SQLITE_TRACE_STMT,
        Some(|event| {
            if let TraceEvent::Stmt(_, sql) = event {
                // 只保留固定首关键字，不展开绑定值，不收集 SQL 正文。
                let keyword = sql.split_whitespace().next().unwrap_or("");
                match keyword {
                    "BEGIN" | "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "ALTER"
                    | "PRAGMA" | "COMMIT" | "ROLLBACK" => record(keyword),
                    _ => record("OTHER"),
                }
            }
        }),
    );
}

pub(crate) fn automatic_rollback() {
    // SQLite 自动回滚不会执行一条可被 trace_v2 记录的 ROLLBACK SQL。
    record("ROLLBACK_AUTOMATIC");
}

pub fn take_trace() -> Vec<String> {
    TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()))
}

pub fn checkpoint(stage: &str) -> Result<()> {
    if !matches!(stage, "before_commit" | "after_commit") {
        return Err(Error::new("invalid_checkpoint", false));
    }
    let mut output = std::io::stderr().lock();
    writeln!(
        output,
        "{}",
        serde_json::json!({"checkpoint": stage, "pid": std::process::id()})
    )
    .and_then(|()| output.flush())
    .map_err(|_| Error::new("checkpoint_output_failed", true))?;
    drop(output);
    // 父进程等待该标记后执行真实 kill；无控制器时有界退出且不报告成功。
    std::thread::sleep(Duration::from_secs(10));
    Err(Error::new("checkpoint_timeout", true))
}
