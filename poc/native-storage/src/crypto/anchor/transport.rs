//! 有界单次 stdio helper 调用；超时或输出超限时杀死隔离进程组并回收。
use super::protocol::INPUT_LIMIT;
use crate::model::{Error, Result};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct Output {
    pub stdout: String,
    pub success: bool,
}

enum Completed {
    Written(std::io::Result<()>),
    Stdout(std::io::Result<Vec<u8>>),
    Stderr(std::io::Result<Vec<u8>>),
}

struct Running {
    child: Child,
    workers: Vec<JoinHandle<()>>,
    reaped: bool,
}

impl Drop for Running {
    fn drop(&mut self) {
        // helper 启动于自己的进程组，异常路径也关闭继承管道的子进程。
        if !self.reaped {
            terminate(&mut self.child);
            let _ = self.child.wait();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn failed() -> Error {
    Error::new("anchor_rpc_failed", true)
}

fn read_bounded(reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(OUTPUT_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn spawn_worker(running: &mut Running, work: impl FnOnce() + Send + 'static) -> Result<()> {
    let worker = thread::Builder::new()
        .name("native-anchor-pipe".into())
        .spawn(work)
        .map_err(|_| failed())?;
    running.workers.push(worker);
    Ok(())
}

pub(crate) fn exchange(program: &Path, input: &[u8]) -> Result<Output> {
    if input.len() > INPUT_LIMIT {
        return Err(Error::new("anchor_rpc_limit", true));
    }
    let mut command = Command::new(program);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    // 仅旧 helper 的已有环境故障开关会被继承；协议不提供自动重试。
    let child = command.spawn().map_err(|_| failed())?;
    let mut running = Running {
        child,
        workers: Vec::new(),
        reaped: false,
    };
    let mut stdin = running.child.stdin.take().ok_or_else(failed)?;
    let stdout = running.child.stdout.take().ok_or_else(failed)?;
    let stderr = running.child.stderr.take().ok_or_else(failed)?;
    let (sender, receiver) = mpsc::channel();
    let input = input.to_vec();
    let written_sender = sender.clone();
    spawn_worker(&mut running, move || {
        let result = stdin.write_all(&input).and_then(|()| stdin.flush());
        drop(stdin);
        let _ = written_sender.send(Completed::Written(result));
    })?;
    let stdout_sender = sender.clone();
    spawn_worker(&mut running, move || {
        let _ = stdout_sender.send(Completed::Stdout(read_bounded(stdout)));
    })?;
    spawn_worker(&mut running, move || {
        let _ = sender.send(Completed::Stderr(read_bounded(stderr)));
    })?;
    let deadline = Instant::now() + TIMEOUT;
    let mut output = None;
    let mut stderr_done = false;
    let mut written = false;
    loop {
        if Instant::now() >= deadline {
            return Err(Error::new("anchor_rpc_timeout", true));
        }
        match receiver.recv_timeout(Duration::from_millis(5)) {
            Ok(Completed::Written(result)) => {
                result.map_err(|_| failed())?;
                written = true;
            }
            Ok(Completed::Stdout(result)) => {
                let bytes = result.map_err(|_| failed())?;
                if bytes.len() > OUTPUT_LIMIT {
                    return Err(Error::new("anchor_rpc_limit", true));
                }
                output = Some(String::from_utf8(bytes).map_err(|_| failed())?);
            }
            Ok(Completed::Stderr(result)) => {
                let bytes = result.map_err(|_| failed())?;
                if bytes.len() > OUTPUT_LIMIT {
                    return Err(Error::new("anchor_rpc_limit", true));
                }
                stderr_done = true;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => thread::sleep(Duration::from_millis(5)),
        }
        if written && stderr_done && output.is_some() {
            // 先收齐管道，再 reap：异常期间保留子 PID，避免对已复用的进程组发信号。
            if let Some(status) = running.child.try_wait().map_err(|_| failed())? {
                running.reaped = true;
                return Ok(Output {
                    stdout: output.take().ok_or_else(failed)?,
                    success: status.success(),
                });
            }
        }
    }
}

fn terminate(child: &mut Child) {
    #[cfg(unix)]
    {
        extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        if let Ok(group) = i32::try_from(child.id()) {
            // 安全边界：process_group(0) 创建了以子进程 PID 命名的独立组；
            // 负 PID 仅向该组发 SIGKILL，不传递指针，不影响调用进程所在组。
            unsafe {
                kill(-group, 9);
            }
        }
    }
    let _ = child.kill();
}
