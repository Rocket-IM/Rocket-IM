//! 锚调用和本机辅助记录都有界；辅助文件不是独立防回滚根。
use super::{checked, ensure, LabError};
use crate::{rollback_anchor as protocol, snapshot};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(super) const LIMIT: usize = 32 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub protocol_version: String,
    pub scope: protocol::Scope,
    pub anchor_public_key: String,
    pub client_seed: String,
    pub journal_key: String,
    pub helper_path: PathBuf,
    pub anchor_directory: PathBuf,
    #[serde(default)]
    pub rebuild_trust: Option<protocol::rebuild::RebuildTrust>,
}

pub(super) fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, LabError> {
    let file = checked(
        "anchor_file",
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path),
    )?;
    let meta = checked("anchor_file", file.metadata())?;
    ensure(
        meta.is_file() && meta.permissions().mode() & 0o777 == 0o600,
        "anchor_file",
        "锚配置/设备记录必须是0600普通文件",
    )?;
    ensure(meta.len() <= limit as u64, "anchor_limit", "锚记录超过上限")?;
    let mut bytes = Vec::new();
    checked(
        "anchor_read",
        file.take(limit as u64 + 1).read_to_end(&mut bytes),
    )?;
    ensure(bytes.len() <= limit, "anchor_limit", "锚记录超过上限")?;
    Ok(bytes)
}

pub(super) fn state_hash(directory: &Path) -> Result<String, LabError> {
    // 原快照头为8字节magic、1版本、12 nonce、16 tag；不读入无限文件。
    Ok(protocol::hash_bytes(&read_file(
        &directory.join("state.enc"),
        snapshot::MAX_PLAINTEXT_BYTES + 37,
    )?))
}

pub(super) fn random_hex() -> Result<String, LabError> {
    let mut value = [0; 32];
    checked("anchor_random", getrandom::getrandom(&mut value))?;
    Ok(value.iter().map(|byte| format!("{byte:02x}")).collect())
}

impl Config {
    pub fn load(path: &Path, directory: &Path) -> Result<Self, LabError> {
        ensure(
            path.is_absolute(),
            "anchor_config",
            "可信配置必须是绝对路径",
        )?;
        let config: Self = checked(
            "anchor_config",
            serde_json::from_slice(&read_file(path, LIMIT)?),
        )?;
        ensure(
            config.protocol_version == "rim-rollback-client-1"
                && config.helper_path.is_absolute()
                && config.anchor_directory.is_absolute(),
            "anchor_config",
            "锚配置版本或绝对路径无效",
        )?;
        checked("anchor_key", protocol::decode_hex(&config.client_seed))?;
        checked("anchor_key", protocol::decode_hex(&config.journal_key))?;
        checked(
            "anchor_key",
            protocol::decode_hex(&config.anchor_public_key),
        )?;
        // 这只是排除显然同目录配置，并不能证明独立故障域。
        let local = checked("anchor_config", fs::canonicalize(directory))?;
        let config_path = checked("anchor_config", fs::canonicalize(path))?;
        let anchor = checked("anchor_config", fs::canonicalize(&config.anchor_directory))?;
        let parent = config_path
            .parent()
            .ok_or_else(|| LabError::new("anchor_config", "可信配置缺少父目录"))?;
        ensure(
            checked("anchor_config", fs::metadata(parent))?
                .permissions()
                .mode()
                & 0o777
                == 0o700,
            "anchor_config",
            "可信配置父目录必须是0700",
        )?;
        ensure(
            !config_path.starts_with(&local)
                && !anchor.starts_with(&local)
                && !local.starts_with(&anchor)
                && !config_path.starts_with(&anchor),
            "anchor_config",
            "设备、锚及客户端可信配置必须分开保存",
        )?;
        Ok(config)
    }

    fn aad(&self, domain: &str) -> Result<Vec<u8>, LabError> {
        checked(
            "anchor_encoding",
            serde_json::to_vec(&(domain, &self.scope, &self.anchor_public_key)),
        )
    }

    pub fn save<T: Serialize>(
        &self,
        path: &Path,
        domain: &str,
        record: &T,
    ) -> Result<(), LabError> {
        let bytes = checked("anchor_encoding", serde_json::to_vec(record))?;
        ensure(bytes.len() <= LIMIT, "anchor_limit", "锚辅助记录超过32KiB")?;
        checked(
            "anchor_local_save",
            snapshot::save(
                path,
                &checked("anchor_key", protocol::decode_hex(&self.journal_key))?,
                &self.aad(domain)?,
                &bytes,
                snapshot::Failpoint::None,
            ),
        )
    }

    pub fn load_record<T: DeserializeOwned>(
        &self,
        path: &Path,
        domain: &str,
    ) -> Result<T, LabError> {
        read_file(path, LIMIT + 37)?;
        let bytes = checked(
            "anchor_journal",
            snapshot::load(
                path,
                &checked("anchor_key", protocol::decode_hex(&self.journal_key))?,
                &self.aad(domain)?,
            ),
        )?;
        checked("anchor_journal", serde_json::from_slice(&bytes))
    }

    pub fn rpc(
        &self,
        action: protocol::Action,
        txn: &str,
        head: &str,
        target: &str,
        expected_revision: &str,
    ) -> Result<protocol::Response, LabError> {
        let request = protocol::Request {
            protocol_version: protocol::PROTOCOL.into(),
            scope: self.scope.clone(),
            challenge: random_hex()?,
            action,
            txn: txn.into(),
            head: head.into(),
            target: target.into(),
            expected_revision: expected_revision.into(),
        };
        let signed = checked(
            "anchor_request",
            protocol::sign_request(
                &request,
                &checked("anchor_key", protocol::decode_hex(&self.client_seed))?,
            ),
        )?;
        let input = checked(
            "anchor_encoding",
            serde_json::to_vec(&serde_json::json!({
                "op":"request", "directory":self.anchor_directory, "request":signed,
            })),
        )?;
        let output = invoke(&self.helper_path, &input)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            ok: bool,
            response: protocol::Signed,
        }
        let reply: Reply = checked("anchor_response", serde_json::from_slice(&output))?;
        ensure(reply.ok, "anchor_response", "独立锚未返回可核验响应")?;
        checked(
            "anchor_response",
            protocol::verify_response(&reply.response, &self.anchor_public_key, &signed),
        )
    }
}

pub(super) fn remove(path: &Path) -> Result<(), LabError> {
    match fs::remove_file(path) {
        Ok(()) => checked(
            "anchor_sync",
            checked(
                "anchor_directory",
                File::open(
                    path.parent()
                        .ok_or_else(|| LabError::new("anchor_directory", "辅助记录缺少父目录"))?,
                ),
            )?
            .sync_all(),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LabError::new("anchor_remove", error.to_string())),
    }
}

fn nonblocking(fd: i32) -> Result<(), LabError> {
    // SAFETY: fd 是当前持有的管道；fcntl 不转移所有权。
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure(flags >= 0, "anchor_pipe", "无法读取管道标志")?;
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    ensure(result >= 0, "anchor_pipe", "无法设置有界非阻塞管道")
}

pub(super) fn invoke(path: &Path, input: &[u8]) -> Result<Vec<u8>, LabError> {
    ensure(input.len() <= LIMIT, "anchor_limit", "锚请求超过32KiB")?;
    let mut child = checked(
        "anchor_unavailable",
        Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn(),
    )?;
    let result = (|| {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| LabError::new("anchor_pipe", "缺少输入管道"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| LabError::new("anchor_pipe", "缺少输出管道"))?;
        nonblocking(stdin.as_raw_fd())?;
        nonblocking(stdout.as_raw_fd())?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut written = 0;
        while written < input.len() {
            ensure(Instant::now() < deadline, "anchor_timeout", "独立锚3秒超时")?;
            match stdin.write(&input[written..]) {
                Ok(0) => return Err(LabError::new("anchor_pipe", "输入管道提前关闭")),
                Ok(size) => written += size,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => return Err(LabError::new("anchor_pipe", error.to_string())),
            }
        }
        drop(stdin);
        let mut output = Vec::new();
        loop {
            ensure(Instant::now() < deadline, "anchor_timeout", "独立锚3秒超时")?;
            let mut chunk = [0; 4096];
            match stdout.read(&mut chunk) {
                Ok(0) => {
                    if let Some(status) = checked("anchor_wait", child.try_wait())? {
                        ensure(
                            status.success(),
                            "anchor_unavailable",
                            "独立锚退出且没有成功响应",
                        )?;
                        return Ok(output);
                    }
                }
                Ok(size) => {
                    output.extend_from_slice(&chunk[..size]);
                    ensure(output.len() <= LIMIT, "anchor_limit", "锚响应超过32KiB")?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(LabError::new("anchor_pipe", error.to_string())),
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })();
    // 所有错误/超时路径都回收子进程，禁止让失败的锚调用留在后台。
    if result.is_err() {
        let _ = child.kill();
    }
    let waited = checked("anchor_wait", child.wait());
    match result {
        Ok(output) => {
            waited?;
            Ok(output)
        }
        Err(error) => Err(error),
    }
}
