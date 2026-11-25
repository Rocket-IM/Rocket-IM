//! 独立实验权威的有界加密快照；已有/部分目录不能重新初始化。
use super::{authority::State, check, error, Result};
use crate::snapshot;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
const AAD: &[u8] = b"Rocket-IM/POC/startup-authority-storage/v1";
const LIMIT: usize = 128 * 1024;
pub(super) struct Store {
    directory: PathBuf,
    key: [u8; 32],
    _lock: File,
}
fn io<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|_| error())
}
fn file(path: &Path, create: bool) -> Result<File> {
    let f = io(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path))?;
    let m = io(f.metadata())?;
    check(
        m.is_file() && m.permissions().mode() & 0o777 == 0o600 && m.len() <= (LIMIT + 64) as u64,
        "startup_file",
    )?;
    Ok(f)
}
impl Store {
    pub(super) fn create(directory: &Path) -> Result<Self> {
        check(directory.is_absolute(), "startup_directory")?;
        io(fs::DirBuilder::new().mode(0o700).create(directory))?;
        let mut key = [0; 32];
        getrandom::getrandom(&mut key).map_err(|_| error())?;
        let mut f = file(&directory.join("authority.key"), true)?;
        io(f.write_all(&key))?;
        io(f.sync_all())?;
        let _ = file(&directory.join("writer.lock"), true)?;
        io(File::open(directory.parent().ok_or_else(error)?))?
            .sync_all()
            .map_err(|_| error())?;
        Self::open(directory)
    }
    pub(super) fn open(directory: &Path) -> Result<Self> {
        check(directory.is_absolute(), "startup_directory")?;
        let m = io(fs::symlink_metadata(directory))?;
        check(
            m.is_dir() && !m.file_type().is_symlink() && m.permissions().mode() & 0o777 == 0o700,
            "startup_directory",
        )?;
        let lock = file(&directory.join("writer.lock"), false)?;
        lock.try_lock()
            .map_err(|_| super::PermissionError::new("startup_busy", "启动权威正被其他进程占用"))?;
        let mut keyfile = file(&directory.join("authority.key"), false)?;
        check(io(keyfile.metadata())?.len() == 32, "startup_key")?;
        let mut key = [0; 32];
        io(keyfile.read_exact(&mut key))?;
        // 受控退出留下的临时文件不成为恢复输入；容量有限且仅在持锁后清理。
        let entries = io(fs::read_dir(directory))?
            .take(9)
            .collect::<std::io::Result<Vec<_>>>();
        let entries = io(entries)?;
        check(entries.len() <= 8, "startup_capacity")?;
        for e in entries {
            let name = e.file_name();
            let name = name.to_str().ok_or_else(error)?;
            if ["writer.lock", "authority.key", "state.enc"].contains(&name) {
                continue;
            }
            let suffix = name
                .strip_prefix(".snapshot-")
                .and_then(|n| n.strip_suffix(".tmp"));
            check(
                suffix.is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())),
                "startup_file",
            )?;
            file(&e.path(), false)?;
            io(fs::remove_file(e.path()))?;
        }
        io(File::open(directory))?.sync_all().map_err(|_| error())?;
        Ok(Self {
            directory: directory.into(),
            key,
            _lock: lock,
        })
    }
    pub(super) fn load(&self) -> Result<State> {
        file(&self.directory.join("state.enc"), false)?;
        let raw = snapshot::load(&self.directory.join("state.enc"), &self.key, AAD)
            .map_err(|_| error())?;
        check(raw.len() <= LIMIT, "startup_limit")?;
        let s: State = serde_json::from_slice(&raw).map_err(|_| error())?;
        s.validate()?;
        Ok(s)
    }
    pub(super) fn save(&self, state: &State, fail: &str) -> Result<()> {
        state.validate()?;
        let raw = serde_json::to_vec(state).map_err(|_| error())?;
        check(raw.len() <= LIMIT, "startup_limit")?;
        if fail == "before_save" {
            std::process::exit(86);
        }
        snapshot::save_with_hook(
            &self.directory.join("state.enc"),
            &self.key,
            AAD,
            &raw,
            |point| {
                if fail == "before_rename" && point == snapshot::SavePoint::BeforeRename {
                    std::process::exit(87);
                }
            },
        )
        .map_err(|_| error())?;
        if fail == "after_save" {
            std::process::exit(88);
        }
        Ok(())
    }
}
