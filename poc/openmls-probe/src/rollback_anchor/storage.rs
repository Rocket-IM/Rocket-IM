//! 锚专用有界加密快照与单写锁；拒绝已有目录初始化及部分恢复。
use super::{
    authority::{Failpoint, State},
    invalid, AnchorError,
};
use crate::snapshot;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

const STATE_LIMIT: usize = 16 * 1024;
const CONTEXT: &[u8] = b"Rocket-IM/POC/synthetic-local-rollback-anchor/v1";

fn io_error() -> AnchorError {
    AnchorError::new("anchor_io", "独立锚存储不可用、权限错误或完整性验证失败")
}

pub(super) struct LockedAnchor {
    directory: PathBuf,
    key: [u8; 32],
    _lock: File,
}

fn check_directory(directory: &Path, private: bool) -> Result<(), AnchorError> {
    if !directory.is_absolute() || directory.as_os_str().len() > 4096 {
        return Err(invalid());
    }
    let mut current = PathBuf::new();
    for component in directory.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            _ => return Err(invalid()),
        }
        let meta = fs::symlink_metadata(&current).map_err(|_| io_error())?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(io_error());
        }
    }
    if private
        && fs::metadata(directory)
            .map_err(|_| io_error())?
            .permissions()
            .mode()
            & 0o777
            != 0o700
    {
        return Err(io_error());
    }
    Ok(())
}

fn private_file(path: &Path, create: bool) -> Result<File, AnchorError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| io_error())?;
    let meta = file.metadata().map_err(|_| io_error())?;
    if !meta.is_file() || meta.permissions().mode() & 0o777 != 0o600 {
        return Err(io_error());
    }
    Ok(file)
}

fn lock(directory: &Path, create: bool) -> Result<File, AnchorError> {
    let file = private_file(&directory.join("writer.lock"), create)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            Err(AnchorError::new("anchor_busy", "另一个进程正在操作独立锚"))
        }
        Err(_) => Err(io_error()),
    }
}

/// 专用目录限 8 项；受控退出残留只在锁内删除，不作为恢复输入。
fn cleanup(directory: &Path) -> Result<(), AnchorError> {
    let entries = fs::read_dir(directory)
        .map_err(|_| io_error())?
        .take(9)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io_error())?;
    if entries.len() > 8 {
        return Err(AnchorError::new("anchor_capacity", "锚目录超出固定容量"));
    }
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(invalid)?;
        if ["anchor.key", "state.enc", "writer.lock"].contains(&name) {
            continue;
        }
        let suffix = name
            .strip_prefix(".snapshot-")
            .and_then(|n| n.strip_suffix(".tmp"));
        if !suffix.is_some_and(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(io_error());
        }
        let file = private_file(&entry.path(), false)?;
        if file.metadata().map_err(|_| io_error())?.len() > (STATE_LIMIT + 64) as u64 {
            return Err(io_error());
        }
        fs::remove_file(entry.path()).map_err(|_| io_error())?;
    }
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())
}

impl LockedAnchor {
    pub(super) fn initialize(directory: &Path, state: &State) -> Result<Self, AnchorError> {
        if !directory.is_absolute() || directory.as_os_str().len() > 4096 {
            return Err(invalid());
        }
        check_directory(directory.parent().ok_or_else(invalid)?, false)?;
        // create 而不是 create_dir_all；已有锚或失败初始化绝不覆盖、重新生成或解绑。
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(|_| io_error())?;
        check_directory(directory, true)?;
        let lock = lock(directory, true)?;
        let mut key = [0; 32];
        getrandom::getrandom(&mut key).map_err(|_| io_error())?;
        let mut file = private_file(&directory.join("anchor.key"), true)?;
        file.write_all(&key)
            .and_then(|_| file.sync_all())
            .map_err(|_| io_error())?;
        let anchor = LockedAnchor {
            directory: directory.to_owned(),
            key,
            _lock: lock,
        };
        anchor.save(state, Failpoint::None)?;
        File::open(directory.parent().ok_or_else(invalid)?)
            .and_then(|file| file.sync_all())
            .map_err(|_| io_error())?;
        Ok(anchor)
    }

    pub(super) fn open(directory: &Path) -> Result<Self, AnchorError> {
        check_directory(directory, true)?;
        let lock = lock(directory, false)?;
        cleanup(directory)?;
        let mut file = private_file(&directory.join("anchor.key"), false)?;
        if file.metadata().map_err(|_| io_error())?.len() != 32 {
            return Err(io_error());
        }
        let mut key = [0; 32];
        file.read_exact(&mut key).map_err(|_| io_error())?;
        Ok(Self {
            directory: directory.to_owned(),
            key,
            _lock: lock,
        })
    }

    pub(super) fn load(&self) -> Result<State, AnchorError> {
        let file = private_file(&self.directory.join("state.enc"), false)?;
        if file.metadata().map_err(|_| io_error())?.len() > (STATE_LIMIT + 64) as u64 {
            return Err(io_error());
        }
        let raw = snapshot::load(&self.directory.join("state.enc"), &self.key, CONTEXT)
            .map_err(|_| io_error())?;
        if raw.len() > STATE_LIMIT {
            return Err(invalid());
        }
        let state: State = serde_json::from_slice(&raw).map_err(|_| invalid())?;
        state.validate()?;
        Ok(state)
    }

    pub(super) fn save(&self, state: &State, failpoint: Failpoint) -> Result<(), AnchorError> {
        state.validate()?;
        let raw = serde_json::to_vec(state).map_err(|_| invalid())?;
        if raw.len() > STATE_LIMIT {
            return Err(invalid());
        }
        if matches!(failpoint, Failpoint::BeforeSave) {
            std::process::exit(91);
        }
        snapshot::save_with_hook(
            &self.directory.join("state.enc"),
            &self.key,
            CONTEXT,
            &raw,
            |_| {
                if matches!(failpoint, Failpoint::BeforeRename) {
                    std::process::exit(92);
                }
            },
        )
        .map_err(|_| io_error())?;
        if matches!(failpoint, Failpoint::AfterSave) {
            std::process::exit(93);
        }
        Ok(())
    }
}
