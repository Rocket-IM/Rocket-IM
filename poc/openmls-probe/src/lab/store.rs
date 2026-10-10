use super::{checked, ensure, state::DeviceState, Context, CrashPoint, LabError};
use crate::snapshot::{self, SavePoint};
use std::{
    cell::Cell,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(super) struct LockedDevice {
    directory: PathBuf,
    _lock: File,
    key: [u8; 32],
    pub saved_commitment: Cell<Option<[u8; 32]>>,
}

fn private_file(path: &Path, create: bool) -> Result<File, LabError> {
    let file = checked(
        "device_file",
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path),
    )?;
    let metadata = checked("file_metadata", file.metadata())?;
    ensure(
        metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600,
        "file_permissions",
        "设备文件必须是 0600 普通文件",
    )?;
    Ok(file)
}

impl LockedDevice {
    pub fn open(directory: &Path) -> Result<Self, LabError> {
        ensure(
            directory.is_absolute(),
            "directory",
            "设备目录必须使用绝对路径",
        )?;
        if !directory.exists() {
            checked(
                "directory_create",
                fs::DirBuilder::new().mode(0o700).create(directory),
            )?;
        }
        let metadata = checked("directory_metadata", fs::symlink_metadata(directory))?;
        ensure(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o777 == 0o700,
            "directory_permissions",
            "设备目录必须是 0700 且不可为符号链接",
        )?;
        let lock = private_file(&directory.join("writer.lock"), true)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(LabError::new("busy", "另一个进程正在处理此设备"))
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(LabError::new("file_lock", error.to_string()))
            }
        }
        let key_path = directory.join("device.key");
        let mut key = [0u8; 32];
        if key_path.exists() {
            let mut file = private_file(&key_path, false)?;
            ensure(
                checked("key_metadata", file.metadata())?.len() == 32,
                "key_length",
                "设备快照密钥长度不匹配",
            )?;
            checked("key_read", file.read_exact(&mut key))?;
        } else {
            ensure(
                !directory.join("state.enc").exists(),
                "missing_key",
                "存在快照但缺少设备密钥，不能覆盖",
            )?;
            checked("random_source", getrandom::getrandom(&mut key))?;
            let mut file = checked(
                "key_create",
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&key_path),
            )?;
            checked("key_write", file.write_all(&key))?;
            checked("key_sync", file.sync_all())?;
            checked(
                "directory_sync",
                checked("directory_open", File::open(directory))?.sync_all(),
            )?;
        }
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
            key,
            saved_commitment: Cell::new(None),
        })
    }

    pub fn load(&self, context: &Context) -> Result<Option<DeviceState>, LabError> {
        self.load_inner(context, None, true)
    }

    pub fn load_committed(
        &self,
        context: &Context,
        expected: &[u8; 32],
    ) -> Result<Option<DeviceState>, LabError> {
        self.load_inner(context, Some(expected), true)
    }

    /// 重建只读取原已承诺元数据；绝不恢复旧provider或取得旧签名器。
    pub fn metadata_committed(
        &self,
        context: &Context,
        expected: &[u8; 32],
    ) -> Result<Option<DeviceState>, LabError> {
        self.load_inner(context, Some(expected), false)
    }

    fn load_inner(
        &self,
        context: &Context,
        expected: Option<&[u8; 32]>,
        restore_provider: bool,
    ) -> Result<Option<DeviceState>, LabError> {
        let path = self.directory.join("state.enc");
        if !path.exists() {
            return Ok(None);
        }
        let encoded_context = checked(
            "context_encoding",
            serde_json::to_vec(&("Rocket-IM/state-lab/v1", context)),
        )?;
        let plaintext = checked(
            "snapshot_load",
            match expected {
                Some(expected) => {
                    snapshot::load_committed(&path, &self.key, &encoded_context, expected)
                }
                None => snapshot::load(&path, &self.key, &encoded_context),
            },
        )?;
        let mut state: DeviceState = checked("state_decoding", serde_json::from_slice(&plaintext))?;
        ensure(
            state.version == 1 && state.context == *context,
            "wrong_context",
            "快照版本或设备上下文不匹配",
        )?;
        super::identity_state::validate(&state)?;
        super::wire_terminal_reference::stored(&state)?;
        super::wire_reclaim_validate::validate(&state)?;
        super::wire_send_order::validate(&state)?;
        super::wire_reads::validate(&state)?;
        if restore_provider {
            state.restore_provider()?;
        }
        Ok(Some(state))
    }

    pub fn save(&self, state: &mut DeviceState, point: CrashPoint) -> Result<(), LabError> {
        state.capture_provider()?;
        let plaintext = checked("state_encoding", serde_json::to_vec(state))?;
        let context = checked(
            "context_encoding",
            serde_json::to_vec(&("Rocket-IM/state-lab/v1", &state.context)),
        )?;
        if matches!(point, CrashPoint::BeforeSave) {
            std::process::exit(83);
        }
        let commitment = snapshot::save_committed_with_hook(
            &self.directory.join("state.enc"),
            &self.key,
            &context,
            &plaintext,
            |reached| {
                if matches!(
                    (point, reached),
                    (CrashPoint::BeforeRename, SavePoint::BeforeRename)
                ) {
                    std::process::exit(84);
                }
            },
        )
        .map_err(|error| {
            // rename 后同步失败不能冒充可安全重试的普通保存失败。
            let code = match error {
                snapshot::SnapshotError::CommitDurabilityUnknown(_) => "snapshot_commit_unknown",
                _ => "snapshot_save",
            };
            LabError::new(code, error.to_string())
        })?;
        self.saved_commitment.set(Some(commitment));
        if matches!(point, CrashPoint::AfterSave) {
            std::process::exit(85);
        }
        Ok(())
    }
}
