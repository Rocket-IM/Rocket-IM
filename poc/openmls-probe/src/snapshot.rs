//! Unix 原生 POC 的单快照文件层；调用者必须锁定单一 writer，并使用受信私有目录。
//! 不等于平台安全存储、数据库事务或完整回滚防护；密钥由调用者独立安全持有。
//! 进程被杀时可能留下 0600 的加密临时文件，恢复只读取正式快照，不自动提升临时文件。

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"RIMSNAP\0";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const PREFIX_LEN: usize = MAGIC.len() + 1 + NONCE_LEN;
const TAG_LEN: usize = 16;
pub const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILE_BYTES: usize = PREFIX_LEN + MAX_PLAINTEXT_BYTES + TAG_LEN;
const MAX_CONTEXT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failpoint {
    None,
    BeforeRename,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavePoint {
    BeforeRename,
}

/// rename 前的任何错误保留旧快照。rename 后目录同步失败返回 CommitDurabilityUnknown。
pub fn save(
    path: &Path,
    key: &[u8; 32],
    context: &[u8],
    plaintext: &[u8],
    failpoint: Failpoint,
) -> Result<(), SnapshotError> {
    save_impl(path, key, context, plaintext, failpoint, |_| {}).map(|_| ())
}

/// hook 在密文临时文件 sync_all 后、rename 前执行，供上层协调真正的进程中断。
/// hook 返回才继续提交；模块自身不终止进程，也不捕获 hook 的 panic。
pub fn save_with_hook(
    path: &Path,
    key: &[u8; 32],
    context: &[u8],
    plaintext: &[u8],
    hook: impl FnOnce(SavePoint),
) -> Result<(), SnapshotError> {
    save_impl(path, key, context, plaintext, Failpoint::None, hook).map(|_| ())
}

/// 返回本次确实写出的完整密文摘要，供外部锚绑定，不能用之后另读的文件替代。
pub fn save_committed_with_hook(
    path: &Path,
    key: &[u8; 32],
    context: &[u8],
    plaintext: &[u8],
    hook: impl FnOnce(SavePoint),
) -> Result<[u8; 32], SnapshotError> {
    save_impl(path, key, context, plaintext, Failpoint::None, hook)
}

fn save_impl(
    path: &Path,
    key: &[u8; 32],
    context: &[u8],
    plaintext: &[u8],
    failpoint: Failpoint,
    hook: impl FnOnce(SavePoint),
) -> Result<[u8; 32], SnapshotError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES || context.len() > MAX_CONTEXT_BYTES {
        return Err(SnapshotError::Oversize);
    }
    let (destination, parent) = checked_path(path)?;
    check_existing_target(&destination)?;
    let directory = File::open(&parent)?;
    let mut nonce_bytes = [0; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(SnapshotError::Randomness)?;
    let mut encoded = MAGIC.to_vec();
    encoded.push(VERSION);
    encoded.extend(nonce_bytes);
    let aad = associated_data(&encoded, context);
    let ciphertext = Aes256Gcm::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SnapshotError::EncryptionFailed)?;
    encoded.extend(ciphertext);
    let (mut temporary, mut file) = TemporaryFile::create(&parent)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    hook(SavePoint::BeforeRename);
    if failpoint == Failpoint::BeforeRename {
        return Err(SnapshotError::InjectedFailure);
    }
    check_existing_target(&destination)?;
    fs::rename(&temporary.path, &destination)?;
    temporary.is_committed = true;
    directory
        .sync_all()
        .map_err(SnapshotError::CommitDurabilityUnknown)?;
    Ok(Sha256::digest(&encoded).into())
}

/// 输入大小有界，格式/版本及 AES-GCM 认证失败不返回任何部分明文，不修改文件。
pub fn load(path: &Path, key: &[u8; 32], context: &[u8]) -> Result<Vec<u8>, SnapshotError> {
    load_impl(path, key, context, None)
}

/// 在同一次读取上先核对锚已预约的摘要，再解密；拒绝读取间被替换的快照。
pub fn load_committed(
    path: &Path,
    key: &[u8; 32],
    context: &[u8],
    expected: &[u8; 32],
) -> Result<Vec<u8>, SnapshotError> {
    load_impl(path, key, context, Some(expected))
}

fn load_impl(
    path: &Path,
    key: &[u8; 32],
    context: &[u8],
    expected: Option<&[u8; 32]>,
) -> Result<Vec<u8>, SnapshotError> {
    if context.len() > MAX_CONTEXT_BYTES {
        return Err(SnapshotError::Oversize);
    }
    let (source, _) = checked_path(path)?;
    check_existing_target(&source)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&source)
        .map_err(open_error)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(SnapshotError::NotRegularFile);
    }
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(SnapshotError::Oversize);
    }
    let mut encoded = Vec::new();
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_FILE_BYTES {
        return Err(SnapshotError::Oversize);
    }
    if expected.is_some_and(|expected| <[u8; 32]>::from(Sha256::digest(&encoded)) != *expected) {
        return Err(SnapshotError::CommitmentMismatch);
    }
    if encoded.len() < PREFIX_LEN + TAG_LEN || &encoded[..MAGIC.len()] != MAGIC {
        return Err(SnapshotError::InvalidFormat);
    }
    if encoded[MAGIC.len()] != VERSION {
        return Err(SnapshotError::UnsupportedVersion);
    }
    let aad = associated_data(&encoded[..PREFIX_LEN], context);
    let nonce = Nonce::from_slice(&encoded[MAGIC.len() + 1..PREFIX_LEN]);
    Aes256Gcm::new(key.into())
        .decrypt(
            nonce,
            Payload {
                msg: &encoded[PREFIX_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| SnapshotError::AuthenticationFailed)
}

fn associated_data(prefix: &[u8], context: &[u8]) -> Vec<u8> {
    let mut bytes = prefix.to_vec();
    bytes.extend((context.len() as u32).to_be_bytes());
    bytes.extend(context);
    bytes
}

fn checked_path(path: &Path) -> Result<(PathBuf, PathBuf), SnapshotError> {
    let filename = path.file_name().ok_or(SnapshotError::InvalidPath)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = if parent.is_absolute() {
        parent.to_owned()
    } else {
        std::env::current_dir()?.join(parent)
    };
    let mut checked = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::ParentDir | Component::Prefix(_) => return Err(SnapshotError::InvalidPath),
            Component::CurDir => continue,
            _ => checked.push(component.as_os_str()),
        }
        let metadata = fs::symlink_metadata(&checked)?;
        if metadata.file_type().is_symlink() {
            return Err(SnapshotError::Symlink);
        }
        if !metadata.is_dir() {
            return Err(SnapshotError::InvalidPath);
        }
    }
    Ok((checked.join(filename), checked))
}

fn check_existing_target(path: &Path) -> Result<(), SnapshotError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(SnapshotError::Symlink),
        Ok(metadata) if !metadata.is_file() => Err(SnapshotError::NotRegularFile),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SnapshotError::Io(error)),
    }
}

fn open_error(error: io::Error) -> SnapshotError {
    if error.raw_os_error() == Some(libc::ELOOP) {
        SnapshotError::Symlink
    } else {
        SnapshotError::Io(error)
    }
}

struct TemporaryFile {
    path: PathBuf,
    is_committed: bool,
}

impl TemporaryFile {
    fn create(parent: &Path) -> Result<(Self, File), SnapshotError> {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(SnapshotError::Randomness)?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = parent.join(format!(".snapshot-{suffix}.tmp"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        Ok((
            Self {
                path,
                is_committed: false,
            },
            file,
        ))
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.is_committed {
            // 清理失败不能掩盖原错误；残留物仍为加密的 0600 临时文件，不作为恢复输入。
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug)]
pub enum SnapshotError {
    Io(io::Error),
    Randomness(getrandom::Error),
    InvalidPath,
    Symlink,
    NotRegularFile,
    Oversize,
    InvalidFormat,
    UnsupportedVersion,
    EncryptionFailed,
    AuthenticationFailed,
    CommitmentMismatch,
    InjectedFailure,
    CommitDurabilityUnknown(io::Error),
}

impl From<io::Error> for SnapshotError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "snapshot I/O failed: {error}"),
            Self::Randomness(error) => write!(f, "snapshot randomness failed: {error}"),
            Self::CommitDurabilityUnknown(error) => {
                write!(f, "snapshot renamed but directory sync failed: {error}")
            }
            error => write!(f, "snapshot rejected: {error:?}"),
        }
    }
}

impl std::error::Error for SnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) | Self::CommitDurabilityUnknown(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod tests;
