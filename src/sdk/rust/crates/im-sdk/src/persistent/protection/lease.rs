//! 活实例持共享租约，导入持独占租约。锁文件不删除，不在换库后复用旧连接。
use super::super::types::*;
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

pub(super) fn acquire(path: &Path, exclusive: bool) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    if fs::symlink_metadata(path).is_ok_and(|m| !m.is_file()) {
        return Err(Error::paused("backup_lease_invalid"));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|_| Error::paused("backup_lease_invalid"))?;
    let result = if exclusive {
        file.try_lock()
    } else {
        file.try_lock_shared()
    };
    result.map_err(|_| Error::paused("backup_store_in_use"))?;
    Ok(file)
}
