//! 有效全快照一次替换；分叉暂停另存，不能删除已有身份信任或撤销墓碑。
use super::{ensure, key_package_state::Directory, state::DeviceState, LabError};
use crate::{key_package::directory, permission::types};
pub(super) fn accept(
    state: &mut DeviceState,
    account: &str,
    snapshots: &[String],
) -> Result<&'static str, LabError> {
    let mut previous: Option<(crate::key_package::directory::Snapshot, String)> = None;
    for encoded in snapshots {
        let current = directory::parse(encoded)?;
        ensure(
            current.service_id == state.context.service && current.account_id == account,
            "directory_context",
            "目录范围不符",
        )?;
        if let Some((ref old, ref bytes)) = previous {
            directory::successor(old, &current)?;
            ensure(
                current.previous_sha256 == directory::hash(bytes)?,
                "directory_gap",
                "目录链缺口",
            )?;
        } else {
            ensure(
                current.version == "1" && current.previous_sha256 == "0".repeat(64),
                "directory_gap",
                "缺少独立来源链起点",
            )?;
        }
        previous = Some((current, encoded.clone()));
    }
    let (head, _) = previous.ok_or_else(|| LabError::new("directory_invalid", "目录为空"))?;
    let pool = state.key_packages.get_or_insert_with(Default::default);
    if let Some(old) = pool.directories.get_mut(account) {
        let old_head = directory::parse(
            old.snapshots
                .last()
                .ok_or_else(|| LabError::new("directory_invalid", "旧目录为空"))?,
        )?;
        ensure(
            types::decimal(&head.version)? >= types::decimal(&old_head.version)?,
            "directory_stale",
            "拒绝回退目录",
        )?;
        if old.snapshots.iter().zip(snapshots).any(|(a, b)| a != b) {
            old.conflict = true;
            return Ok("conflict");
        }
        if old.conflict {
            return Ok("conflict");
        }
    }
    pool.directories.insert(
        account.into(),
        Directory {
            snapshots: snapshots.to_vec(),
            conflict: false,
        },
    );
    Ok("candidate_saved_freshness_unknown")
}
