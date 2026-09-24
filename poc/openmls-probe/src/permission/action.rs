//! 群范围动作的意图与目标；AddDevice 由当前同账号旧设备一次签名授权。
use super::{Action, Member};

impl Action {
    /// Welcome 属于本次候选，不能成为跨封口重准备的业务意图。
    pub fn same_intent(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::AddMember {
                    member: a,
                    key_package_sha256: ak,
                    history_policy: ah,
                    ..
                },
                Self::AddMember {
                    member: b,
                    key_package_sha256: bk,
                    history_policy: bh,
                    ..
                },
            )
            | (
                Self::AddDevice {
                    member: a,
                    key_package_sha256: ak,
                    history_policy: ah,
                    ..
                },
                Self::AddDevice {
                    member: b,
                    key_package_sha256: bk,
                    history_policy: bh,
                    ..
                },
            ) => a == b && ak == bk && ah == bh,
            _ => self == other,
        }
    }
    pub fn removes(&self, member: &Member) -> bool {
        match self {
            Self::AddMember { .. } | Self::AddDevice { .. } => false,
            Self::RemoveMember { account_id } => member.account_id == *account_id,
            Self::RevokeDevice {
                account_id,
                device_id,
            } => member.account_id == *account_id && member.device_id == *device_id,
        }
    }
}
