//! E10C-W1 的公开格式与绑定校验；不授予策略授权，也不证明远程执行。
pub use super::witness_binding::*;
pub use super::witness_format::{decode, parse_bytes, parse_signed_wire};
pub use super::witness_policy::*;
pub use super::witness_types::*;
pub use super::witness_validate::*;
pub use super::witness_wire::validate_lab_envelopes;

pub const PROFILE: &str = "E10C-W1";
pub const RULES_VERSION: &str = "rim-recovery-witness-rules-1";
pub const REQUEST_DOMAIN: &[u8] = b"Rocket-IM/POC/recovery-witness-request/v1\0";
pub const RESPONSE_DOMAIN: &[u8] = b"Rocket-IM/POC/recovery-witness-response/v1\0";
pub const POLICY_DOMAIN: &[u8] = b"Rocket-IM/POC/recovery-witness-policy/v1\0";
pub const REQUEST_WIRE_LIMIT: usize = 8192;
pub const RESPONSE_WIRE_LIMIT: usize = 16384;

/// 只取已绑定引用，不进行授权判断；使用前须通过 parse_policy。
pub fn policy_ref(policy: &PolicyEnvelope) -> PolicyRef {
    policy.policy_ref.clone()
}
