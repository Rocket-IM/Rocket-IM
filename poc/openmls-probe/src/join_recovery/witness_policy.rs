//! W1 可信本地策略原件；解析及摘要通过不授予策略授权或独立性。
use super::types::Scope;
use crate::permission::Member;
use serde::{Deserialize, Serialize};

pub(super) fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub source_id: String,
    pub source_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Independence {
    pub control_domain_id: String,
    pub confirmation_source_ref: SourceRef,
    pub assumption: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub protocol_version: String,
    pub witness_profile: String,
    pub policy_id: String,
    pub policy_version: String,
    pub scope: Scope,
    pub target: Member,
    pub witness: Member,
    pub validation_rules_version: String,
    pub trust_source_ref: SourceRef,
    pub change_authority_ref: SourceRef,
    pub independence: Independence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEnvelope {
    pub policy_ref: PolicyRef,
    pub policy_bytes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub protocol_version: String,
    pub activation_id: String,
    pub activation_version: String,
    pub witness_profile: String,
    pub scope: Scope,
    pub target: Member,
    #[serde(deserialize_with = "required_option")]
    pub policy_ref: Option<PolicyRef>,
    pub trusted_authorization_ref: SourceRef,
    pub activated_at_unix_secs: String,
    pub legacy_uninstalled_target: String,
    pub legacy_installed: String,
}
