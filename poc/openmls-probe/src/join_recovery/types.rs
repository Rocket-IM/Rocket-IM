//! 恢复公开契约：不包含设备私钥、密码库类型或本地状态。
use crate::permission::{receipts::SignedRecord, Member, PermissionCheckpoint, Proof};
use serde::{Deserialize, Serialize};

fn present_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

fn explicit_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub service_id: String,
    pub conversation_id: String,
    pub group_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRef {
    pub change_id: String,
    pub record_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub authorization_version: String,
    pub crypto_state_ref: String,
}
impl From<&PermissionCheckpoint> for Floor {
    fn from(cp: &PermissionCheckpoint) -> Self {
        Self {
            authorization_version: cp.authorization_version.clone(),
            crypto_state_ref: cp.crypto_state_ref.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRef {
    pub account_id: String,
    pub version: String,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Intent,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    Claim,
    Close,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    Cancelled,
    PredecessorChanged,
    Expired,
    PreparationFailed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub protocol_version: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_option"
    )]
    pub witness_profile: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_option"
    )]
    pub policy_ref: Option<super::witness::PolicyRef>,
    pub kind: IntentKind,
    pub scope: Scope,
    pub request_id: String,
    pub signer: Member,
    pub nonce: String,
    pub change_id: String,
    pub root_admission: AdmissionRef,
    pub current_admission: AdmissionRef,
    pub actor: Member,
    pub predecessor: Floor,
    pub known_floor: Floor,
    pub directory_refs: Vec<DirectoryRef>,
    pub key_package_sha256: String,
    pub history_policy: String,
    pub issued_at_unix_secs: String,
    pub expires_at_unix_secs: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub protocol_version: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_option"
    )]
    pub witness_profile: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_option"
    )]
    pub policy_ref: Option<super::witness::PolicyRef>,
    pub kind: ControlKind,
    pub scope: Scope,
    pub request_id: String,
    pub signer: Member,
    pub nonce: String,
    pub recovery_id: String,
    pub change_id: String,
    pub intent_sha256: String,
    #[serde(deserialize_with = "explicit_option")]
    pub reason: Option<CloseReason>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Request {
    Intent(Box<Intent>),
    Control(Box<Control>),
}
impl Request {
    pub fn signer(&self) -> &Member {
        match self {
            Self::Intent(i) => &i.signer,
            Self::Control(c) => &c.signer,
        }
    }
    pub fn id(&self) -> &str {
        match self {
            Self::Intent(i) => &i.request_id,
            Self::Control(c) => &c.request_id,
        }
    }
    pub fn scope(&self) -> &Scope {
        match self {
            Self::Intent(i) => &i.scope,
            Self::Control(c) => &c.scope,
        }
    }
    pub fn nonce(&self) -> &str {
        match self {
            Self::Intent(i) => &i.nonce,
            Self::Control(c) => &c.nonce,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    RecoverJoin,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub kind: RecoveryKind,
    pub recovery_id: String,
    pub root_admission: AdmissionRef,
    pub current_admission: AdmissionRef,
    pub target: Member,
    pub intent_sha256: String,
    pub allocation_sha256: String,
    pub key_package_sha256: String,
    pub key_package_ref: String,
    pub welcome_sha256: String,
    pub history_policy: String,
    pub previous_epoch: String,
    pub old_leaf_index: String,
    pub old_leaf_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub protocol_version: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_option"
    )]
    pub witness_profile: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_option"
    )]
    pub policy_ref: Option<super::witness::PolicyRef>,
    pub scope: Scope,
    pub change_id: String,
    pub actor: Member,
    pub previous_authorization_version: String,
    pub authorization_version: String,
    pub from_state_ref: String,
    pub to_state_ref: String,
    pub action: Action,
    pub commit_sha256: String,
    pub nonce: String,
    pub issued_at_unix_secs: String,
    pub expires_at_unix_secs: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResultBody {
    Allocated {
        claim_sha256: String,
        key_package_sha256: String,
        key_package_ref: String,
        predecessor: Floor,
    },
    Accepted {
        allocation_sha256: String,
        candidate_sha256: String,
        checkpoint: PermissionCheckpoint,
    },
    Closed {
        close_sha256: String,
        reason: CloseReason,
        checkpoint: PermissionCheckpoint,
        #[serde(deserialize_with = "explicit_option")]
        allocation_sha256: Option<String>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub protocol_version: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_option"
    )]
    pub witness_profile: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_option"
    )]
    pub policy_ref: Option<super::witness::PolicyRef>,
    pub scope: Scope,
    pub recovery_id: String,
    pub change_id: String,
    pub root_admission: AdmissionRef,
    pub current_admission: AdmissionRef,
    pub target: Member,
    pub actor: Member,
    pub intent_sha256: String,
    pub result: ResultBody,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub intent: SignedRecord,
    pub claim: SignedRecord,
    pub allocation: SignedRecord,
    pub change: Proof,
    pub key_package: String,
    pub welcome: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub bundle: Bundle,
    pub receipt: SignedRecord,
}

/// 权限链中的公开证明；目标 Welcome 只通过目标/批准者原结果接口读取。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicBundle {
    pub intent: SignedRecord,
    pub claim: SignedRecord,
    pub allocation: SignedRecord,
    pub change: Proof,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRecord {
    pub bundle: PublicBundle,
    pub receipt: SignedRecord,
}
impl From<&Bundle> for PublicBundle {
    fn from(b: &Bundle) -> Self {
        Self {
            intent: b.intent.clone(),
            claim: b.claim.clone(),
            allocation: b.allocation.clone(),
            change: b.change.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Evidence {
    Full(Record),
    Public(PublicRecord),
}
impl Evidence {
    pub fn public(&self) -> PublicRecord {
        match self {
            Self::Full(r) => PublicRecord {
                bundle: PublicBundle::from(&r.bundle),
                receipt: r.receipt.clone(),
            },
            Self::Public(r) => r.clone(),
        }
    }
    pub fn full(&self) -> Option<&Record> {
        if let Self::Full(r) = self {
            Some(r)
        } else {
            None
        }
    }
}
