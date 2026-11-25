//! W1 公开签名对象和本地事实关联；不承载私有 provider 或秘密。
use super::{
    types::{AdmissionRef, Scope},
    witness_policy::{PolicyRef, SourceRef},
};
use crate::permission::{receipts::SignedRecord, Member, PermissionCheckpoint};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteCheckpoint {
    pub group_id: String,
    pub epoch: String,
    pub checkpoint: PermissionCheckpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRequest {
    pub protocol_version: String,
    pub witness_profile: String,
    pub policy_ref: PolicyRef,
    pub validation_rules_version: String,
    pub scope: Scope,
    pub actor: Member,
    pub target: Member,
    pub witness: Member,
    pub root_admission: AdmissionRef,
    pub current_admission: AdmissionRef,
    pub recovery_id: String,
    pub change_id: String,
    pub accepted_ref: AdmissionRef,
    pub commit_sha256: String,
    pub welcome_sha256: String,
    pub key_package_sha256: String,
    pub key_package_ref: String,
    pub request_id: String,
    pub challenge: String,
    pub issued_at_unix_secs: String,
    pub expires_at_unix_secs: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessResponse {
    pub protocol_version: String,
    pub witness_profile: String,
    pub policy_ref: PolicyRef,
    pub validation_rules_version: String,
    pub scope: Scope,
    pub actor: Member,
    pub target: Member,
    pub witness: Member,
    pub root_admission: AdmissionRef,
    pub current_admission: AdmissionRef,
    pub recovery_id: String,
    pub change_id: String,
    pub accepted_ref: AdmissionRef,
    pub commit_sha256: String,
    pub welcome_sha256: String,
    pub key_package_sha256: String,
    pub key_package_ref: String,
    pub request_id: String,
    pub challenge: String,
    pub request_sha256: String,
    pub previous: CompleteCheckpoint,
    pub next: CompleteCheckpoint,
    pub installation_ref: SourceRef,
    pub highest_known: CompleteCheckpoint,
    pub known_evidence_refs: Vec<SourceRef>,
    pub issued_at_unix_secs: String,
    pub expires_at_unix_secs: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationFact {
    pub protocol_version: String,
    pub witness_profile: String,
    pub policy_ref: PolicyRef,
    pub validation_rules_version: String,
    pub scope: Scope,
    pub actor: Member,
    pub target: Member,
    pub witness: Member,
    pub accepted_ref: AdmissionRef,
    pub commit_sha256: String,
    pub welcome_sha256: String,
    pub key_package_sha256: String,
    pub key_package_ref: String,
    pub previous: CompleteCheckpoint,
    pub next: CompleteCheckpoint,
    pub installed_at_unix_secs: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRecord {
    pub protocol_version: String,
    pub witness_profile: String,
    pub policy_ref: PolicyRef,
    pub validation_rules_version: String,
    pub scope: Scope,
    pub actor: Member,
    pub target: Member,
    pub witness: Member,
    pub root_admission: AdmissionRef,
    pub current_admission: AdmissionRef,
    pub recovery_id: String,
    pub change_id: String,
    pub accepted_ref: AdmissionRef,
    pub commit_sha256: String,
    pub welcome_sha256: String,
    pub key_package_sha256: String,
    pub key_package_ref: String,
    pub request: SignedRecord,
    pub response: SignedRecord,
    pub actual_next: CompleteCheckpoint,
    pub challenge_consumed: bool,
    pub key_package_consumed: bool,
    pub installed_at_unix_secs: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEvidenceAttachment {
    pub reference: SourceRef,
    pub evidence_bytes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessDelivery {
    pub response: SignedRecord,
    pub known_evidence: Vec<PublicEvidenceAttachment>,
    pub supplemental_evidence: Vec<PublicEvidenceAttachment>,
}
