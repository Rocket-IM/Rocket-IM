//! 新协议各对象分别签名；时间为UTC Unix毫秒，版本/序号为规范十进制字符串。
use super::ensure;
use crate::permission::{
    receipts::{validate_key, SignedRecord},
    types, Member, PermissionError,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roots {
    pub service_id: String,
    pub issuer: String,
    pub audience: String,
    pub business_key: String,
    pub receipt_key: String,
}
impl Roots {
    pub fn validate(&self) -> Result<(), PermissionError> {
        for x in [&self.service_id, &self.issuer, &self.audience] {
            types::id(x)?;
        }
        validate_key(&self.business_key)?;
        validate_key(&self.receipt_key)?;
        ensure(
            self.business_key != self.receipt_key,
            "identity_source_root",
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    pub service_id: String,
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub permit_id: String,
    pub target: Member,
    pub challenge_sha256: String,
    pub challenge_nonce: String,
    pub purpose: String,
    pub issued_at_ms: String,
    pub expires_at_ms: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub service_id: String,
    pub approval_id: String,
    pub actor: Member,
    pub target: Member,
    pub permit_sha256: String,
    pub previous_version: String,
    pub previous_sha256: String,
    pub expires_at_ms: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub registration: SignedRecord,
    pub permit: SignedRecord,
    pub approval: Option<SignedRecord>,
    pub accepted_at_ms: String,
    pub status: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub protocol_version: String,
    pub service_id: String,
    pub account_id: String,
    pub version: String,
    pub previous_sha256: String,
    pub devices: Vec<Entry>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub service_id: String,
    pub requester: Member,
    pub account_id: String,
    pub request_id: String,
    pub challenge: String,
    pub snapshots: Vec<Snapshot>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub service_id: String,
    pub actor: Member,
    pub requester: Member,
    pub account_id: String,
    pub request_id: String,
    pub challenge: String,
    pub version: String,
    pub snapshot_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol_version", content = "body", deny_unknown_fields)]
pub enum Document {
    #[serde(rename = "rim-business-permit-1")]
    Permit(Permit),
    #[serde(rename = "rim-account-device-approval-1")]
    Approval(Approval),
    #[serde(rename = "rim-authorized-directory-response-1")]
    Directory(Response),
    #[serde(rename = "rim-independent-directory-head-1")]
    Head(Head),
}
impl Document {
    pub fn domain(&self) -> &'static [u8] {
        match self {
            Self::Permit(_) => b"Rocket-IM/POC/business-permit/v1\0",
            Self::Approval(_) => b"Rocket-IM/POC/account-device-approval/v1\0",
            Self::Directory(_) => b"Rocket-IM/POC/authorized-directory-response/v1\0",
            Self::Head(_) => b"Rocket-IM/POC/independent-directory-head/v1\0",
        }
    }
    pub fn validate(&self) -> Result<(), PermissionError> {
        use crate::key_package::member;
        match self {
            Self::Permit(p) => {
                for x in [
                    &p.service_id,
                    &p.issuer,
                    &p.audience,
                    &p.subject,
                    &p.permit_id,
                ] {
                    types::id(x)?;
                }
                member(&p.target)?;
                types::hash(&p.challenge_sha256)?;
                ensure(
                    types::bytes(&p.challenge_nonce, 32)?.len() == 32,
                    "identity_source_invalid",
                )?;
                let a = types::decimal(&p.issued_at_ms)?;
                let b = types::decimal(&p.expires_at_ms)?;
                ensure(
                    b.checked_sub(a).is_some_and(|n| n > 0 && n <= 300000)
                        && matches!(p.purpose.as_str(), "first_device" | "add_device"),
                    "identity_source_invalid",
                )?;
            }
            Self::Approval(p) => {
                types::id(&p.service_id)?;
                types::id(&p.approval_id)?;
                member(&p.actor)?;
                member(&p.target)?;
                types::hash(&p.permit_sha256)?;
                types::hash(&p.previous_sha256)?;
                types::decimal(&p.expires_at_ms)?;
                ensure(
                    types::decimal(&p.previous_version)? > 0
                        && p.actor.account_id == p.target.account_id
                        && p.actor.device_id != p.target.device_id,
                    "identity_source_approval",
                )?;
            }
            Self::Directory(p) => {
                for x in [&p.service_id, &p.account_id, &p.request_id] {
                    types::id(x)?;
                }
                member(&p.requester)?;
                types::hash(&p.challenge)?;
                ensure(
                    !p.snapshots.is_empty() && p.snapshots.len() <= 16,
                    "resource_exhausted",
                )?;
            }
            Self::Head(p) => {
                for x in [&p.service_id, &p.account_id, &p.request_id] {
                    types::id(x)?;
                }
                member(&p.actor)?;
                member(&p.requester)?;
                types::hash(&p.challenge)?;
                types::hash(&p.snapshot_sha256)?;
                ensure(types::decimal(&p.version)? > 0, "identity_source_invalid")?;
            }
        }
        ensure(
            serde_json::to_vec(self)
                .map_err(|_| crate::key_package::error("identity_source_encoding"))?
                .len()
                <= super::LIMIT,
            "resource_exhausted",
        )?;
        Ok(())
    }
}
