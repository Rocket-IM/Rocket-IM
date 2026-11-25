//! Alpha1网络契约，计数保持十进制字符串；连接凭证不写入SQLite。
use super::super::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkOptions {
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[cfg(feature = "network")]
    #[serde(default)]
    pub authentication: Option<super::AuthenticationOptions>,
    /// 独立核验的根证书DER，小写十六进制；仍执行标准TLS证书链和IP校验。
    pub ca_certificate: String,
    pub conversation: String,
    pub peer: Identity,
    pub creator: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub url: String,
    pub ca_hash: String,
    pub conversation: String,
    pub peer: Identity,
    pub creator: bool,
}
impl NetworkOptions {
    pub(super) fn binding(&self) -> Result<Binding> {
        id(&self.conversation)?;
        self.peer.validate()?;
        let automatic = self.automatic();
        if !automatic
            && (!(32..=256).contains(&self.token.len())
                || !self
                    .token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Err(Error::new("invalid_credentials"));
        }
        Ok(Binding {
            url: self.url.clone(),
            ca_hash: hash(&unhex(&self.ca_certificate, 8192)?),
            conversation: self.conversation.clone(),
            peer: self.peer.clone(),
            creator: self.creator,
        })
    }
    fn automatic(&self) -> bool {
        #[cfg(feature = "network")]
        {
            self.authentication.is_some()
        }
        #[cfg(not(feature = "network"))]
        {
            false
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub request_id: String,
    pub message_id: String,
    pub sequence: String,
    pub envelope_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    pub sequence: String,
    pub kind: String,
    pub acceptance: Acceptance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    pub after: String,
    pub upper: String,
    pub next: String,
    pub events: Vec<Event>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::persistent) struct NetworkData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::persistent) workset: Option<super::CapacityWorksetState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::persistent) workset_history: Vec<super::CapacityWorksetState>,
    pub(super) binding: Option<Binding>,
    pub(super) events: Vec<Event>,
    #[serde(default = "zero")]
    pub(super) processed: String,
    #[serde(default = "zero")]
    pub(super) reported: String,
    pub(super) upper: Option<String>,
    pub(super) accepted: BTreeMap<String, Acceptance>,
    pub(super) delivered: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) recovery: Option<super::recovery_types::RecoveryData>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) not_accepted: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) unavailable: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) retired_events: BTreeSet<String>,
}
pub(super) fn zero() -> String {
    "0".into()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendingState {
    pub message_id: String,
    pub request_id: String,
    pub status: String,
    pub acceptance: Option<Acceptance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<super::SendRejection>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkState {
    pub connection: String,
    pub error: Option<Error>,
    pub downloaded: String,
    pub processed: String,
    pub reported: String,
    pub sending: Vec<SendingState>,
    pub recovery: Option<super::recovery_types::NetworkRecoveryState>,
    pub unavailable_history: Vec<UnavailableRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnavailableRecord {
    pub sequence: String,
    pub reason: String,
    pub acceptance: Acceptance,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnavailableMessage {
    pub sequence: String,
    pub reason: String,
    pub acceptance: Acceptance,
    pub envelope: Envelope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Session {
    pub version: String,
    pub service: String,
    pub conversation: String,
    pub own: Identity,
    pub peer: Identity,
    pub creator: bool,
}

#[cfg(feature = "network")]
impl Drop for NetworkOptions {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
    }
}
