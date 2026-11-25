//! 恢复只交换签名公开材料；含秘密的候选与历史快照始终留在 Rust 库。
use super::{
    data::{Data, Saved},
    journal::{Candidate, Journal},
    types::*,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct Meta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_guard: Option<String>,
    pub journal: Option<Journal>,
    pub session: Option<Session>,
    pub history: Vec<Session>,
    pub archives: Vec<Candidate>,
    pub legacy: Option<Legacy>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Legacy {
    pub data: Vec<u8>,
    pub crypto: Vec<u8>,
    pub digest: String,
}
impl Meta {
    pub fn blocks_operations(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| !matches!(s.phase, RecoveryPhase::Committed | RecoveryPhase::Finished))
    }
    pub fn validate(&self, data: &Data, crypto: &[u8]) -> Result<()> {
        let bad = || Error::paused("store_invalid");
        if let Some(w) = data.network.as_ref().and_then(|n| n.workset.as_ref()) {
            if self.reserve_version.is_none()
                || self
                    .backup_guard
                    .as_ref()
                    .is_some_and(|g| g != &w.workset.sdk_instance)
            {
                return Err(bad());
            }
        }
        if self
            .reserve_version
            .as_deref()
            .is_some_and(|v| v != super::reserve::VERSION)
        {
            return Err(bad());
        }
        if self.backup_guard.as_ref().is_some_and(|id| {
            id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }) {
            return Err(bad());
        }
        if self.history.len() > super::metering::MAX_ROUNDS
            || self.archives.len() > super::metering::MAX_ROUNDS
        {
            return Err(bad());
        }
        if let Some(j) = &self.journal {
            let r = data.requests.get(&j.request).ok_or_else(bad)?;
            if data.state.pending_request.as_ref() != Some(&j.request)
                || r.hash != hash(&encode(&j.input)?)
            {
                return Err(bad());
            }
            j.input.validate().map_err(|_| bad())?;
            if j.seed.is_some() != matches!(j.input, Action::Initialize) {
                return Err(bad());
            }
            if let Some(c) = &j.candidate {
                c.data.validate(&c.crypto)?;
                if j.phase != super::journal::Phase::Executing {
                    return Err(bad());
                }
                super::candidate::restore(&Saved {
                    data: c.data.clone(),
                    crypto: c.crypto.clone(),
                    meta: Meta::default(),
                })
                .map_err(|_| bad())?;
                let extra = usize::from(matches!(
                    j.input,
                    Action::Send { .. } | Action::Receive { .. }
                ));
                if c.data.messages.len() != data.messages.len() + extra
                    || encode(&c.data.messages[..data.messages.len()])? != encode(&data.messages)?
                {
                    return Err(bad());
                }
                super::network::check_candidate(data, &c.data, &j.input)?;
                let mut predecessor = c.data.clone();
                predecessor.network = data.network.clone();
                predecessor.state = data.state.clone();
                predecessor.messages.truncate(data.messages.len());
                predecessor
                    .requests
                    .get_mut(&j.request)
                    .ok_or_else(bad)?
                    .result = RequestState::Pending;
                if encode(&predecessor)? != encode(data)? {
                    return Err(bad());
                }

                if c.data.state.scope != data.state.scope
                    || number(&c.data.state.revision)? != number(&data.state.revision)? + 1
                    || c.data.state.pending_request.is_some()
                {
                    return Err(bad());
                }
            }
        }
        for a in &self.archives {
            a.data.validate(&a.crypto)?;
            if a.data.state.scope != data.state.scope {
                return Err(bad());
            }
        }
        for s in &self.history {
            super::recovery_wire::validate_session(s, data, crypto)?;
        }
        if let Some(s) = &self.session {
            super::recovery_wire::validate_session(s, data, crypto)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPhase {
    Offered,
    Building,
    Prepared,
    Joining,
    Ready,
    Committed,
    Finished,
    Closing,
    Closed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Session {
    pub offer: Offer,
    pub offer_packet: String,
    pub target: bool,
    pub phase: RecoveryPhase,
    pub fresh: Vec<u8>,
    pub candidate: Option<Vec<u8>>,
    pub approval: Option<String>,
    pub ready: Option<String>,
    pub receipt: Option<String>,
    pub own_close: Option<String>,
    pub peer_close: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Offer {
    pub target: Identity,
    pub peer: Identity,
    pub conversation: String,
    pub old_context: String,
    pub previous: Option<String>,
    pub request: String,
    pub request_hash: String,
    pub key_package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<RecoveryTransport>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryTransport {
    pub version: String,
    pub round_id: String,
    pub deadline: String,
}
impl Offer {
    pub fn context(&self) -> Result<String> {
        Ok(hash(&encode(self)?))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Frame {
    pub sender: Identity,
    pub body: Body,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Body {
    Offer {
        offer: Box<Offer>,
    },
    Approval {
        context: String,
        welcome: String,
    },
    Ready {
        context: String,
        approval_hash: String,
    },
    Commit {
        context: String,
        ready_hash: String,
    },
    Close {
        context: String,
    },
    Installed {
        context: String,
        receipt_hash: String,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryCommand {
    Begin {
        request_id: String,
        action: Action,
    },
    /// peer 是接入方独立核验的目标身份，必须也匹配库中已固定的对端。
    Accept {
        offer: String,
        peer: Identity,
    },
    Reject {
        offer: String,
        peer: Identity,
    },
    Join {
        approval: String,
    },
    Confirm {
        ready: String,
    },
    Finish {
        receipt: String,
    },
    /// 只有不确定构建/加入可主动 Close；Ready 以后必须完成原轮。
    Close {
        peer_close: Option<String>,
    },
    /// 只读取回某轮已保存原件，包括已归档轮；不重新激活旧上下文。
    Inspect {
        context: String,
    },
    Status,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryResult {
    pub commit: Option<RecoveryCommit>,
    pub phase: Option<RecoveryPhase>,
    pub context: Option<String>,
    pub packet: Option<String>,
}
impl Session {
    pub fn result(&self) -> Result<RecoveryResult> {
        use RecoveryPhase::*;
        let packet = match self.phase {
            Offered => Some(self.offer_packet.clone()),
            Prepared => self.approval.clone(),
            Ready => self.ready.clone(),
            Committed | Finished => self.receipt.clone(),
            Closing | Closed => self.own_close.clone(),
            _ => None,
        };
        Ok(RecoveryResult {
            commit: None,
            phase: Some(self.phase.clone()),
            context: Some(self.offer.context()?),
            packet,
        })
    }
}
pub(super) fn snapshot(saved: &Saved) -> Result<rocket_crypto_core::storage::Snapshot> {
    decode(&saved.crypto)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCommit {
    pub revision: String,
    pub context: String,
}
