//! 联网恢复的公开授权与持久转交记录。没有用户私钥或访问令牌。
use super::super::{data::Saved, recovery_types::RecoveryTransport, types::*};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reservation {
    pub version: String,
    pub id: String,
    pub target: Identity,
    pub peer: Identity,
    pub conversation: String,
    pub old_context: String,
    pub previous: Option<String>,
    pub request: String,
    pub request_hash: String,
    pub deadline: String,
}
impl Reservation {
    pub fn transport(&self) -> RecoveryTransport {
        RecoveryTransport {
            version: self.version.clone(),
            round_id: self.id.clone(),
            deadline: self.deadline.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Round {
    pub reservation: Reservation,
    pub context: Option<String>,
    pub status: String,
    pub materials: BTreeMap<String, String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::persistent) struct RecoveryData {
    pub(super) intent: Option<Reservation>,
    pub(super) round: Option<Round>,
    pub(super) decision: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkRecoveryCommand {
    Begin {
        request_id: String,
        action: Action,
    },
    Approve {
        round_id: String,
    },
    Reject {
        round_id: String,
    },
    /// building/joining执行未知时显式封存；Ready后拒绝。
    Seal {
        round_id: String,
    },
    Status,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRecoveryState {
    pub round_id: String,
    pub context: Option<String>,
    pub role: String,
    pub phase: String,
    pub requires_action: bool,
    pub request_id: String,
    pub request_hash: String,
    pub deadline: String,
}
pub(in crate::persistent) fn recovery_managed(saved: &Saved) -> bool {
    saved
        .data
        .network
        .as_ref()
        .is_some_and(|n| n.recovery.is_some())
}
pub(in crate::persistent) fn recovery_transport(saved: &Saved) -> Option<RecoveryTransport> {
    saved
        .data
        .network
        .as_ref()?
        .recovery
        .as_ref()?
        .intent
        .as_ref()
        .map(Reservation::transport)
}
pub(in crate::persistent) fn recovery_gate(saved: &Saved) -> bool {
    let Some(r) = saved
        .data
        .network
        .as_ref()
        .and_then(|n| n.recovery.as_ref())
    else {
        return false;
    };
    if r.intent
        .as_ref()
        .is_some_and(|q| r.round.as_ref().is_none_or(|v| v.reservation.id != q.id))
    {
        return true;
    }
    if let Some(round) = &r.round {
        let settled =
            round.status == "complete" && round.context.as_ref() == Some(&saved.data.state.context);
        if settled {
            return false;
        }
    }
    r.intent.is_some()
        || r.decision.as_deref() == Some("approve")
        || r.decision.as_deref() == Some("seal")
}
pub(super) fn projection(saved: &Saved) -> Result<Option<NetworkRecoveryState>> {
    let Some(r) = saved
        .data
        .network
        .as_ref()
        .and_then(|n| n.recovery.as_ref())
    else {
        return Ok(None);
    };
    let pending = r
        .intent
        .as_ref()
        .filter(|q| r.round.as_ref().is_none_or(|v| v.reservation.id != q.id));
    let Some(q) = pending
        .or_else(|| r.round.as_ref().map(|v| &v.reservation))
        .or(r.intent.as_ref())
    else {
        return Ok(None);
    };
    let target = Some(&q.target) == saved.data.state.identity.as_ref();
    let phase = if let Some(s) = saved.meta.session.as_ref().filter(|s| {
        s.offer
            .transport
            .as_ref()
            .is_some_and(|t| t.round_id == q.id)
    }) {
        if r.round.as_ref().is_some_and(|r| r.status == "complete") {
            "complete".into()
        } else {
            format!("{:?}", s.phase).to_lowercase()
        }
    } else if !target
        && r.decision.is_none()
        && r.round
            .as_ref()
            .is_some_and(|v| v.materials.contains_key("offer"))
    {
        "approval_required".into()
    } else {
        "reserving".into()
    };
    Ok(Some(NetworkRecoveryState {
        round_id: q.id.clone(),
        context: r.round.as_ref().and_then(|r| r.context.clone()),
        role: if target { "target" } else { "peer" }.into(),
        requires_action: matches!(phase.as_str(), "approval_required" | "building" | "joining"),
        phase,
        request_id: q.request.clone(),
        request_hash: q.request_hash.clone(),
        deadline: q.deadline.clone(),
    }))
}
