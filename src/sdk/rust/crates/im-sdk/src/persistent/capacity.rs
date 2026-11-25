//! 一次显式读事务中的完整Saved投影；观察不授予执行权限，也不生成密码候选。
use super::{capacity_types::*, data::Saved, journal::Phase, metering::*, types::*};
use std::sync::atomic::{AtomicU64, Ordering};

fn budget(category: &str, unit: &str, used: usize, limit: usize) -> CapacityBudget {
    CapacityBudget {
        category: category.into(),
        unit: unit.into(),
        used: used.to_string(),
        limit: limit.to_string(),
        hard_remaining: limit.saturating_sub(used).to_string(),
    }
}
fn component(category: &str, bytes: usize) -> CapacityComponent {
    CapacityComponent {
        category: category.into(),
        included_in: "meta_bytes".into(),
        bytes: bytes.to_string(),
    }
}
fn optional_bytes<T: serde::Serialize>(v: Option<&T>) -> Result<usize> {
    v.map(|v| encode(v).map(|b| b.len()))
        .transpose()
        .map(|v| v.unwrap_or(0))
}
pub(super) fn snapshot(s: Saved) -> Result<Capacity> {
    let encoded = EncodedSaved::new(&s)?;
    let network = super::network::capacity(&s, &encoded)?;
    let j = s.meta.journal.as_ref();
    let pending = match j {
        Some(j) if j.candidate.is_some() => "complete_candidate",
        Some(j) if j.phase == Phase::Reserved => "reserved",
        Some(j) if j.seed.is_some() => "initialization_retry",
        Some(_) => "executing_unknown",
        None if s.data.state.pending_request.is_some() => "legacy_unknown",
        None => "none",
    };
    let mut out = Capacity {
        version: "sdk-capacity-alpha2".into(),
        owner: "sdk".into(),
        scope: s.data.state.scope.clone(),
        observation_id: observation_id(),
        consistency: "single_sqlite_read".into(),
        revision: s.data.state.revision.clone(),
        cursors: network.cursors,
        recovery: CapacityRecovery {
            pending: pending.into(),
            phase: s.meta.session.as_ref().map(|v| v.phase.clone()),
            candidate: j.is_some_and(|j| j.candidate.is_some()),
            locally_authorized: network.authorized || s.meta.session.is_some(),
            network_phase: network.phase,
        },
        budgets: vec![
            budget("requests", "items", s.data.requests.len(), MAX_REQUESTS),
            budget(
                "ordinary_messages",
                "items",
                s.data.messages.len(),
                MAX_MESSAGES,
            ),
            budget("events", "items", network.events, MAX_EVENTS),
            budget(
                "data_bytes",
                "bytes",
                encoded.data.len(),
                super::data::MAX_DATA,
            ),
            budget("crypto_bytes", "bytes", encoded.crypto, MAX_CRYPTO),
            budget(
                "meta_bytes",
                "bytes",
                encoded.meta.len(),
                super::store::MAX_META,
            ),
            budget("history", "items", s.meta.history.len(), MAX_ROUNDS),
            budget("archives", "items", s.meta.archives.len(), MAX_ROUNDS),
            budget("transitions", "items", s.data.transitions.len(), MAX_ROUNDS),
        ],
        components: vec![
            component(
                "candidate_bytes",
                optional_bytes(j.and_then(|j| j.candidate.as_ref()))?,
            ),
            component("session_bytes", optional_bytes(s.meta.session.as_ref())?),
            component("archives_bytes", encode(&s.meta.archives)?.len()),
            component("legacy_bytes", optional_bytes(s.meta.legacy.as_ref())?),
        ],
        reserve: CapacityReserve {
            state: "not_enabled".into(),
            protected_remaining: None,
            ordinary_available: None,
            resources: vec![],
            work: vec![],
        },
        operations: vec![],
        blockers: vec![],
        physical: CapacityUnavailable {
            state: "unavailable".into(),
            reserved: false,
        },
        remote: CapacityUnavailable {
            state: "unavailable".into(),
            reserved: false,
        },
    };
    let ordinary = &["new_send", "new_receive"];
    if s.data.requests.len() >= MAX_REQUESTS {
        out.block("request_limit", Some("requests"), ordinary);
    }
    if s.data.messages.len() >= MAX_MESSAGES {
        out.block("message_limit", Some("ordinary_messages"), &["new_send"]);
    }
    if encoded.data_preflight_exceeded(MIN_GROWTH) {
        out.block("data_preflight_limit", Some("data_bytes"), ordinary);
    }
    if encoded.meta_preflight_exceeded(MIN_GROWTH) {
        out.block("meta_preflight_limit", Some("meta_bytes"), ordinary);
    }
    if s.data.state.identity.is_none() {
        out.block("initialize_required", None, ordinary);
    } else if s.data.state.conversation.is_none() {
        out.block("group_required", None, ordinary);
    }
    if s.data.state.pending_request.is_some() {
        out.block("operation_pending", None, ordinary);
        out.block(
            "successor_required",
            None,
            &["download", "process", "report", "retry_send"],
        );
    }
    if matches!(pending, "executing_unknown" | "legacy_unknown") {
        out.block(
            "successor_required",
            None,
            &["recover_pending", "install_candidate"],
        );
    }
    if s.meta.blocks_operations() || super::network::recovery_gate(&s) {
        out.block(
            "recovery_active",
            None,
            &[
                "new_send",
                "new_receive",
                "download",
                "process",
                "report",
                "retry_send",
            ],
        );
    }
    if s.meta.blocks_operations() {
        out.block("recovery_active", None, &["install_candidate"]);
    }
    if !out.recovery.candidate {
        out.block("candidate_missing", None, &["install_candidate"]);
    }
    if out.cursors.is_none() {
        out.block(
            "network_unbound",
            None,
            &["download", "process", "report", "retry_send"],
        );
    }
    if network.events >= MAX_EVENTS {
        out.block("event_limit", Some("events"), &["download"]);
    }
    if encoded.meta_preflight_exceeded(RECOVERY_GROWTH) {
        out.block(
            "recovery_preflight_limit",
            Some("meta_bytes"),
            &["new_recovery"],
        );
    }
    for (name, used) in [
        ("history", s.meta.history.len()),
        ("transitions", s.data.transitions.len()),
    ] {
        if used >= MAX_ROUNDS {
            out.block("recovery_limit", Some(name), &["new_recovery"]);
        }
    }
    if s.data.state.identity.is_none() {
        out.block("initialize_required", None, &["first_backup", "export"]);
    }
    if s.meta.backup_guard.is_none() {
        // 只编码字段表示，不生成随机钥、外部预约或密码候选。
        let mut meta = s.meta.clone();
        meta.backup_guard = Some("0".repeat(64));
        if encode(&meta)?.len() > super::store::MAX_META {
            out.block(
                "backup_guard_limit",
                Some("meta_bytes"),
                &["first_backup", "export"],
            );
        }
    }
    for (code, resource) in network.process_blockers {
        out.block(code, Some(resource), &["process"]);
    }
    for name in [
        "new_send",
        "new_receive",
        "retry_request",
        "recover_pending",
        "retry_send",
        "download",
        "process",
        "report",
        "install_candidate",
        "new_recovery",
        "authorized_recovery",
        "first_backup",
        "export",
        "import",
    ] {
        let mut blockers: Vec<String> = out
            .blockers
            .iter()
            .filter(|b| b.operations.iter().any(|v| v == name))
            .map(|b| b.code.clone())
            .collect();
        blockers.sort();
        blockers.dedup();
        let state = if !blockers.is_empty() {
            CapacityOperationState::Blocked
        } else if matches!(
            name,
            "new_send"
                | "new_receive"
                | "retry_request"
                | "recover_pending"
                | "new_recovery"
                | "import"
        ) {
            CapacityOperationState::RequiresInput
        } else {
            CapacityOperationState::NotReserved
        };
        out.operations.push(CapacityOperation {
            operation: name.into(),
            state,
            blockers,
        });
    }
    if s.meta.reserve_version.is_some() {
        let proof = super::reserve::prove(&s)?;
        if !proof.fits() {
            return Err(Error::paused("reserve_invalid"));
        }
        for op in &mut out.operations {
            if op.blockers.is_empty()
                && match op.operation.as_str() {
                    "install_candidate" => proof.candidate,
                    "retry_send" => proof.sends > 0,
                    "process" => proof.controls > 0,
                    "report" => proof.reports > 0,
                    "authorized_recovery" => proof.recovery,
                    _ => false,
                }
            {
                op.state = CapacityOperationState::BoundedReady;
            }
        }
        out.reserve = proof.public();
    }
    Ok(out)
}
impl Capacity {
    fn block(&mut self, code: &str, resource: Option<&str>, operations: &[&str]) {
        self.blockers.push(CapacityBlocker {
            code: code.into(),
            resource: resource.map(str::to_string),
            operations: operations.iter().map(|v| (*v).into()).collect(),
        });
    }
}
fn observation_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // 临时标识，不包含数据库摘要或秘密；不用于授权、排序或跨进程一致性。
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    hash(
        format!(
            "{}:{time}:{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
        .as_bytes(),
    )
}
