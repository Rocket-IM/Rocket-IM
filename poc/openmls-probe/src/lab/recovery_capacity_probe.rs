//! 合成近满夹具：只复制已验签观察和生成合法自签请求，不声称自然累积。
//! 只在未绑定独立锚的隔离目录调用，随后由正常程序重载验证。
use super::{
    checked, codec, ensure, join_recovery_state as stored, store::LockedDevice, Context,
    CrashPoint, LabError,
};
use crate::{join_recovery as p, permission::receipts::SignedRecord};
use openmls_traits::signatures::Signer;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    directory: PathBuf,
    context: Context,
    mode: String,
}

pub fn seed(input: &str) -> Result<Value, LabError> {
    ensure(input.len() <= 16384, "probe", "夹具输入过大")?;
    let input: Input = checked("probe", serde_json::from_str(input))?;
    ensure(
        matches!(
            input.mode.as_str(),
            "count"
                | "bytes"
                | "witness_bytes"
                | "inspect"
                | "pause"
                | "startup_fork_pause"
                | "q02_imports"
                | "q02_heads"
        ),
        "probe",
        "未知容量模式",
    )?;
    let locked = LockedDevice::open(&input.directory)?;
    let mut state = locked
        .load(&input.context)?
        .ok_or_else(|| LabError::new("probe", "缺少既有快照"))?;
    if input.mode == "inspect" {
        state.provider_entries.sort();
        let mut value = checked("probe", serde_json::to_value(&state))?;
        value["permissions"]
            .as_object_mut()
            .ok_or_else(|| LabError::new("probe", "缺少权限状态"))?
            .remove("consistency");
        return Ok(
            json!({"excluding_consistency_sha256": crate::permission::commit_digest(&checked("probe", serde_json::to_vec(&value))?)}),
        );
    }
    ensure(
        std::env::var_os("RIM_ROLLBACK_ANCHOR_CONFIG").is_none(),
        "probe",
        "必须先构造夹具再绑定锚",
    )?;
    if input.mode == "pause" || input.mode == "startup_fork_pause" {
        state.permissions.consistency.pause(
            if input.mode == "pause" {
                super::consistency_state::Status::EvidenceCapacityExhausted
            } else {
                super::consistency_state::Status::ForkDetected
            },
            "synthetic_identity_source_guard",
        );
        locked.save(&mut state, CrashPoint::None)?;
        return Ok(json!({"status":"synthetic_existing_capacity_pause"}));
    }
    if input.mode.starts_with("q02_") {
        ensure(
            state.permissions.consistency.challenge.is_some(),
            "probe",
            "合成满额状态需要真实活动挑战",
        )?;
        if input.mode == "q02_imports" {
            let original = state
                .permissions
                .exchange
                .imports
                .values()
                .next()
                .cloned()
                .ok_or_else(|| LabError::new("probe", "需要真实已验证导入原件"))?;
            // 仅复制已有公开原件；合成索引不代表128次真实交换或自然可达状态。
            for index in 0..128 {
                if state.permissions.exchange.imports.len() == 128 {
                    break;
                }
                state
                    .permissions
                    .exchange
                    .imports
                    .insert(format!("synthetic_{index}"), original.clone());
            }
        } else {
            let original = state
                .permissions
                .consistency
                .heads
                .first()
                .ok_or_else(|| LabError::new("probe", "需要真实已验证head"))?;
            let raw = checked("probe", serde_json::to_vec(original))?;
            while state.permissions.consistency.heads.len() < 128 {
                state
                    .permissions
                    .consistency
                    .heads
                    .push(checked("probe", serde_json::from_slice(&raw))?);
            }
        }
        let result = json!({"synthetic":true,"mode":input.mode,
            "imports":state.permissions.exchange.imports.len(),"heads":state.permissions.consistency.heads.len()});
        locked.save(&mut state, CrashPoint::None)?;
        return Ok(result);
    }
    let observation = stored::get(&state)?
        .observations
        .first()
        .cloned()
        .ok_or_else(|| LabError::new("probe", "需要已验证观察"))?;
    let fact = super::join_recovery_evidence::verify(&state, &observation)?;
    let signer = state.signer()?;
    let own = super::key_package_state::own(&state);
    let witness_bytes = if input.mode == "witness_bytes" {
        checked("probe", serde_json::to_vec(&state.witness_state))?.len()
    } else {
        0
    };
    let s = stored::get_mut(&mut state)?;
    s.observations = vec![observation; if input.mode == "count" { 128 } else { 127 }];
    stored::budget(s)?;
    if input.mode == "bytes" || input.mode == "witness_bytes" {
        let target = 8 * 1024 * 1024 - 1024 - witness_bytes;
        for n in 0..320 {
            if s.requests.len() == 320 {
                break;
            }
            let id = format!("capacity-fixture-{n}");
            let request = p::Request::Control(Box::new(p::Control {
                protocol_version: "rim-recovery-request-1".into(),
                witness_profile: None,
                policy_ref: None,
                kind: p::ControlKind::Close,
                scope: fact.statement.scope.clone(),
                request_id: id.clone(),
                signer: own.clone(),
                nonce: format!("{n:064x}"),
                recovery_id: format!("capacity-recovery-{n}"),
                change_id: format!("capacity-change-{n}"),
                intent_sha256: "a".repeat(64),
                reason: Some(p::CloseReason::Cancelled),
            }));
            let mut raw = checked("probe", serde_json::to_vec(&request))?;
            let base = raw.len();
            let mut lo = base;
            let mut hi = 16384;
            let mut best = None;
            while lo <= hi {
                let len = (lo + hi) / 2;
                raw.resize(len, b' ');
                let mut bytes = p::REQUEST_DOMAIN.to_vec();
                bytes.extend(&raw);
                let proof = SignedRecord {
                    statement_bytes: codec::encode(&raw),
                    signature_bytes: codec::encode(
                        &signer
                            .sign(&bytes)
                            .map_err(|_| LabError::new("probe", "签名失败"))?,
                    ),
                };
                p::parse_request(&proof)?;
                s.requests.insert(id.clone(), proof.clone());
                if checked("probe", serde_json::to_vec(s))?.len() <= target {
                    best = Some(proof);
                    lo = len + 1;
                } else {
                    hi = len - 1;
                }
            }
            s.requests.remove(&id);
            if let Some(proof) = best {
                s.requests.insert(id, proof);
            } else {
                break;
            }
            if checked("probe", serde_json::to_vec(s))?.len() >= target - 4 {
                break;
            }
        }
        ensure(
            checked("probe", serde_json::to_vec(s))?.len() >= target - 4,
            "probe",
            "未达到字节边界",
        )?;
    }
    stored::validate(&state)?;
    super::join_recovery_witness_state::validate(&state)?;
    let s = stored::get(&state)?;
    let result = json!({"synthetic":true,"observations":s.observations.len(),"requests":s.requests.len(),"bytes":checked("probe",serde_json::to_vec(s))?.len()});
    locked.save(&mut state, CrashPoint::None)?;
    Ok(result)
}
