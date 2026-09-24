//! 合成控制器的独立身份固定，以及 Add 候选附属材料和曾入群账号的持久所有权。
use super::{codec, ensure, permissions, state::DeviceState, LabError, Pin, MAX_RECORDS};
use crate::permission::{
    self, admission::JoinMaterial, receipts::RecoveryRecord, Action, Member, PermissionCheckpoint,
    Proof, Statement,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct JoinAnchor {
    pub checkpoint: PermissionCheckpoint,
    pub relay_receipt_key: String,
    #[serde(default)]
    pub mode: JoinMode,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum JoinMode {
    #[default]
    Member,
    Device,
}

impl JoinMode {
    pub(super) fn accepts(self, action: &Action) -> bool {
        matches!(
            (self, action),
            (Self::Member, Action::AddMember { .. }) | (Self::Device, Action::AddDevice { .. })
        )
    }
}

fn check_key_binding(state: &DeviceState, member: &Member) -> Result<(), LabError> {
    ensure(
        !state.permissions.admission.seen_members.iter().any(|old| {
            (old.signature_key == member.signature_key && old.identity() != member.identity())
                || (old.identity() == member.identity()
                    && old.signature_key != member.signature_key)
        }) && !state.peer_pins.iter().any(|old| {
            (old.signature_key == member.signature_key
                && (old.account != member.account_id || old.device != member.device_id))
                || (old.account == member.account_id
                    && old.device == member.device_id
                    && old.signature_key != member.signature_key)
        }),
        "identity_changed",
        "已固定或曾入群的公钥不能改绑到其他设备身份",
    )
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct AdmissionState {
    pub anchor: Option<JoinAnchor>,
    pub public_records: BTreeMap<String, RecoveryRecord>,
    pub materials: BTreeMap<String, JoinMaterial>,
    pub ever_accounts: BTreeSet<String>,
    #[serde(default)]
    pub seen_members: Vec<Member>,
    #[serde(default)]
    pub device_history_complete: bool,
    pub joined_record: Option<RecoveryRecord>,
    pub joined_epoch: Option<String>,
}

pub(super) fn pin(state: &mut DeviceState, member: Member) -> Result<Value, LabError> {
    super::wire_types::id(&member.account_id)?;
    super::wire_types::id(&member.device_id)?;
    permission::receipts::validate_key(&member.signature_key)?;
    check_key_binding(state, &member)?;
    ensure(
        member.account_id != state.context.account,
        "join_identity",
        "此独立信任入口不授权同账号新设备",
    )?;
    if let Some(old) = state
        .peer_pins
        .iter()
        .find(|old| old.account == member.account_id && old.device == member.device_id)
    {
        ensure(
            old.signature_key == member.signature_key,
            "identity_changed",
            "独立身份 pin 不可改绑",
        )?;
        return Ok(json!({"member":member,"reused":true}));
    }
    ensure(
        state.peer_pins.len() < 31,
        "resource_exhausted",
        "独立身份 pin 已满",
    )?;
    ensure(
        codec::decode(&member.signature_key)? != state.own_signature_key
            && !state
                .peer_pins
                .iter()
                .any(|old| old.signature_key == member.signature_key),
        "identity_changed",
        "不同设备不能复用身份公钥",
    )?;
    state.peer_pins.push(Pin {
        account: member.account_id.clone(),
        device: member.device_id.clone(),
        signature_key: member.signature_key.clone(),
    });
    Ok(json!({"member":member,"reused":false}))
}

pub(super) fn check_new_member(state: &DeviceState, action: &Action) -> Result<(), LabError> {
    if let Action::AddMember { member, .. } | Action::AddDevice { member, .. } = action {
        check_key_binding(state, member)?;
    }
    let member = match action {
        Action::AddMember { member, .. } => {
            ensure(
                state.peer_pins.iter().any(|pin| {
                    pin.account == member.account_id
                        && pin.device == member.device_id
                        && pin.signature_key == member.signature_key
                }),
                "missing_pin",
                "新账号成员必须先有独立固定的身份 pin",
            )?;
            ensure(
                !state
                    .permissions
                    .admission
                    .ever_accounts
                    .contains(&member.account_id),
                "join_reentry",
                "本轮不支持旧账号重新入群",
            )?;
            member
        }
        Action::AddDevice { member, .. } => {
            ensure(
                state.permissions.admission.device_history_complete,
                "device_history_unavailable",
                "旧快照缺少完整设备身份历史，不能启用同账号新增设备",
            )?;
            ensure(
                !state
                    .permissions
                    .admission
                    .seen_members
                    .iter()
                    .any(|old| old.identity() == member.identity())
                    && !state
                        .permissions
                        .admission
                        .seen_members
                        .iter()
                        .any(|old| old.signature_key == member.signature_key),
                "join_reentry",
                "本轮不支持曾入群的设备或公钥重新加入",
            )?;
            member
        }
        _ => return Ok(()),
    };
    // 已有记录同时保留撤销目标；旧快照的设备公钥历史仍由完整性标记单独拒绝。
    for proof in state.permissions.applied.values().chain(
        state
            .permissions
            .admission
            .public_records
            .values()
            .map(|r| &r.change),
    ) {
        let old = Statement::parse(&codec::decode(&proof.statement_bytes)?)?;
        let known = match (&old.action, action) {
            (Action::RemoveMember { account_id }, _) => *account_id == member.account_id,
            (
                Action::RevokeDevice {
                    account_id,
                    device_id,
                },
                Action::AddDevice { .. },
            ) => *account_id == member.account_id && *device_id == member.device_id,
            (Action::RevokeDevice { account_id, .. }, _) => *account_id == member.account_id,
            (
                Action::AddMember { member: old, .. } | Action::AddDevice { member: old, .. },
                Action::AddDevice { .. },
            ) => old.identity() == member.identity() || old.signature_key == member.signature_key,
            (Action::AddMember { member: old, .. } | Action::AddDevice { member: old, .. }, _) => {
                old.account_id == member.account_id
            }
        };
        ensure(!known, "join_reentry", "本轮不支持已变更身份重新入群")?;
    }
    Ok(())
}

pub(super) fn remember(state: &mut DeviceState, checkpoint: &PermissionCheckpoint) {
    for member in &checkpoint.members {
        if !state
            .permissions
            .admission
            .seen_members
            .iter()
            .any(|old| old.identity() == member.identity())
        {
            state
                .permissions
                .admission
                .seen_members
                .push(member.clone());
        }
    }
    state
        .permissions
        .admission
        .seen_members
        .sort_by_key(Member::identity);
    state
        .permissions
        .admission
        .ever_accounts
        .extend(checkpoint.members.iter().map(|m| m.account_id.clone()));
}

pub(super) fn prepare(
    state: &mut DeviceState,
    change_id: String,
    member: Member,
    key_package: String,
    history_policy: String,
    validity_secs: Option<u16>,
    mode: JoinMode,
) -> Result<Value, LabError> {
    ensure(
        state.permissions.recovery.relay_receipt_key.is_some(),
        "receipt_pin_required",
        "入群需固定 Service 回执钥",
    )?;
    ensure(
        history_policy == "from_join",
        "invalid_permission",
        "仅支持入群后历史策略",
    )?;
    let key_package_sha256 =
        permission::commit_digest(&permission::types::bytes(&key_package, 512 * 1024)?);
    let welcome_sha256 = "0".repeat(64);
    let action = match mode {
        JoinMode::Member => Action::AddMember {
            member,
            key_package_sha256,
            welcome_sha256,
            history_policy,
        },
        JoinMode::Device => Action::AddDevice {
            member,
            key_package_sha256,
            welcome_sha256,
            history_policy,
        },
    };
    ensure(
        state.permissions.admission.materials.len() < MAX_RECORDS
            || state
                .permissions
                .admission
                .materials
                .contains_key(&change_id),
        "resource_exhausted",
        "入群候选材料已满",
    )?;
    permissions::prepare_change(state, change_id, action, validity_secs, Some(key_package))
}

pub(super) fn prepared(
    state: &DeviceState,
    change: &Proof,
    reused: bool,
) -> Result<Value, LabError> {
    let statement = Statement::parse(&codec::decode(&change.statement_bytes)?)?;
    let mut result = json!({"change":change,"reused":reused});
    if matches!(
        statement.action,
        Action::AddMember { .. } | Action::AddDevice { .. }
    ) {
        let join = state
            .permissions
            .admission
            .materials
            .get(&statement.change_id)
            .ok_or_else(|| LabError::new("missing_join_material", "候选缺少持久入群材料"))?;
        result["join"] = serde_json::to_value(join)
            .map_err(|_| LabError::new("permission_encoding", "入群材料编码失败"))?;
    }
    Ok(result)
}

pub(super) fn summary(state: &DeviceState) -> Value {
    json!({"device_history_complete":state.permissions.admission.device_history_complete,"anchor_mode":state.permissions.admission.anchor.as_ref().map(|a|a.mode),"group_trust_source":state.permissions.checkpoint.as_ref().map(|_|"verified_permission_checkpoint"),"public_checkpoint":state.permissions.admission.anchor.as_ref().map(|a|&a.checkpoint),
        "joined_epoch":state.permissions.admission.joined_epoch,
        "joined_authorization_version":state.permissions.admission.joined_record.as_ref().and_then(|record|Statement::parse(&codec::decode(&record.change.statement_bytes).ok()?).ok()).map(|s|s.authorization_version),
        "history_policy":state.permissions.admission.joined_record.as_ref().map(|_|"from_join")})
}
