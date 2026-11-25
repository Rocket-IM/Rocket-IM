//! R1 必须安装真实密码状态；先持久观察 R0，MLS 失败时仍保留该接受事实。
use super::{
    checked, codec, ensure, join_recovery_mls as mls, join_recovery_state as stored,
    permission_state as ps, state::DeviceState, wire, wire_types, CrashPoint, LabError,
};
use crate::{join_recovery as p, permission};
use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    *,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::{json, Value};

fn survivor(
    state: &DeviceState,
    record: &p::PublicRecord,
    s: &p::Statement,
) -> Result<OpenMlsRustCrypto, LabError> {
    let cp = state
        .permissions
        .checkpoint
        .as_ref()
        .ok_or_else(|| LabError::new("recovery_r1_required", "缺少真实前驱"))?;
    ps::validate_current(state, cp, &state.group()?)?;
    if let Some(pending) = &stored::get(state)?.pending {
        return ps::provider_from(&pending.candidate_entries);
    }
    let provider = ps::provider_from(&ps::entries(&state.provider)?)?;
    let mut group = ps::group_from(state, &provider)?;
    let old = mls::leaf(&group, &s.action.target)?;
    let sender = mls::leaf(&group, &s.actor)?;
    ensure(
        old.u32().to_string() == s.action.old_leaf_index
            && mls::leaf_hash(&group, old)? == s.action.old_leaf_sha256
            && group.epoch().as_u64().to_string() == s.action.previous_epoch
            && codec::encode(group.group_id().as_slice()) == s.scope.group_id
            && group.pending_proposals().next().is_none()
            && group.pending_commit().is_none(),
        "recovery_commit",
        "旧叶、epoch 或群不符",
    )?;
    let old_leaf = group
        .public_group()
        .leaf(old)
        .cloned()
        .ok_or_else(|| LabError::new("recovery_leaf", "旧叶缺失"))?;
    let message = checked(
        "recovery_commit",
        MlsMessageIn::tls_deserialize_exact(codec::decode(&record.bundle.change.commit_bytes)?),
    )?;
    let protocol = checked("recovery_commit", message.try_into_protocol_message())?;
    let processed = checked(
        "recovery_commit",
        group.process_message(&provider, protocol),
    )?;
    ensure(
        processed.sender() == &Sender::Member(sender)
            && processed.epoch() == group.epoch()
            && processed.group_id() == group.group_id(),
        "recovery_commit",
        "实际发送者不符",
    )?;
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err(LabError::new("recovery_commit", "需要真实 Commit"));
    };
    let additions: Vec<_> = staged.add_proposals().collect();
    ensure(additions.len() == 1, "recovery_commit", "需要单个真实 Add")?;
    let package = additions[0].add_proposal().key_package();
    ensure(
        permission::commit_digest(&checked(
            "recovery_commit",
            package.tls_serialize_detached(),
        )?) == s.action.key_package_sha256
            && crate::key_package::material::metadata(package)?.key_package_ref
                == s.action.key_package_ref
            && old_leaf.credential() == package.leaf_node().credential()
            && old_leaf.signature_key() == package.leaf_node().signature_key()
            && old_leaf.encryption_key() != package.leaf_node().encryption_key(),
        "recovery_commit",
        "实际 Add 未替换准确身份与新材料",
    )?;
    mls::proposals(&staged, old, package)?;
    checked(
        "recovery_commit",
        group.merge_staged_commit(&provider, *staged),
    )?;
    Ok(provider)
}
fn target(
    state: &DeviceState,
    record: &p::Record,
    s: &p::Statement,
    point: CrashPoint,
) -> Result<(OpenMlsRustCrypto, MlsGroup), LabError> {
    let provider = ps::provider_from(&ps::entries(&state.provider)?)?;
    let message = checked(
        "welcome_validation",
        MlsMessageIn::tls_deserialize_exact(codec::decode(&record.bundle.welcome)?),
    )?;
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return Err(LabError::new("welcome_validation", "需要真实 Welcome"));
    };
    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let processed = checked(
        "welcome_validation",
        ProcessedWelcome::new_from_welcome(&provider, &config, welcome),
    )?;
    if matches!(point, CrashPoint::AfterWelcomeKeys) {
        std::process::exit(83);
    }
    ensure(
        processed.own_key_package().is_some_and(|k| {
            k.tls_serialize_detached()
                .is_ok_and(|raw| codec::encode(&raw) == record.bundle.key_package)
        }),
        "welcome_context",
        "Welcome 未用准确新包",
    )?;
    let staged = checked(
        "welcome_validation",
        processed.into_staged_welcome(&provider, None),
    )?;
    let sender = checked("welcome_validation", staged.welcome_sender())?;
    let context = codec::credential_context(sender.credential())?;
    ensure(
        context.service == state.context.service
            && context.account == s.actor.account_id
            && context.device == s.actor.device_id
            && sender.signature_key().as_slice() == codec::decode(&s.actor.signature_key)?,
        "welcome_actor",
        "Welcome 签发者不符",
    )?;
    let group = checked("welcome_validation", staged.into_group(&provider))?;
    if matches!(point, CrashPoint::AfterWelcomeValidation) {
        std::process::exit(84);
    }
    Ok((provider, group))
}
pub(super) fn apply(
    state: &mut DeviceState,
    record: p::Evidence,
    point: CrashPoint,
) -> Result<Value, LabError> {
    apply_inner(state, record, point, false)
}
pub(super) fn apply_witness(
    state: &mut DeviceState,
    record: p::Evidence,
    point: CrashPoint,
) -> Result<Value, LabError> {
    apply_inner(state, record, point, true)
}
fn apply_inner(
    state: &mut DeviceState,
    record: p::Evidence,
    point: CrashPoint,
    witness_authorized: bool,
) -> Result<Value, LabError> {
    let Some(super::join_recovery_preflight::Ready {
        change_id,
        previous,
        next,
        statement: s,
        own_target,
    }) = (if witness_authorized {
        super::join_recovery_preflight::check_witness(state, &record)
    } else {
        super::join_recovery_preflight::check(state, &record)
    })?
    else {
        return Ok(
            json!({"duplicate":true,"installed":true,"checkpoint":state.permissions.checkpoint}),
        );
    };
    let public = record.public();
    let (provider, mut group) = if own_target {
        target(
            state,
            record.full().ok_or_else(|| {
                LabError::new("recovery_material_required", "目标准确 Welcome 尚未读取")
            })?,
            &s,
            point,
        )?
    } else {
        let provider = survivor(state, &public, &s)?;
        let group = ps::group_from(state, &provider)?;
        (provider, group)
    };
    let epoch = s
        .action
        .previous_epoch
        .parse::<u64>()
        .ok()
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| LabError::new("recovery_commit", "epoch 溢出"))?;
    ensure(
        codec::encode(group.group_id().as_slice()) == s.scope.group_id
            && group.epoch().as_u64() == epoch
            && wire::state_ref(&group)? == next.crypto_state_ref
            && ps::decoded_members(state, &group)? == next.members,
        "recovery_commit",
        "实际完整群状态与 R0 不符",
    )?;
    if own_target {
        super::wire_history::enable(&provider, &mut group)?;
        state.permissions.history.past.clear();
        let package = state
            .key_packages
            .as_mut()
            .and_then(|pool| pool.packages.get_mut(&s.action.key_package_sha256))
            .ok_or_else(|| LabError::new("key_package_missing", "新材料缺失"))?;
        crate::key_package::material::current(&package.material, super::join_recovery::now()?)?;
        state.recovery_deadline = Some((
            package
                .material
                .not_before
                .parse()
                .map_err(|_| LabError::new("recovery_state", "期限损坏"))?,
            package
                .material
                .not_after
                .parse()
                .map_err(|_| LabError::new("recovery_state", "期限损坏"))?,
        ));
        package.consumed = true;
        state.permissions.admission.joined_epoch = Some(epoch.to_string());
    } else {
        super::join_recovery_witness_response::installed(state, &public, &s, &previous, &next)?;
        super::wire_history::archive(state, epoch - 1, previous, &mut group, &provider)?;
    }
    let source = stored::key(state)?.to_owned();
    state.group_id = Some(group.group_id().as_slice().to_vec());
    state.provider = provider;
    state.wire.configuration = Some(wire_types::Configuration {
        conversation_id: next.conversation_id.clone(),
        authorization_version: next.authorization_version.clone(),
        crypto_state_ref: next.crypto_state_ref.clone(),
        members: next
            .members
            .iter()
            .map(|m| wire_types::Device {
                account_id: m.account_id.clone(),
                device_id: m.device_id.clone(),
            })
            .collect(),
    });
    state.permissions.recovery.relay_receipt_key = Some(source);
    state.permissions.recovery.verified_refs.insert(
        next.authorization_version.clone(),
        next.crypto_state_ref.clone(),
    );
    state.permissions.used_nonces.insert(s.nonce);
    state.permissions.recovery.prepare_count = 0;
    state.permissions.checkpoint = Some(next.clone());
    super::permission_admission::remember(state, &next);
    let s = stored::get_mut(state)?;
    s.records
        .get_mut(&change_id)
        .ok_or_else(|| LabError::new("recovery_state", "接受记录缺失"))?
        .installed = true;
    s.pending = None;
    Ok(json!({"duplicate":false,"installed":true,"checkpoint":next,"epoch":epoch.to_string()}))
}
