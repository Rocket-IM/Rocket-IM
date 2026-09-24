use super::{checked, codec, ensure, state::DeviceState, LabError, Peer, Pin};
use openmls::prelude::{tls_codec::Deserialize, *};
use serde_json::{json, Value};

fn matches_pin(
    state: &DeviceState,
    context: &super::Context,
    key: &[u8],
    pins: &[Pin],
) -> Result<(), LabError> {
    ensure(
        context.service == state.context.service,
        "wrong_service",
        "群成员属于其他实例",
    )?;
    if context.account == state.context.account {
        let trusted = state
            .roster
            .trusted_signature_key(&context.device)
            .ok_or_else(|| LabError::new("device_not_authorized", "同账号设备尚未授权"))?;
        ensure(
            trusted.as_slice() == key,
            "identity_changed",
            "同账号设备公钥与可信检查点不匹配",
        )
    } else {
        let matching: Vec<_> = pins
            .iter()
            .filter(|pin| pin.account == context.account && pin.device == context.device)
            .collect();
        ensure(
            matching.len() == 1,
            "missing_pin",
            "其他账号成员没有唯一的可信 fixture pin",
        )?;
        ensure(
            codec::decode(&matching[0].signature_key)? == key,
            "identity_changed",
            "成员公钥与独立可信 fixture pin 不匹配",
        )
    }
}

pub(super) fn validate_members(state: &DeviceState, group: &MlsGroup) -> Result<(), LabError> {
    if let Some(checkpoint) = &state.permissions.checkpoint {
        // 此检查点已由本机验证；它只授权本群，不改写独立的账号 TrustedRoster。
        return ensure(
            checkpoint.service_id == state.context.service
                && checkpoint.crypto_state_ref == super::wire::state_ref(group)?
                && checkpoint.members == super::permission_state::decoded_members(state, group)?,
            "permission_context",
            "实际 MLS 身份集合与本群已验证检查点不匹配",
        );
    }
    for member in group.members() {
        let context = codec::credential_context(&member.credential)?;
        matches_pin(state, &context, &member.signature_key, &state.peer_pins)?;
    }
    Ok(())
}

pub(super) fn create(state: &mut DeviceState, peers: Vec<Peer>) -> Result<Value, LabError> {
    ensure(
        state.group_id.is_none(),
        "already_grouped",
        "当前实验每个设备只允许一个群",
    )?;
    ensure(
        !peers.is_empty() && peers.len() <= 31,
        "resource_limit",
        "群需 1—31 个对端设备",
    )?;
    let mut packages = Vec::new();
    let pins: Vec<_> = peers
        .iter()
        .map(|peer| Pin {
            account: peer.account.clone(),
            device: peer.device.clone(),
            signature_key: peer.signature_key.clone(),
        })
        .collect();
    for peer in peers {
        codec::valid_id(&peer.account)?;
        codec::valid_id(&peer.device)?;
        let package =
            codec::validated_package(&codec::decode(&peer.key_package)?, &state.provider)?;
        let context = codec::credential_context(package.leaf_node().credential())?;
        ensure(
            context.account == peer.account && context.device == peer.device,
            "key_package_identity",
            "KeyPackage 的账号或设备身份不匹配",
        )?;
        matches_pin(
            state,
            &context,
            package.leaf_node().signature_key().as_slice(),
            &pins,
        )?;
        packages.push(package);
    }
    let signer = state.signer()?;
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(codec::CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group = checked(
        "group_create",
        MlsGroup::new(&state.provider, &signer, &config, state.own_credential()?),
    )?;
    let (_, welcome, _) = checked(
        "group_add",
        group.add_members(&state.provider, &signer, &packages),
    )?;
    checked("group_commit", group.merge_pending_commit(&state.provider))?;
    state.group_id = Some(group.group_id().as_slice().to_vec());
    state.peer_pins = pins;
    validate_members(state, &group)?;
    Ok(
        json!({"welcome":codec::encode(&checked("welcome_encoding",welcome.to_bytes())?),
        "group_id":codec::encode(group.group_id().as_slice()),"epoch":group.epoch().as_u64(),"members":group.members().count()}),
    )
}

pub(super) fn join(
    state: &mut DeviceState,
    welcome: &str,
    pins: Vec<Pin>,
) -> Result<Value, LabError> {
    ensure(
        state.group_id.is_none(),
        "already_grouped",
        "设备已有群状态，不能覆盖",
    )?;
    ensure(
        pins.len() <= 31,
        "resource_limit",
        "可信 fixture pin 数量超过上限",
    )?;
    let message = checked(
        "welcome_encoding",
        MlsMessageIn::tls_deserialize_exact(codec::decode(welcome)?),
    )?;
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err(LabError::new("message_type", "预期 Welcome")),
    };
    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let staged = checked(
        "welcome_validation",
        StagedWelcome::new_from_welcome(&state.provider, &config, welcome, None),
    )?;
    let group = checked("group_join", staged.into_group(&state.provider))?;
    state.peer_pins = pins;
    validate_members(state, &group)?;
    state.group_id = Some(group.group_id().as_slice().to_vec());
    state.inspect()
}

pub(super) fn remove(state: &mut DeviceState, member: &str) -> Result<Value, LabError> {
    codec::valid_id(member)?;
    let mut group = state.group()?;
    validate_members(state, &group)?;
    let matching = group
        .members()
        .map(|entry| Ok((entry.index, codec::credential_context(&entry.credential)?)))
        .collect::<Result<Vec<_>, LabError>>()?
        .into_iter()
        .filter(|(_, context)| context.device == member)
        .collect::<Vec<_>>();
    ensure(
        matching.len() == 1,
        "member_target",
        "移除目标不存在或设备名有歧义",
    )?;
    ensure(
        matching[0].0 != group.own_leaf_index(),
        "remove_self",
        "不能用此请求移除自己",
    )?;
    let (commit, _, _) = checked(
        "remove_member",
        group.remove_members(&state.provider, &state.signer()?, &[matching[0].0]),
    )?;
    let bytes = checked("commit_encoding", commit.to_bytes())?;
    checked("remove_commit", group.merge_pending_commit(&state.provider))?;
    Ok(
        json!({"commit":codec::encode(&bytes),"epoch":group.epoch().as_u64(),"members":group.members().count()}),
    )
}

pub(super) fn apply_commit(state: &mut DeviceState, encoded: &str) -> Result<Value, LabError> {
    let mut group = state.group()?;
    let processed = checked(
        "commit_validation",
        group.process_message(&state.provider, codec::protocol(&codec::decode(encoded)?)?),
    )?;
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => commit,
        _ => return Err(LabError::new("message_type", "预期成员变更 Commit")),
    };
    // 此最小实验只允许已入群设备的移除；新增成员须以后接入完整授权链。
    ensure(
        staged.add_proposals().next().is_none(),
        "unsupported_add",
        "该实验入口不接受重新添加成员的 Commit",
    )?;
    checked(
        "commit_storage",
        group.merge_staged_commit(&state.provider, *staged),
    )?;
    validate_members(state, &group)?;
    state.inspect()
}
