//! 单个真实 Remove+Add；临时 provider 构造候选，base 保存已用握手 generation。
use super::{
    checked, codec, ensure, join_recovery_state as stored, permission_state as ps,
    state::DeviceState, wire, LabError,
};
use crate::{
    join_recovery as p,
    permission::{self, receipts::SignedRecord, Member},
};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use openmls::treesync::LeafNodeSource;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};

pub(super) fn leaf(group: &MlsGroup, target: &Member) -> Result<LeafNodeIndex, LabError> {
    for member in group.members() {
        let c = codec::credential_context(&member.credential)?;
        if c.account == target.account_id
            && c.device == target.device_id
            && member.signature_key == codec::decode(&target.signature_key)?
        {
            return Ok(member.index);
        }
    }
    Err(LabError::new("recovery_leaf", "准确目标叶不存在"))
}
pub(super) fn leaf_hash(group: &MlsGroup, index: LeafNodeIndex) -> Result<String, LabError> {
    let leaf = group
        .public_group()
        .leaf(index)
        .ok_or_else(|| LabError::new("recovery_leaf", "旧叶缺失"))?;
    Ok(permission::commit_digest(&checked(
        "recovery_leaf",
        leaf.tls_serialize_detached(),
    )?))
}
pub(super) fn check(
    state: &DeviceState,
    intent: &SignedRecord,
    claim: &SignedRecord,
    allocation: &SignedRecord,
    key_package: &str,
) -> Result<(), LabError> {
    let i = p::parse_intent(intent)?;
    ensure(
        i.actor == super::key_package_state::own(state),
        "permission_denied",
        "只能由指定批准者构造",
    )?;
    let s = stored::get(state)?;
    let existing = s.pending.as_ref().map(|p| &p.bundle).or_else(|| {
        s.records
            .get(&i.change_id)
            .and_then(|r| r.record.full().map(|r| &r.bundle))
    });
    if let Some(b) = existing {
        ensure(
            b.intent == *intent
                && b.claim == *claim
                && b.allocation == *allocation
                && b.key_package == key_package,
            "idempotency_conflict",
            "候选只允许原字节重试",
        )?;
        return Ok(());
    }
    ensure(
        !s.closed.contains_key(&i.request_id),
        "recovery_closed",
        "该尝试已经封口",
    )?;
    super::join_recovery_request::intent(state, &i)?;
    let (c, _) = p::control(claim, intent)?;
    ensure(
        s.requests.get(&c.request_id) == Some(claim),
        "recovery_claim_missing",
        "缺少已持久本机领取请求",
    )?;
    let reference = p::allocation(&i, intent, claim, allocation, stored::key(state)?)?;
    let material =
        crate::key_package::material::inspect(key_package, &state.context.service, &i.signer)?;
    ensure(
        material.key_package_sha256 == i.key_package_sha256
            && material.key_package_ref == reference,
        "recovery_invalid",
        "新材料未准确绑定分配",
    )?;
    let now = super::join_recovery::now()?;
    ensure(
        i.issued_at_unix_secs.parse::<u64>().is_ok_and(|t| t <= now)
            && i.expires_at_unix_secs.parse::<u64>().is_ok_and(|t| now < t),
        "recovery_expired",
        "目标意图已过期",
    )?;
    ensure(
        state.permissions.recovery.prepare_count < 64,
        "permission_epoch_budget",
        "前驱候选预算已满",
    )?;
    Ok(())
}
pub(super) fn proposals(
    staged: &StagedCommit,
    old: LeafNodeIndex,
    package: &KeyPackage,
) -> Result<(), LabError> {
    let removals: Vec<_> = staged
        .remove_proposals()
        .map(|r| r.remove_proposal().removed())
        .collect();
    let adds: Vec<_> = staged.add_proposals().collect();
    ensure(
        staged.queued_proposals().count() == 2
            && staged
                .queued_proposals()
                .all(|p| p.proposal_or_ref_type() == ProposalOrRefType::Proposal)
            && removals == [old]
            && adds.len() == 1
            && adds[0].add_proposal().key_package() == package
            && staged.update_path_leaf_node().is_some(),
        "recovery_commit",
        "需要准确的 inline Remove/Add 和新路径",
    )
}
pub(super) fn prepare(
    state: &mut DeviceState,
    intent: SignedRecord,
    claim: SignedRecord,
    allocation: SignedRecord,
    key_package: String,
) -> Result<Value, LabError> {
    check(state, &intent, &claim, &allocation, &key_package)?;
    let i = p::parse_intent(&intent)?;
    let s = stored::get(state)?;
    if let Some(b) = s.pending.as_ref().map(|p| &p.bundle).or_else(|| {
        s.records
            .get(&i.change_id)
            .and_then(|r| r.record.full().map(|r| &r.bundle))
    }) {
        return Ok(json!({"bundle":b,"duplicate":true}));
    }
    let cp = stored::checkpoint(state)?.clone();
    let root = s
        .roots
        .get(&i.root_admission.change_id)
        .ok_or_else(|| LabError::new("recovery_chain_missing", "缺少根"))?
        .record
        .clone();
    ps::validate_current(state, &cp, &state.group()?)?;
    let provider = ps::provider_from(&ps::entries(&state.provider)?)?;
    let mut group = ps::group_from(state, &provider)?;
    ensure(
        codec::encode(group.group_id().as_slice()) == i.scope.group_id
            && group.pending_proposals().next().is_none()
            && group.pending_commit().is_none(),
        "recovery_commit",
        "群范围或待决提案不符",
    )?;
    let old = leaf(&group, &i.signer)?;
    let old_leaf = group
        .public_group()
        .leaf(old)
        .ok_or_else(|| LabError::new("recovery_leaf", "旧叶缺失"))?;
    ensure(
        matches!(old_leaf.leaf_node_source(),LeafNodeSource::KeyPackage(life) if super::join_recovery::now().is_ok_and(|t|t>=life.not_after())),
        "recovery_not_expired",
        "准确当前叶尚未过期或已更新",
    )?;
    let old_hash = leaf_hash(&group, old)?;
    let package =
        permission::admission::validate_package(&key_package, &state.context.service, &i.signer)?;
    ensure(
        old_leaf.encryption_key() != package.leaf_node().encryption_key(),
        "key_package_reuse",
        "叶秘密不可复用",
    )?;
    let epoch = group.epoch().as_u64();
    let signer = state.signer()?;
    let builder = checked(
        "recovery_commit",
        group
            .commit_builder()
            .consume_proposal_store(false)
            .propose_removals([old])
            .propose_adds([package.clone()])
            .load_psks(provider.storage()),
    )?;
    let bundle = checked(
        "recovery_commit",
        builder.build(provider.rand(), provider.crypto(), &signer, |_| true),
    )?;
    let (commit, welcome, _) =
        checked("recovery_commit", bundle.stage_commit(&provider))?.into_messages();
    proposals(
        group
            .pending_commit()
            .ok_or_else(|| LabError::new("recovery_commit", "缺少真实候选"))?,
        old,
        &package,
    )?;
    let commit = checked("recovery_commit", commit.to_bytes())?;
    let welcome = checked(
        "recovery_commit",
        welcome
            .ok_or_else(|| LabError::new("recovery_commit", "缺少真实 Welcome"))?
            .to_bytes(),
    )?;
    let base = ps::provider_from(&ps::entries(&provider)?)?;
    checked(
        "recovery_commit",
        ps::group_from(state, &base)?.clear_pending_commit(base.storage()),
    )?;
    checked("recovery_commit", group.merge_pending_commit(&provider))?;
    ensure(
        ps::decoded_members(state, &group)? == cp.members,
        "recovery_commit",
        "恢复不改变业务成员集合",
    )?;
    let version = cp
        .authorization_version
        .parse::<u64>()
        .ok()
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| LabError::new("permission_version", "版本溢出"))?;
    let mut nonce = [0u8; 32];
    checked("random_source", getrandom::getrandom(&mut nonce))?;
    let statement = p::Statement {
        protocol_version: if i.policy_ref.is_some() {
            "rim-permission-4"
        } else {
            "rim-permission-3"
        }
        .into(),
        witness_profile: i.witness_profile.clone(),
        policy_ref: i.policy_ref.clone(),
        scope: i.scope.clone(),
        change_id: i.change_id.clone(),
        actor: i.actor.clone(),
        previous_authorization_version: cp.authorization_version.clone(),
        authorization_version: version.to_string(),
        from_state_ref: cp.crypto_state_ref.clone(),
        to_state_ref: wire::state_ref(&group)?,
        commit_sha256: permission::commit_digest(&commit),
        nonce: codec::digest_hex(&nonce),
        issued_at_unix_secs: super::join_recovery::now()?.to_string(),
        expires_at_unix_secs: i.expires_at_unix_secs.clone(),
        action: p::Action {
            kind: p::RecoveryKind::RecoverJoin,
            recovery_id: i.request_id.clone(),
            root_admission: i.root_admission.clone(),
            current_admission: i.current_admission.clone(),
            target: i.signer.clone(),
            intent_sha256: p::signed_digest(&intent)?,
            allocation_sha256: p::signed_digest(&allocation)?,
            key_package_sha256: i.key_package_sha256.clone(),
            key_package_ref: codec::encode(
                checked("recovery_commit", package.hash_ref(provider.crypto()))?.as_slice(),
            ),
            welcome_sha256: permission::commit_digest(&welcome),
            history_policy: "from_recovery".into(),
            previous_epoch: epoch.to_string(),
            old_leaf_index: old.u32().to_string(),
            old_leaf_sha256: old_hash,
        },
    };
    let signed = p::sign(&statement, statement.domain()?, &signer)?;
    let bundle = p::Bundle {
        intent,
        claim,
        allocation,
        key_package,
        welcome: codec::encode(&welcome),
        change: permission::Proof {
            statement_bytes: signed.statement_bytes,
            signature_bytes: signed.signature_bytes,
            commit_bytes: codec::encode(&commit),
        },
    };
    p::candidate(&cp, &root, stored::key(state)?, &bundle, true)?;
    ensure(
        checked(
            "recovery_encoding",
            serde_json::to_vec(&json!({"kind":"accept","bundle":bundle})),
        )?
        .len()
            <= 900 * 1024,
        "resource_exhausted",
        "完整候选超限，须封口原尝试",
    )?;
    state.provider = base;
    state.permissions.recovery.prepare_count += 1;
    stored::get_mut(state)?.pending = Some(stored::Pending {
        bundle: bundle.clone(),
        candidate_entries: ps::entries(&provider)?,
    });
    stored::budget(stored::get(state)?)?;
    Ok(json!({"bundle":bundle,"duplicate":false}))
}
