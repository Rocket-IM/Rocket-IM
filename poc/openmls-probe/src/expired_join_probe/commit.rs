//! 仅验收装置的精确候选检查；不代替签名权限链或 Service 授权。
use super::*;
use actor::Actor;

pub(super) fn replacement(
    actor: &Actor,
    removed: LeafNodeIndex,
    packages: Vec<KeyPackage>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut group = actor.group()?;
    ensure(
        group.pending_proposals().next().is_none(),
        "pending proposals forbidden",
    )?;
    let bundle = checked(
        "build replacement",
        checked(
            "load psks",
            group
                .commit_builder()
                .consume_proposal_store(false)
                .propose_removals([removed])
                .propose_adds(packages)
                .load_psks(actor.provider.storage()),
        )?
        .build(
            actor.provider.rand(),
            actor.provider.crypto(),
            &actor.signer,
            |_| true,
        ),
    )?;
    let (commit, welcome, _) =
        checked("stage replacement", bundle.stage_commit(&actor.provider))?.into_messages();
    let welcome = welcome.ok_or("missing welcome")?;
    Ok((
        checked("commit bytes", commit.to_bytes())?,
        checked("welcome bytes", welcome.to_bytes())?,
    ))
}

pub(super) fn accept(
    actor: &Actor,
    bytes: &[u8],
    removed: LeafNodeIndex,
    package: &KeyPackage,
    sender: LeafNodeIndex,
) -> Result<(), String> {
    let mut group = actor.group()?;
    let old = group
        .members()
        .find(|m| m.index == removed)
        .ok_or("missing old leaf")?;
    ensure(
        old.credential == *package.leaf_node().credential()
            && old.signature_key == package.leaf_node().signature_key().as_slice(),
        "replacement identity mismatch",
    )?;
    ensure(
        checked(
            "old leaf key",
            tls_codec::VLBytes::new(old.encryption_key).tls_serialize_detached(),
        )? != checked(
            "new leaf key",
            package
                .leaf_node()
                .encryption_key()
                .tls_serialize_detached(),
        )?,
        "leaf encryption key reused",
    )?;
    let processed = checked(
        "process replacement",
        group.process_message(&actor.provider, protocol(bytes)?),
    )?;
    ensure(
        processed.sender() == &Sender::Member(sender)
            && processed.epoch() == group.epoch()
            && processed.group_id() == group.group_id(),
        "sender/group/epoch mismatch",
    )?;
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err("not staged commit".into());
    };
    ensure(
        staged.queued_proposals().count() == 2
            && staged
                .queued_proposals()
                .all(|p| p.proposal_or_ref_type() == ProposalOrRefType::Proposal),
        "exactly two inline proposals required",
    )?;
    let removes: Vec<_> = staged
        .remove_proposals()
        .map(|p| p.remove_proposal().removed())
        .collect();
    let adds: Vec<_> = staged.add_proposals().collect();
    ensure(
        removes == [removed] && adds.len() == 1 && adds[0].add_proposal().key_package() == package,
        "exact Remove/Add mismatch",
    )?;
    ensure(
        staged.update_path_leaf_node().is_some(),
        "update path required",
    )?;
    checked(
        "merge replacement",
        group.merge_staged_commit(&actor.provider, *staged),
    )
}

pub(super) fn same_state(a: &Actor, b: &Actor) -> Result<(), String> {
    let a = a.group()?;
    let b = b.group()?;
    ensure(
        a.group_id() == b.group_id()
            && a.epoch() == b.epoch()
            && a.members().eq(b.members())
            && a.export_ratchet_tree() == b.export_ratchet_tree(),
        "full group state mismatch",
    )
}
