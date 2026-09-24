//! 单个不可替换的后继及永久取消状态，与原预约同快照提交。
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rollback_anchor) struct Link {
    pub(in crate::rollback_anchor) plan: Plan,
    pub(in crate::rollback_anchor) child: Box<authority::State>,
    pub(in crate::rollback_anchor) cancelled: bool,
}

pub(in crate::rollback_anchor) fn validate_link(
    state: &authority::State,
) -> Result<(), AnchorError> {
    if let Some(trust) = &state.rebuild_trust {
        trust.validate(&state.scope)?;
    }
    if let Some(link) = &state.rebuild_link {
        validate_base(state, &link.plan)?;
        if link.child.rebuild_link.is_some()
            || link.child.rebuild_trust.is_some()
            || link.child.scope != link.plan.successor_scope
            || link.child.client_public_key != link.plan.successor_client_public_key
            || link.child.anchor_seed != state.anchor_seed
        {
            return Err(denied());
        }
        link.child.validate()?;
    }
    Ok(())
}

fn validate_base(state: &authority::State, plan: &Plan) -> Result<(), AnchorError> {
    plan.validate()?;
    if state.scope != plan.old_scope
        || state.head != plan.old_head
        || state.revision.to_string() != plan.old_revision
        || !state
            .active
            .as_ref()
            .is_some_and(|active| active.txn == plan.old_txn && active.base == plan.old_head)
        || public_key(&decode_hex(&state.anchor_seed)?) != plan.anchor_public_key
        || state.rebuild_trust.as_ref() != Some(&plan.trust)
        || state.client_public_key == plan.successor_client_public_key
    {
        return Err(denied());
    }
    Ok(())
}

pub(in crate::rollback_anchor) fn apply(
    state: &mut authority::State,
    plan: Plan,
    approval: &Signed,
    client_proof: &Signed,
    challenge: &str,
    action: Action,
) -> Result<(Signed, bool), AnchorError> {
    validate_base(state, &plan)?;
    verify_approval(&plan, approval)?;
    verify_client(
        &plan,
        challenge,
        action,
        client_proof,
        &state.client_public_key,
    )?;
    if state
        .rebuild_link
        .as_ref()
        .is_some_and(|link| link.plan != plan)
    {
        return Err(denied());
    }
    let (status, changed) = match action {
        Action::Link if state.rebuild_link.is_none() => {
            state.rebuild_link = Some(Link {
                child: Box::new(authority::State {
                    protocol_version: crate::rollback_anchor::PROTOCOL.to_owned(),
                    scope: plan.successor_scope.clone(),
                    client_public_key: plan.successor_client_public_key.clone(),
                    anchor_seed: state.anchor_seed.clone(),
                    head: plan.successor_head.clone(),
                    revision: 0,
                    active: None,
                    last: None,
                    rebuild_trust: None,
                    rebuild_link: None,
                }),
                plan: plan.clone(),
                cancelled: false,
            });
            (Status::Linked, true)
        }
        Action::Link => (Status::Duplicate, false),
        Action::Cancel => {
            let link = state.rebuild_link.as_mut().ok_or_else(denied)?;
            let changed = !link.cancelled;
            link.cancelled = true;
            (Status::Cancelled, changed)
        }
        Action::Inspect => (
            match &state.rebuild_link {
                None => Status::Unlinked,
                Some(link) if link.cancelled => Status::Cancelled,
                Some(_) => Status::Linked,
            },
            false,
        ),
    };
    let link = state.rebuild_link.as_ref();
    let response = Response {
        protocol_version: PROTOCOL.to_owned(),
        plan_sha256: plan.digest()?,
        request_sha256: request_digest(client_proof)?,
        challenge: challenge.to_owned(),
        action,
        status,
        old_scope: state.scope.clone(),
        old_head: state.head.clone(),
        old_txn: plan.old_txn,
        old_revision: state.revision.to_string(),
        successor_scope: plan.successor_scope.clone(),
        successor_head: link.map_or_else(
            || plan.successor_head.clone(),
            |link| link.child.head.clone(),
        ),
        successor_revision: link
            .map_or_else(|| "0".to_owned(), |link| link.child.revision.to_string()),
        cancelled: link.is_some_and(|link| link.cancelled),
    };
    Ok((
        sign(&response, &decode_hex(&state.anchor_seed)?, RESULT_DOMAIN)?,
        changed,
    ))
}
