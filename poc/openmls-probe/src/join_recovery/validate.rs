//! 结构限制与公共授权；期限在首次使用的提交边界另行核验。
use super::*;
use crate::permission::{types as scalar, PermissionCheckpoint, PermissionError};

impl Scope {
    pub fn validate(&self) -> Result<(), PermissionError> {
        scalar::id(&self.service_id)?;
        scalar::id(&self.conversation_id)?;
        scalar::bytes(&self.group_id, 256)?;
        Ok(())
    }
}
impl AdmissionRef {
    pub fn validate(&self) -> Result<(), PermissionError> {
        scalar::id(&self.change_id)?;
        scalar::hash(&self.record_sha256)
    }
}
impl Floor {
    pub fn validate(&self) -> Result<(), PermissionError> {
        scalar::decimal(&self.authorization_version)?;
        scalar::hash(&self.crypto_state_ref)
    }
}
pub(super) fn interval(start: &str, end: &str) -> Result<(), PermissionError> {
    require(
        scalar::decimal(end)?
            .checked_sub(scalar::decimal(start)?)
            .is_some_and(|n| (1..=300).contains(&n)),
        "recovery_invalid",
    )
}
impl Request {
    pub fn validate(&self) -> Result<(), PermissionError> {
        self.domain()?;
        self.scope().validate()?;
        scalar::id(self.id())?;
        scalar::hash(self.nonce())?;
        crate::key_package::member(self.signer())?;
        match self {
            Self::Intent(i) => {
                require(
                    i.signer.identity() != i.actor.identity()
                        && i.signer.signature_key != i.actor.signature_key
                        && i.history_policy == "from_recovery",
                    "recovery_invalid",
                )?;
                scalar::id(&i.change_id)?;
                i.root_admission.validate()?;
                i.current_admission.validate()?;
                crate::key_package::member(&i.actor)?;
                i.predecessor.validate()?;
                i.known_floor.validate()?;
                require(
                    i.known_floor == i.predecessor,
                    "recovery_predecessor_changed",
                )?;
                scalar::hash(&i.key_package_sha256)?;
                interval(&i.issued_at_unix_secs, &i.expires_at_unix_secs)?;
                let mut accounts = vec![i.signer.account_id.as_str(), i.actor.account_id.as_str()];
                accounts.sort();
                accounts.dedup();
                require(
                    if i.policy_ref.is_none() {
                        i.directory_refs
                            .iter()
                            .map(|d| d.account_id.as_str())
                            .collect::<Vec<_>>()
                            == accounts
                    } else {
                        let actual: Vec<_> = i
                            .directory_refs
                            .iter()
                            .map(|d| d.account_id.as_str())
                            .collect();
                        actual.len() <= 3
                            && actual.windows(2).all(|w| w[0] < w[1])
                            && accounts.iter().all(|a| actual.contains(a))
                    },
                    "recovery_invalid",
                )?;
                for d in &i.directory_refs {
                    scalar::id(&d.account_id)?;
                    require(scalar::decimal(&d.version)? > 0, "recovery_invalid")?;
                    scalar::hash(&d.sha256)?;
                }
            }
            Self::Control(c) => {
                require(
                    (c.kind == ControlKind::Close) == c.reason.is_some(),
                    "recovery_invalid",
                )?;
                scalar::id(&c.recovery_id)?;
                scalar::id(&c.change_id)?;
                scalar::hash(&c.intent_sha256)?;
            }
        }
        Ok(())
    }
}
impl Statement {
    pub fn validate(&self) -> Result<(), PermissionError> {
        self.domain()?;
        self.scope.validate()?;
        scalar::id(&self.change_id)?;
        crate::key_package::member(&self.actor)?;
        for n in [
            &self.previous_authorization_version,
            &self.authorization_version,
            &self.action.previous_epoch,
        ] {
            scalar::decimal(n)?;
        }
        require(
            scalar::decimal(&self.action.old_leaf_index)? <= u32::MAX.into(),
            "recovery_invalid",
        )?;
        for h in [
            &self.from_state_ref,
            &self.to_state_ref,
            &self.commit_sha256,
            &self.nonce,
            &self.action.intent_sha256,
            &self.action.allocation_sha256,
            &self.action.key_package_sha256,
            &self.action.welcome_sha256,
            &self.action.old_leaf_sha256,
        ] {
            scalar::hash(h)?;
        }
        self.action.root_admission.validate()?;
        self.action.current_admission.validate()?;
        scalar::id(&self.action.recovery_id)?;
        crate::key_package::member(&self.action.target)?;
        let key_ref = scalar::bytes(&self.action.key_package_ref, 32)?;
        require(
            self.policy_ref.is_none() || key_ref.len() == 32,
            "recovery_invalid",
        )?;
        require(
            self.action.history_policy == "from_recovery",
            "recovery_invalid",
        )?;
        interval(&self.issued_at_unix_secs, &self.expires_at_unix_secs)
    }
}
impl Receipt {
    pub fn validate(&self) -> Result<(), PermissionError> {
        self.domain()?;
        self.scope.validate()?;
        scalar::id(&self.recovery_id)?;
        scalar::id(&self.change_id)?;
        self.root_admission.validate()?;
        self.current_admission.validate()?;
        crate::key_package::member(&self.target)?;
        crate::key_package::member(&self.actor)?;
        scalar::hash(&self.intent_sha256)?;
        match &self.result {
            ResultBody::Allocated {
                claim_sha256,
                key_package_sha256,
                key_package_ref,
                predecessor,
            } => {
                scalar::hash(claim_sha256)?;
                scalar::hash(key_package_sha256)?;
                let key_ref = scalar::bytes(key_package_ref, 32)?;
                require(
                    self.policy_ref.is_none() || key_ref.len() == 32,
                    "recovery_invalid",
                )?;
                predecessor.validate()?;
            }
            ResultBody::Accepted {
                allocation_sha256,
                candidate_sha256,
                checkpoint,
            } => {
                scalar::hash(allocation_sha256)?;
                scalar::hash(candidate_sha256)?;
                self.check_checkpoint(checkpoint)?;
            }
            ResultBody::Closed {
                close_sha256,
                checkpoint,
                allocation_sha256,
                ..
            } => {
                scalar::hash(close_sha256)?;
                self.check_checkpoint(checkpoint)?;
                if let Some(hash) = allocation_sha256 {
                    scalar::hash(hash)?;
                }
            }
        }
        Ok(())
    }
    fn check_checkpoint(&self, cp: &PermissionCheckpoint) -> Result<(), PermissionError> {
        cp.validate()?;
        require(
            cp.service_id == self.scope.service_id
                && cp.conversation_id == self.scope.conversation_id,
            "recovery_invalid",
        )
    }
}
pub fn authorize(
    cp: &PermissionCheckpoint,
    intent: &Intent,
    root_device: bool,
) -> Result<(), PermissionError> {
    cp.validate()?;
    require(
        cp.service_id == intent.scope.service_id
            && cp.conversation_id == intent.scope.conversation_id
            && cp.members.contains(&intent.signer)
            && cp.members.contains(&intent.actor)
            && if root_device {
                intent.actor.account_id == intent.signer.account_id
            } else {
                intent.actor.account_id == cp.owner_account_id
            },
        "permission_denied",
    )
}
