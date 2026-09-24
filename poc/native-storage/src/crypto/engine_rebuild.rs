//! 重建只新增同账号独立设备；批准和实际 MLS Add 结果由同一个持久候选提交。
use super::*;
use crate::crypto::{
    anchor::{
        protocol::Signed,
        rebuild_protocol::{self, AddAdmission, Checkpoint, Member as CheckpointMember, Plan},
    },
    model::Envelope,
};
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Added {
    approval: Signed,
    admission: Signed,
    welcome: String,
    commit: String,
    checkpoint: Value,
}

impl Engine {
    pub(crate) fn group_id(&self) -> Result<String, ApiError> {
        self.available()?;
        Ok(encode(self.group()?.group_id().as_slice()))
    }

    /// 只公布带领域的公共 GroupContext 摘要，不导出 MLS exporter 秘密。
    pub(crate) fn checkpoint(&self) -> Result<Value, ApiError> {
        self.available()?;
        let group = self.group()?;
        self.checkpoint_for_group(&group)
    }

    fn checkpoint_for_group(&self, group: &MlsGroup) -> Result<Value, ApiError> {
        let mut bytes = b"Rocket-IM/native-rebuild/MLS-GroupContext/v1\0".to_vec();
        bytes.extend(failed(
            group
                .public_group()
                .group_context()
                .tls_serialize_detached(),
        )?);
        let mut members: Vec<_> = self
            .identities()?
            .iter()
            .map(CheckpointMember::from_identity)
            .collect();
        members.sort_by(|left, right| {
            (&left.account_id, &left.device_id).cmp(&(&right.account_id, &right.device_id))
        });
        let checkpoint = Checkpoint {
            service_id: self.own.service.clone(),
            conversation_id: self.conversation.clone().ok_or_else(model::corrupt)?,
            authorization_version: group.epoch().as_u64().to_string(),
            crypto_state_ref: model::hash(&bytes),
            owner_account_id: self.own.account.clone(),
            members,
        };
        checkpoint.validate()?;
        failed(serde_json::to_value(checkpoint))
    }

    pub(crate) fn validate_rebuild_plan(raw: &Value, peer: &Identity) -> Result<(), ApiError> {
        let plan: Plan = failed(serde_json::from_value(raw.clone()))?;
        plan.validate()?;
        for id in [&peer.service, &peer.account, &peer.device] {
            validate_id(id)?;
        }
        require(
            peer.service == plan.successor_scope.service
                && peer.account == plan.successor_scope.account
                && peer.device == plan.successor_scope.device
                && crate::crypto::anchor::protocol::encode_hex(&decode(&peer.identity_key)?)
                    == plan.successor_scope.identity_key
                && model::hash(&decode(&peer.key_package)?) == plan.key_package_sha256,
            "anchor_rebuild_denied",
        )
    }

    pub(crate) fn approve_plan(&self, raw: &Value) -> Result<Signed, ApiError> {
        self.available()?;
        let plan: Plan = failed(serde_json::from_value(raw.clone()))?;
        plan.validate()?;
        require(
            self.rebuild_members.is_none()
                && self.checkpoint()? == failed(serde_json::to_value(&plan.trust.checkpoint))?
                && plan.trust.authorizer == CheckpointMember::from_identity(&self.own)
                && plan.successor_scope.account == self.own.account
                && plan.successor_scope.device != self.own.device,
            "anchor_rebuild_denied",
        )?;
        self.sign_statement(&plan, &rebuild_protocol::approval_signing_bytes(&plan)?)
    }

    pub(crate) fn add_rebuild_member(
        &mut self,
        peer: &Identity,
        raw: &Value,
    ) -> Result<Value, ApiError> {
        Self::validate_rebuild_plan(raw, peer)?;
        let plan: Plan = failed(serde_json::from_value(raw.clone()))?;
        let approval = self.approve_plan(raw)?;
        self.validate_rebuild_peer(peer)?;
        require(peer.account == self.own.account, "anchor_rebuild_denied")?;
        let package = failed(KeyPackageIn::tls_deserialize_exact(&decode(
            &peer.key_package,
        )?))?;
        let package = failed(package.validate(self.provider.crypto(), ProtocolVersion::Mls10))?;
        require(
            package.ciphersuite() == SUITE
                && package.leaf_node().credential() == &credential(peer)
                && package.leaf_node().signature_key().as_slice() == decode(&peer.identity_key)?,
            "crypto_identity_mismatch",
        )?;
        let mut members = self.identities()?;
        members.push(peer.clone());
        for member in &mut members {
            member.key_package.clear();
        }
        members.sort_by(|left, right| {
            (&left.account, &left.device).cmp(&(&right.account, &right.device))
        });
        self.mutate(|candidate| {
            let mut group = candidate.group()?;
            let (commit, welcome, _) =
                failed(group.add_members(&candidate.provider, &candidate.signer, &[package]))?;
            failed(group.merge_pending_commit(&candidate.provider))?;
            candidate.validate_rebuild_members(group.members(), &members)?;
            let welcome = failed(welcome.to_bytes())?;
            let commit = failed(commit.to_bytes())?;
            protocol_size(&welcome)?;
            protocol_size(&commit)?;
            candidate.rebuild_members = Some(members);
            let checkpoint = candidate.checkpoint_for_group(&group)?;
            let admission = AddAdmission {
                plan_sha256: plan.digest()?,
                checkpoint_before: plan.trust.checkpoint.clone(),
                checkpoint_after: failed(serde_json::from_value(checkpoint.clone()))?,
                successor_identity: peer.clone(),
                welcome_sha256: model::hash(&welcome),
                commit_sha256: model::hash(&commit),
                group_id: encode(group.group_id().as_slice()),
                history_policy: "from_join".into(),
                approver: CheckpointMember::from_identity(&candidate.own),
            };
            let admission = candidate.sign_statement(
                &admission,
                &rebuild_protocol::admission_signing_bytes(&admission, &plan)?,
            )?;
            failed(serde_json::to_value(Added {
                approval,
                admission,
                welcome: encode(&welcome),
                commit: encode(&commit),
                checkpoint,
            }))
        })
    }

    /// members 包含新设备自己；coordinator 还须核验签名 AddAdmission 与加入后的 checkpoint。
    pub(crate) fn join_rebuild(
        &mut self,
        conversation: &str,
        members: &[Identity],
        authorizer: &Identity,
        welcome: &str,
    ) -> Result<(), ApiError> {
        self.available()?;
        require(self.conversation.is_none(), "crypto_already_grouped")?;
        validate_id(conversation)?;
        self.validate_rebuild_peer(authorizer)?;
        require(
            authorizer.account == self.own.account,
            "anchor_rebuild_denied",
        )?;
        require(
            members
                .iter()
                .any(|member| same_identity(member, authorizer))
                && members.iter().any(|member| member == &self.own),
            "crypto_identity_mismatch",
        )?;
        let message = failed(MlsMessageIn::tls_deserialize_exact(&decode(welcome)?))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(ApiError::new("invalid_crypto_input", false));
        };
        self.mutate(|candidate| {
            let processed = failed(ProcessedWelcome::new_from_welcome(
                &candidate.provider,
                &MlsGroupJoinConfig::default(),
                welcome,
            ))?;
            let actual_package = processed.own_key_package().ok_or_else(model::corrupt)?;
            require(
                failed(actual_package.tls_serialize_detached())?
                    == decode(&candidate.own.key_package)?,
                "crypto_identity_mismatch",
            )?;
            let staged = failed(processed.into_staged_welcome(&candidate.provider, None))?;
            require(
                staged.group_context().group_id().as_slice()
                    == group_id(&candidate.own.service, conversation),
                "crypto_scope_mismatch",
            )?;
            let sender = failed(staged.welcome_sender())?;
            require(
                sender.credential() == &credential(authorizer)
                    && sender.signature_key().as_slice() == decode(&authorizer.identity_key)?,
                "crypto_identity_mismatch",
            )?;
            candidate.validate_rebuild_members(staged.members(), members)?;
            let group = failed(staged.into_group(&candidate.provider))?;
            require(group.is_active(), "crypto_group_required")?;
            let mut saved = members.to_vec();
            for member in &mut saved {
                member.key_package.clear();
            }
            saved.sort_by(|left, right| {
                (&left.account, &left.device).cmp(&(&right.account, &right.device))
            });
            candidate.conversation = Some(conversation.into());
            candidate.peer = Some(authorizer.clone());
            candidate.rebuild_members = Some(saved);
            candidate.own.key_package.clear();
            Ok(())
        })
    }

    pub(crate) fn validate_rebuild_result(raw: &Value) -> Result<(Plan, AddAdmission), ApiError> {
        let added: Added = failed(serde_json::from_value(raw.clone()))?;
        let plan: Plan = failed(serde_json::from_slice(&decode(
            &added.approval.statement_bytes,
        )?))?;
        rebuild_protocol::verify_approval(&plan, &added.approval)?;
        let admission = rebuild_protocol::verify_admission(&plan, &added.admission)?;
        require(
            model::hash(&decode(&added.welcome)?) == admission.welcome_sha256
                && model::hash(&decode(&added.commit)?) == admission.commit_sha256
                && added.checkpoint == failed(serde_json::to_value(&admission.checkpoint_after))?,
            "anchor_rebuild_denied",
        )?;
        Ok((plan, admission))
    }

    fn sign_statement(&self, statement: &impl Serialize, bytes: &[u8]) -> Result<Signed, ApiError> {
        Ok(Signed {
            statement_bytes: encode(&failed(serde_json::to_vec(statement))?),
            signature_bytes: encode(&failed(self.signer.sign(bytes))?),
        })
    }

    fn identities(&self) -> Result<Vec<Identity>, ApiError> {
        Ok(self.rebuild_members.clone().unwrap_or(vec![
            self.own.clone(),
            self.peer.clone().ok_or_else(model::corrupt)?,
        ]))
    }

    pub(super) fn validate_rebuild_peer(&self, peer: &Identity) -> Result<(), ApiError> {
        for id in [&peer.service, &peer.account, &peer.device] {
            validate_id(id)?;
        }
        require(
            peer.service == self.own.service
                && (peer.account != self.own.account || peer.device != self.own.device)
                && decode(&peer.identity_key)?.len() == 32
                && peer.identity_key != self.own.identity_key,
            "crypto_identity_mismatch",
        )
    }

    pub(super) fn validate_rebuild_members(
        &self,
        actual: impl Iterator<Item = Member>,
        expected: &[Identity],
    ) -> Result<(), ApiError> {
        let actual: Vec<_> = actual.collect();
        let mut identities = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeSet::new();
        require(
            expected.len() == 3
                && actual.len() == 3
                && expected
                    .iter()
                    .filter(|member| same_identity(member, &self.own))
                    .count()
                    == 1,
            "crypto_identity_mismatch",
        )?;
        for member in expected {
            for id in [&member.service, &member.account, &member.device] {
                validate_id(id)?;
            }
            let key = decode(&member.identity_key)?;
            require(
                member.service == self.own.service
                    && key.len() == 32
                    && identities.insert((&member.account, &member.device))
                    && keys.insert(key.clone())
                    && actual
                        .iter()
                        .filter(|actual| {
                            actual.credential == credential(member) && actual.signature_key == key
                        })
                        .count()
                        == 1,
                "crypto_identity_mismatch",
            )?;
        }
        require(
            expected
                .iter()
                .filter(|member| member.account == self.own.account)
                .count()
                == 2,
            "crypto_identity_mismatch",
        )
    }

    pub(super) fn message_peer(&self, envelope: &Envelope) -> Result<&Identity, ApiError> {
        if let Some(members) = &self.rebuild_members {
            members
                .iter()
                .find(|member| {
                    member.account == envelope.sender_account
                        && member.device == envelope.sender_device
                        && !same_identity(member, &self.own)
                })
                .ok_or_else(|| ApiError::new("crypto_scope_mismatch", true))
        } else {
            self.peer.as_ref().ok_or_else(model::corrupt)
        }
    }
}

fn same_identity(left: &Identity, right: &Identity) -> bool {
    left.service == right.service
        && left.account == right.account
        && left.device == right.device
        && left.identity_key == right.identity_key
}
