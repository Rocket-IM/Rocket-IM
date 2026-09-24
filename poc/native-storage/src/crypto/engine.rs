//! 每个实例是一份临时候选；只有外部预约和共同提交协议能够赋予持久执行许可。
#[path = "engine_messages.rs"]
mod messages;
#[path = "engine_rebuild.rs"]
mod rebuild;
#[path = "engine_snapshot.rs"]
mod snapshot;

use openmls::prelude::{tls_codec::Deserialize as _, tls_codec::Serialize as _, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use super::contract::{validate_id, Scope};
use super::model::{self, decode, encode, failed, require, Identity, MAX_PROTOCOL_BYTES};
use crate::model::Error as ApiError;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub(crate) struct Engine {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    own: Identity,
    conversation: Option<String>,
    peer: Option<Identity>,
    // 仅重建加入启用精确三成员；旧双成员快照不增加该字段。
    rebuild_members: Option<Vec<Identity>>,
    usable: bool,
}

impl Engine {
    pub(crate) fn new(scope: &Scope) -> Result<Self, ApiError> {
        validate_id(&scope.service)?;
        validate_id(&scope.account)?;
        validate_id(&scope.device)?;
        let provider = OpenMlsRustCrypto::default();
        let signer = failed(SignatureKeyPair::new(SUITE.signature_algorithm()))?;
        failed(signer.store(provider.storage()))?;
        let mut own = Identity {
            service: scope.service.clone(),
            account: scope.account.clone(),
            device: scope.device.clone(),
            identity_key: encode(signer.public()),
            key_package: String::new(),
        };
        let package = failed(KeyPackage::builder().build(
            SUITE,
            &provider,
            &signer,
            credential_with_key(&own)?,
        ))?;
        let bytes = failed(package.key_package().tls_serialize_detached())?;
        protocol_size(&bytes)?;
        own.key_package = encode(&bytes);
        Ok(Self {
            provider,
            signer,
            own,
            conversation: None,
            peer: None,
            rebuild_members: None,
            usable: true,
        })
    }

    pub(crate) fn identity(&self) -> Identity {
        self.own.clone()
    }

    pub(crate) fn conversation(&self) -> Option<String> {
        self.conversation.clone()
    }

    fn available(&self) -> Result<(), ApiError> {
        require(self.usable, "crypto_paused")
    }

    // 仅防止同一候选被误复用；跨协调线程或进程的未决操作由 SQL 层持久预约阻断。
    fn mutate<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        self.available()?;
        self.usable = false;
        let result = action(self);
        if result.is_ok() {
            self.usable = true;
        }
        result
    }

    pub(crate) fn create_group(
        &mut self,
        conversation: &str,
        peer: &Identity,
    ) -> Result<String, ApiError> {
        self.available()?;
        require(self.conversation.is_none(), "crypto_already_grouped")?;
        validate_id(conversation)?;
        self.validate_peer(peer)?;
        let bytes = decode(&peer.key_package)?;
        let package = failed(KeyPackageIn::tls_deserialize_exact(&bytes))?;
        let package = failed(package.validate(self.provider.crypto(), ProtocolVersion::Mls10))?;
        require(
            package.ciphersuite() == SUITE
                && package.leaf_node().credential() == &credential(peer)
                && package.leaf_node().signature_key().as_slice() == decode(&peer.identity_key)?,
            "crypto_identity_mismatch",
        )?;
        self.mutate(|candidate| {
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(SUITE)
                .use_ratchet_tree_extension(true)
                .build();
            let mut group = failed(MlsGroup::new_with_group_id(
                &candidate.provider,
                &candidate.signer,
                &config,
                GroupId::from_slice(&group_id(&candidate.own.service, conversation)),
                credential_with_key(&candidate.own)?,
            ))?;
            let (_, welcome, _) =
                failed(group.add_members(&candidate.provider, &candidate.signer, &[package]))?;
            failed(group.merge_pending_commit(&candidate.provider))?;
            validate_members(group.members(), &candidate.own, peer)?;
            let bytes = failed(welcome.to_bytes())?;
            protocol_size(&bytes)?;
            candidate.conversation = Some(conversation.into());
            candidate.peer = Some(peer.clone());
            candidate.own.key_package.clear();
            Ok(encode(&bytes))
        })
    }

    pub(crate) fn join_group(
        &mut self,
        conversation: &str,
        peer: &Identity,
        welcome: &str,
    ) -> Result<(), ApiError> {
        self.available()?;
        require(self.conversation.is_none(), "crypto_already_grouped")?;
        validate_id(conversation)?;
        self.validate_peer(peer)?;
        let bytes = decode(welcome)?;
        let message = failed(MlsMessageIn::tls_deserialize_exact(&bytes))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(ApiError::new("invalid_crypto_input", false));
        };
        self.mutate(|candidate| {
            let staged = failed(StagedWelcome::new_from_welcome(
                &candidate.provider,
                &MlsGroupJoinConfig::default(),
                welcome,
                None,
            ))?;
            require(
                staged.group_context().group_id().as_slice()
                    == group_id(&candidate.own.service, conversation),
                "crypto_scope_mismatch",
            )?;
            let sender = failed(staged.welcome_sender())?;
            require(
                sender.credential() == &credential(peer)
                    && sender.signature_key().as_slice() == decode(&peer.identity_key)?,
                "crypto_identity_mismatch",
            )?;
            validate_members(staged.members(), &candidate.own, peer)?;
            let group = failed(staged.into_group(&candidate.provider))?;
            require(group.is_active(), "crypto_group_required")?;
            candidate.conversation = Some(conversation.into());
            candidate.peer = Some(peer.clone());
            candidate.own.key_package.clear();
            Ok(())
        })
    }

    fn validate_peer(&self, peer: &Identity) -> Result<(), ApiError> {
        validate_id(&peer.service)?;
        validate_id(&peer.account)?;
        validate_id(&peer.device)?;
        require(
            peer.service == self.own.service
                && peer.account != self.own.account
                && decode(&peer.identity_key)?.len() == 32
                && peer.identity_key != self.own.identity_key,
            "crypto_identity_mismatch",
        )
    }

    fn group(&self) -> Result<MlsGroup, ApiError> {
        let conversation = self.conversation.as_ref().ok_or_else(model::corrupt)?;
        let peer = self.peer.as_ref().ok_or_else(model::corrupt)?;
        let group = failed(MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(&group_id(&self.own.service, conversation)),
        ))?
        .ok_or_else(model::corrupt)?;
        require(
            group.is_active() && group.ciphersuite() == SUITE,
            "crypto_state_corrupt",
        )?;
        if let Some(members) = &self.rebuild_members {
            require(
                members.iter().any(|member| {
                    member.service == peer.service
                        && member.account == peer.account
                        && member.device == peer.device
                        && member.identity_key == peer.identity_key
                }),
                "crypto_identity_mismatch",
            )?;
            self.validate_rebuild_members(group.members(), members)?;
        } else {
            validate_members(group.members(), &self.own, peer)?;
        }
        Ok(group)
    }
}

fn encoded_fields(domain: &[u8], fields: &[&str]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u16).to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes
}

fn credential(identity: &Identity) -> Credential {
    BasicCredential::new(encoded_fields(
        b"Rocket-IM/native-crypto/identity/v1\0",
        &[&identity.service, &identity.account, &identity.device],
    ))
    .into()
}

fn credential_with_key(identity: &Identity) -> Result<CredentialWithKey, ApiError> {
    Ok(CredentialWithKey {
        credential: credential(identity),
        signature_key: decode(&identity.identity_key)?.into(),
    })
}

fn group_id(service: &str, conversation: &str) -> Vec<u8> {
    encoded_fields(
        b"Rocket-IM/native-crypto/group/v1\0",
        &[service, conversation],
    )
}

fn validate_members(
    actual: impl Iterator<Item = Member>,
    own: &Identity,
    peer: &Identity,
) -> Result<(), ApiError> {
    let own_key = decode(&own.identity_key)?;
    let peer_key = decode(&peer.identity_key)?;
    let members: Vec<_> = actual.collect();
    require(
        members.len() == 2
            && members
                .iter()
                .filter(|member| {
                    member.credential == credential(own) && member.signature_key == own_key
                })
                .count()
                == 1
            && members
                .iter()
                .filter(|member| {
                    member.credential == credential(peer) && member.signature_key == peer_key
                })
                .count()
                == 1,
        "crypto_identity_mismatch",
    )
}

fn protocol_size(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.is_empty() || bytes.len() > MAX_PROTOCOL_BYTES {
        return Err(model::limit());
    }
    Ok(())
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "engine_rebuild_tests.rs"]
mod rebuild_tests;
