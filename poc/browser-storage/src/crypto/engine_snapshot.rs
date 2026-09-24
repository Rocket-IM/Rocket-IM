//! 完整 provider 快照仅作为 Rust 内部 BLOB，由外层和消息结果共同提交。
use super::{credential, group_id, Engine, SUITE};
use openmls::prelude::{tls_codec::Deserialize as _, KeyPackageIn, ProtocolVersion};
use openmls_basic_credential::{SignatureKeyPair, StorageId};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{storage::StorageProvider, OpenMlsProvider};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::model::{self, decode, failed, require, Identity, MAX_ENTRIES, MAX_STATE_BYTES},
    protocol::{validate_id, ApiError, Scope},
};

const FORMAT: &str = "Rocket-IM/browser-crypto/state/v1";
const OPENMLS_VERSION: &str = "0.9.0";
const PROVIDER_VERSION: &str = "0.6.0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedState {
    format: String,
    openmls_version: String,
    provider_version: String,
    own: Identity,
    signature_id: StorageId,
    conversation: Option<String>,
    group_id: Option<Vec<u8>>,
    peer: Option<Identity>,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Engine {
    pub(in crate::crypto) fn export(&self) -> Result<Vec<u8>, ApiError> {
        self.available()?;
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| model::corrupt())?;
        if values.len() > MAX_ENTRIES {
            return Err(model::limit());
        }
        let mut entries: Vec<_> = values
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        drop(values);
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let state = SavedState {
            format: FORMAT.into(),
            openmls_version: OPENMLS_VERSION.into(),
            provider_version: PROVIDER_VERSION.into(),
            own: self.own.clone(),
            signature_id: self.signer.id(),
            conversation: self.conversation.clone(),
            group_id: self
                .conversation
                .as_ref()
                .map(|conversation| group_id(&self.own.service, conversation)),
            peer: self.peer.clone(),
            entries,
        };
        let encoded = failed(serde_json::to_vec(&state))?;
        if encoded.len() > MAX_STATE_BYTES {
            return Err(model::limit());
        }
        Ok(encoded)
    }

    pub(in crate::crypto) fn restore(bytes: &[u8], scope: &Scope) -> Result<Self, ApiError> {
        if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
            return Err(model::limit());
        }
        let state: SavedState = serde_json::from_slice(bytes).map_err(|_| model::corrupt())?;
        require(
            state.format == FORMAT
                && state.openmls_version == OPENMLS_VERSION
                && state.provider_version == PROVIDER_VERSION
                && state.own.service == scope.service
                && state.own.account == scope.account
                && state.own.device == scope.device
                && !state.entries.is_empty()
                && state.entries.len() <= MAX_ENTRIES,
            "crypto_state_corrupt",
        )?;
        validate_id(&state.own.service)?;
        validate_id(&state.own.account)?;
        let public = decode(&state.own.identity_key)?;
        require(public.len() == 32, "crypto_state_corrupt")?;
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| model::corrupt())?;
            let mut previous: Option<&[u8]> = None;
            for (key, value) in &state.entries {
                require(
                    !key.is_empty() && previous.is_none_or(|last| last < key.as_slice()),
                    "crypto_state_corrupt",
                )?;
                values.insert(key.clone(), value.clone());
                previous = Some(key);
            }
        }
        let signer: SignatureKeyPair =
            failed(provider.storage().signature_key_pair(&state.signature_id))?
                .ok_or_else(model::corrupt)?;
        require(
            signer.public() == public && signer.signature_scheme() == SUITE.signature_algorithm(),
            "crypto_state_corrupt",
        )?;
        let engine = Self {
            provider,
            signer,
            own: state.own,
            conversation: state.conversation,
            peer: state.peer,
            usable: true,
        };
        match (&engine.conversation, &engine.peer, state.group_id) {
            (Some(conversation), Some(peer), Some(saved_id)) => {
                validate_id(conversation)?;
                engine.validate_peer(peer)?;
                require(
                    saved_id == group_id(&engine.own.service, conversation)
                        && engine.own.key_package.is_empty(),
                    "crypto_state_corrupt",
                )?;
                engine.group()?;
            }
            (None, None, None) => {
                let bytes = decode(&engine.own.key_package)?;
                let package = failed(KeyPackageIn::tls_deserialize_exact(&bytes))?;
                let package =
                    failed(package.validate(engine.provider.crypto(), ProtocolVersion::Mls10))?;
                require(
                    package.ciphersuite() == SUITE
                        && package.leaf_node().credential() == &credential(&engine.own)
                        && package.leaf_node().signature_key().as_slice() == public,
                    "crypto_state_corrupt",
                )?;
            }
            _ => return Err(model::corrupt()),
        }
        Ok(engine)
    }
}
