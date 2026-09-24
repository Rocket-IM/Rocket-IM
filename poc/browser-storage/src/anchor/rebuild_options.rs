//! 后继物理空间与可信输入；不把认证 seed 写入控制表。
use super::{
    client::{Client, Config},
    error,
    protocol::{self, Scope},
    rebuild_protocol::Plan,
};
use crate::{crypto::model::Identity, protocol::ApiError};
use ed25519_dalek::{SigningKey, VerifyingKey};
use js_sys::Function;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Options {
    pub service: String,
    pub account: String,
    pub device: String,
    pub storage_namespace: String,
    pub endpoint: String,
    pub anchor_public_key: String,
    pub approver_public_key: String,
    pub client_seed: String,
    #[serde(default)]
    pub initial_fault: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Offer {
    pub scope: Scope,
    pub head: String,
    pub identity: Identity,
    pub client_public_key: String,
    pub storage_namespace: String,
}

impl Options {
    pub(super) fn parse(text: &str) -> Result<Self, ApiError> {
        if text.len() > 8192 {
            return Err(error("rebuild_config"));
        }
        let options: Self = serde_json::from_str(text).map_err(|_| error("rebuild_config"))?;
        options.storage_scope()?;
        for value in [&options.anchor_public_key, &options.approver_public_key] {
            let key = VerifyingKey::from_bytes(&protocol::decode_hex(value)?)
                .map_err(|_| error("rebuild_config"))?;
            if key.is_weak() {
                return Err(error("rebuild_config"));
            }
        }
        options.key()?;
        if options.initial_fault.as_deref().is_some_and(|value| {
            !matches!(
                value,
                "after_crypto" | "after_sql" | "refuse_commit" | "reserve_refuse" | "after_commit"
            )
        }) {
            return Err(error("rebuild_config"));
        }
        super::client::validate_endpoint(&options.endpoint)?;
        Ok(options)
    }
    pub(super) fn storage_scope(&self) -> Result<crate::protocol::Scope, ApiError> {
        crate::protocol::Scope::rebuilt(
            self.service.clone(),
            self.account.clone(),
            self.device.clone(),
            self.storage_namespace.clone(),
        )
    }
    pub(super) fn key(&self) -> Result<SigningKey, ApiError> {
        Ok(SigningKey::from_bytes(&protocol::decode_hex(
            &self.client_seed,
        )?))
    }
    pub(super) fn public_key(&self) -> Result<String, ApiError> {
        Ok(protocol::encode_hex(self.key()?.verifying_key().as_bytes()))
    }
    pub(super) fn binding(&self) -> Result<String, ApiError> {
        Ok(protocol::hash_bytes(
            &serde_json::to_vec(&(
                "Rocket-IM/browser-rebuild-context/v1",
                &self.service,
                &self.account,
                &self.device,
                &self.storage_namespace,
                &self.endpoint,
                &self.anchor_public_key,
                &self.approver_public_key,
                self.public_key()?,
            ))
            .map_err(|_| error("rebuild_config"))?,
        ))
    }
    fn scope(&self, identity_key: String) -> Scope {
        Scope {
            service: self.service.clone(),
            account: self.account.clone(),
            device: self.device.clone(),
            identity_key,
            store_id: self.storage_namespace.clone(),
        }
    }
    fn client_for(&self, identity_key: &str, rpc: Function) -> Result<Client, ApiError> {
        let config = Config {
            endpoint: self.endpoint.clone(),
            scope: self.scope(identity_key.into()),
            anchor_public_key: self.anchor_public_key.clone(),
            client_seed: self.client_seed.clone(),
        };
        Client::new(
            &serde_json::to_string(&config).map_err(|_| error("rebuild_config"))?,
            &self.storage_scope()?,
            rpc,
        )
    }
    pub(super) fn client(&self, offer: &Offer, rpc: Function) -> Result<Client, ApiError> {
        self.validate_offer(offer)?;
        self.client_for(&offer.scope.identity_key, rpc)
    }
    pub(super) fn offer(&self, identity: Identity, head: String) -> Result<Offer, ApiError> {
        use base64::Engine as _;
        let public = base64::engine::general_purpose::STANDARD
            .decode(&identity.identity_key)
            .map_err(|_| error("rebuild_identity"))?;
        let offer = Offer {
            scope: self.scope(protocol::encode_hex(&public)),
            head,
            identity,
            client_public_key: self.public_key()?,
            storage_namespace: self.storage_namespace.clone(),
        };
        self.validate_offer(&offer)?;
        Ok(offer)
    }
    pub(super) fn validate_offer(&self, offer: &Offer) -> Result<(), ApiError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        offer.scope.validate()?;
        protocol::decode_hex(&offer.head)?;
        let public = STANDARD
            .decode(&offer.identity.identity_key)
            .map_err(|_| error("rebuild_identity"))?;
        if public.len() != 32
            || STANDARD.encode(&public) != offer.identity.identity_key
            || offer.scope != self.scope(protocol::encode_hex(&public))
            || offer.identity.service != self.service
            || offer.identity.account != self.account
            || offer.identity.device != self.device
            || offer.storage_namespace != self.storage_namespace
            || offer.client_public_key != self.public_key()?
        {
            return Err(error("rebuild_identity"));
        }
        Ok(())
    }
    pub(super) fn validate_plan(&self, offer: &Offer, plan: &Plan) -> Result<(), ApiError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        plan.validate()?;
        let package = STANDARD
            .decode(&offer.identity.key_package)
            .map_err(|_| error("rebuild_identity"))?;
        if package.is_empty()
            || plan.anchor_public_key != self.anchor_public_key
            || plan.approver_public_key != self.approver_public_key
            || plan.successor_scope != offer.scope
            || plan.successor_head != offer.head
            || plan.successor_client_public_key != offer.client_public_key
            || plan.successor_key_package_sha256 != protocol::hash_bytes(&package)
        {
            return Err(error("rebuild_plan_binding"));
        }
        Ok(())
    }
}
