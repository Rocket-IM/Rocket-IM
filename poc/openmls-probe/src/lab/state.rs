use super::{checked, codec, ensure, Context, LabError, Pin};
use crate::authorization::TrustedRoster;
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use openmls_basic_credential::{SignatureKeyPair, StorageId};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{storage::StorageProvider, OpenMlsProvider};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
pub(super) struct Outbound {
    pub payload_digest: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub epoch: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Inbound {
    pub ciphertext_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub epoch: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ControlRecord {
    pub request_digest: [u8; 32],
    pub result: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeviceState {
    pub version: u32,
    pub context: Context,
    pub provider_entries: Vec<(Vec<u8>, Vec<u8>)>,
    pub own_signature_key: [u8; 32],
    pub signature_id: StorageId,
    pub key_package: Vec<u8>,
    pub group_id: Option<Vec<u8>>,
    pub roster: TrustedRoster,
    pub peer_pins: Vec<Pin>,
    pub outbox: BTreeMap<String, Outbound>,
    pub inbox: BTreeMap<String, Inbound>,
    pub control_outbox: BTreeMap<String, ControlRecord>,
    #[serde(default)]
    pub wire: super::wire_types::WireState,
    // None 不落盘，使未启用的旧快照保持原格式；启用后旧程序必须拒绝未知顶层字段。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_send_order: Option<super::wire_send_order::Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_closures: Option<super::wire_closures::Closures>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_rejections: Option<super::wire_rejections::Rejections>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_reads: Option<super::wire_reads::Reads>,
    #[serde(default)]
    pub wire_sync: super::wire_sync::SyncState,
    #[serde(default)]
    pub permissions: super::permission_state::PermissionState,
    #[serde(default)]
    pub history_transfers: super::history_state::HistoryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuild: Option<crate::rollback_anchor::rebuild::Plan>,
    #[serde(default)]
    pub rebuild_stream: super::rebuild_stream::State,
    #[serde(skip)]
    pub provider: OpenMlsRustCrypto,
}

impl DeviceState {
    pub fn new(context: Context) -> Result<Self, LabError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = checked(
            "identity_generation",
            SignatureKeyPair::new(codec::CIPHERSUITE.signature_algorithm()),
        )?;
        checked("identity_storage", signer.store(provider.storage()))?;
        let public: [u8; 32] = signer
            .public()
            .try_into()
            .map_err(|_| LabError::new("key_length", "签名公钥长度不匹配"))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(checked(
                "identity_encoding",
                serde_json::to_vec(&context),
            )?)
            .into(),
            signature_key: signer.to_public_vec().into(),
        };
        let bundle = checked(
            "key_package_generation",
            KeyPackage::builder().build(codec::CIPHERSUITE, &provider, &signer, credential),
        )?;
        let key_package = checked(
            "key_package_encoding",
            bundle.key_package().tls_serialize_detached(),
        )?;
        let roster = checked(
            "initial_pin",
            TrustedRoster::new(
                context.service.clone(),
                context.account.clone(),
                context.device.clone(),
                public,
            ),
        )?;
        Ok(Self {
            version: 1,
            context,
            provider_entries: Vec::new(),
            own_signature_key: public,
            signature_id: signer.id(),
            key_package,
            group_id: None,
            roster,
            peer_pins: Vec::new(),
            outbox: BTreeMap::new(),
            inbox: BTreeMap::new(),
            control_outbox: BTreeMap::new(),
            wire: super::wire_types::WireState::default(),
            wire_send_order: None,
            wire_closures: None,
            wire_rejections: None,
            wire_reads: None,
            wire_sync: super::wire_sync::SyncState::default(),
            permissions: super::permission_state::PermissionState::default(),
            history_transfers: super::history_state::HistoryState::default(),
            rebuild: None,
            rebuild_stream: Default::default(),
            provider,
        })
    }

    pub fn signer(&self) -> Result<SignatureKeyPair, LabError> {
        let signer: Option<SignatureKeyPair> = checked(
            "signer_storage",
            self.provider
                .storage()
                .signature_key_pair(&self.signature_id),
        )?;
        signer.ok_or_else(|| LabError::new("missing_signer", "快照缺少设备签名状态"))
    }

    pub fn own_credential(&self) -> Result<CredentialWithKey, LabError> {
        Ok(CredentialWithKey {
            credential: BasicCredential::new(checked(
                "identity_encoding",
                serde_json::to_vec(&self.context),
            )?)
            .into(),
            signature_key: self.own_signature_key.to_vec().into(),
        })
    }

    pub fn group(&self) -> Result<MlsGroup, LabError> {
        let id = self
            .group_id
            .as_ref()
            .ok_or_else(|| LabError::new("no_group", "设备尚未入群"))?;
        let group = checked(
            "group_storage",
            MlsGroup::load(self.provider.storage(), &GroupId::from_slice(id)),
        )?;
        group.ok_or_else(|| LabError::new("missing_group", "快照缺少群密码状态"))
    }

    pub fn restore_provider(&mut self) -> Result<(), LabError> {
        let mut values = self
            .provider
            .storage()
            .values
            .write()
            .map_err(|_| LabError::new("storage_lock", "内存存储锁失效"))?;
        for (key, value) in &self.provider_entries {
            ensure(
                values.insert(key.clone(), value.clone()).is_none(),
                "duplicate_storage_key",
                "快照包含重复存储键",
            )?;
        }
        Ok(())
    }

    pub fn capture_provider(&mut self) -> Result<(), LabError> {
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| LabError::new("storage_lock", "内存存储锁失效"))?;
        self.provider_entries = values
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        self.provider_entries
            .sort_by(|left, right| left.0.cmp(&right.0));
        Ok(())
    }

    pub fn public_identity(&self) -> Value {
        json!({"service":self.context.service,"account":self.context.account,"device":self.context.device,
            "signature_key":codec::encode(&self.own_signature_key),"key_package":codec::encode(&self.key_package),
            "key_package_available":self.group_id.is_none(),"roster_version":self.roster.version()})
    }

    pub fn inspect(&self) -> Result<Value, LabError> {
        let (group_id, epoch, members, active) = if self.group_id.is_some() {
            let group = self.group()?;
            let members = group
                .members()
                .map(|member| {
                    let context = codec::credential_context(&member.credential)?;
                    Ok(json!({"account":context.account,"device":context.device}))
                })
                .collect::<Result<Vec<Value>, LabError>>()?;
            (
                Some(codec::encode(group.group_id().as_slice())),
                Some(group.epoch().as_u64()),
                members,
                group.is_active(),
            )
        } else {
            (None, None, Vec::new(), false)
        };
        Ok(
            json!({"group_id":group_id,"epoch":epoch,"members":members,"active":active,
            "outbox_count":self.outbox.len(),"inbox_count":self.inbox.len(),
            "control_outbox_count":self.control_outbox.len(),"roster_version":self.roster.version()}),
        )
    }
}
