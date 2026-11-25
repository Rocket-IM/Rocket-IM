//! im-sdk 内部持久适配。快照含秘密，只交给 Rust 存储层，不跨平台桥接。
//! 本格式锁定 OpenMLS 0.9.0/provider 0.6.0；与隔离 POC 的数据库不兼容。
use super::*;
use openmls_basic_credential::StorageId;
use openmls_traits::storage::StorageProvider;
use serde::{Deserialize as De, Serialize as Ser};

pub const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const FORMAT: &str = "Rocket-IM/SDK/persistent-crypto/v1/openmls-0.9.0/provider-0.6.0";

#[derive(Clone, Debug, PartialEq, Eq, Ser, De)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub conversation: String,
    pub account: String,
    pub device: String,
    pub key: Vec<u8>,
}

/// 含秘密的非稳定内部格式，不实现 Debug，不供平台宿主使用。
#[derive(Ser, De)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    format: String,
    service: String,
    account: String,
    device: String,
    public_key: Vec<u8>,
    signature_id: StorageId,
    package: Vec<u8>,
    binding: Option<Binding>,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Device {
    pub fn binding(&self) -> Result<Option<Binding>> {
        Ok(self.active()?.binding.clone())
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let active = self.active()?;
        let values = active
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::new(ErrorCode::CryptoFailure))?;
        require(values.len() <= 10000, ErrorCode::LimitExceeded)?;
        let mut entries: Vec<_> = values.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Snapshot {
            format: FORMAT.into(),
            service: active.service.clone(),
            account: active.account.clone(),
            device: active.device.clone(),
            public_key: active.signer.to_public_vec(),
            signature_id: active.signer.id(),
            package: active.package.clone(),
            binding: active.binding.clone(),
            entries,
        })
    }

    pub fn restore(snapshot: Snapshot, service: &str, account: &str, device: &str) -> Result<Self> {
        let bad = ErrorCode::InvalidEncoding;
        require(snapshot.format == FORMAT, bad)?;
        require(
            (
                snapshot.service.as_str(),
                snapshot.account.as_str(),
                snapshot.device.as_str(),
            ) == (service, account, device),
            ErrorCode::ScopeMismatch,
        )?;
        for value in [service, account, device] {
            identity::id(value)?;
        }
        require(
            !snapshot.entries.is_empty() && snapshot.entries.len() <= 10000,
            bad,
        )?;
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| Error::new(bad))?;
            let mut previous: Option<&[u8]> = None;
            let mut total = 0usize;
            for (k, v) in &snapshot.entries {
                total = total.saturating_add(k.len()).saturating_add(v.len());
                require(
                    !k.is_empty()
                        && previous.is_none_or(|p| p < k.as_slice())
                        && total <= MAX_SNAPSHOT_BYTES,
                    bad,
                )?;
                values.insert(k.clone(), v.clone());
                previous = Some(k);
            }
        }
        let signer: SignatureKeyPair = crypto(
            provider
                .storage()
                .signature_key_pair(&snapshot.signature_id),
        )?
        .ok_or_else(|| Error::new(bad))?;
        require(
            signer.public() == snapshot.public_key
                && signer.public().len() == 32
                && signer.signature_scheme() == SUITE.signature_algorithm(),
            bad,
        )?;
        let credential = CredentialWithKey {
            credential: identity::credential(service, account, device),
            signature_key: signer.to_public_vec().into(),
        };
        let group = if let Some(binding) = &snapshot.binding {
            for v in [&binding.conversation, &binding.account, &binding.device] {
                identity::id(v)?;
            }
            require(
                snapshot.package.is_empty()
                    && binding.key.len() == 32
                    && (binding.account.as_str(), binding.device.as_str()) != (account, device)
                    && binding.key != signer.public(),
                bad,
            )?;
            let id = GroupId::from_slice(&identity::group_id(service, &binding.conversation));
            let group =
                crypto(MlsGroup::load(provider.storage(), &id))?.ok_or_else(|| Error::new(bad))?;
            require(group.ciphersuite() == SUITE && group.is_active(), bad)?;
            identity::members(
                group.members(),
                &credential.credential,
                signer.public(),
                &identity::credential(service, &binding.account, &binding.device),
                &binding.key,
            )?;
            Some(group)
        } else {
            protocol_bytes(&snapshot.package)?;
            let package = crypto(KeyPackageIn::tls_deserialize_exact(&snapshot.package))?;
            let package = crypto(package.validate(provider.crypto(), ProtocolVersion::Mls10))?;
            require(
                package.ciphersuite() == SUITE
                    && identity::matches(
                        package.leaf_node().credential(),
                        package.leaf_node().signature_key().as_slice(),
                        &credential.credential,
                        signer.public(),
                    ),
                bad,
            )?;
            None
        };
        Ok(Self {
            state: State::Active(Box::new(Active {
                service: service.into(),
                account: account.into(),
                device: device.into(),
                provider,
                signer,
                credential,
                package: snapshot.package,
                group,
                binding: snapshot.binding,
            })),
        })
    }
}

impl Snapshot {
    pub(super) fn validate_identity(
        &self,
        service: &str,
        account: &str,
        device: &str,
    ) -> Result<SignatureKeyPair> {
        let bad = ErrorCode::InvalidEncoding;
        require(
            self.format == FORMAT
                && self.service == service
                && self.account == account
                && self.device == device,
            bad,
        )?;
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| Error::new(bad))?;
            let mut previous: Option<&[u8]> = None;
            let mut total = 0;
            for (k, v) in &self.entries {
                total += k.len() + v.len();
                require(
                    !k.is_empty()
                        && previous.is_none_or(|p| p < k.as_slice())
                        && total <= MAX_SNAPSHOT_BYTES,
                    bad,
                )?;
                // provider 0.6.0 的版本化存储键以此标签开头。只拷贝签名身份；
                // 群、ratchet 与旧 KeyPackage 私有项不进入此临时 provider。
                if k.starts_with(b"SignatureKeyPair") {
                    values.insert(k.clone(), v.clone());
                }
                previous = Some(k);
            }
        }
        let signer: SignatureKeyPair =
            crypto(provider.storage().signature_key_pair(&self.signature_id))?
                .ok_or_else(|| Error::new(bad))?;
        require(
            signer.public() == self.public_key
                && signer.public().len() == 32
                && signer.signature_scheme() == SUITE.signature_algorithm(),
            bad,
        )?;
        Ok(signer)
    }
}
