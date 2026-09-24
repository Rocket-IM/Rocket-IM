//! 阶段0发布包验证：单实例仅有一个双设备MLS群，状态只存内存。
//! 不提供网络、持久恢复、成员变更或业务身份认证；不能用于生产聊天。
//! 私钥和第三方密码类型不跨公共边界。close释放本实例，不承诺所有分配已安全擦除。
mod error;
mod identity;
use error::require;
pub use error::{Error, ErrorCode, Result};
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_PROTOCOL_BYTES: usize = 256 * 1024;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct Active {
    service: String,
    account: String,
    device: String,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    package: Vec<u8>,
    group: Option<MlsGroup>,
}

enum State {
    Active(Box<Active>),
    Poisoned,
    Closed,
}

/// 每个实例拥有独立设备身份与内存密码状态；可变方法必须由单一调用者串行访问。
pub struct Device {
    state: State,
}

fn crypto<T, E>(result: std::result::Result<T, E>) -> Result<T> {
    result.map_err(|_| Error::new(ErrorCode::CryptoFailure))
}

fn protocol_bytes(bytes: &[u8]) -> Result<()> {
    require(!bytes.is_empty(), ErrorCode::InvalidArgument)?;
    require(bytes.len() <= MAX_PROTOCOL_BYTES, ErrorCode::LimitExceeded)
}

impl Device {
    pub fn new(service_id: String, account_id: String, device_id: String) -> Result<Self> {
        for value in [&service_id, &account_id, &device_id] {
            identity::id(value)?;
        }
        let provider = OpenMlsRustCrypto::default();
        let signer = crypto(SignatureKeyPair::new(SUITE.signature_algorithm()))?;
        crypto(signer.store(provider.storage()))?;
        let credential = CredentialWithKey {
            credential: identity::credential(&service_id, &account_id, &device_id),
            signature_key: signer.to_public_vec().into(),
        };
        let package =
            crypto(KeyPackage::builder().build(SUITE, &provider, &signer, credential.clone()))?;
        let package = crypto(package.key_package().tls_serialize_detached())?;
        Ok(Self {
            state: State::Active(Box::new(Active {
                service: service_id,
                account: account_id,
                device: device_id,
                provider,
                signer,
                credential,
                package,
                group: None,
            })),
        })
    }

    fn active(&self) -> Result<&Active> {
        match &self.state {
            State::Active(active) => Ok(active),
            State::Poisoned => Err(Error::poisoned(ErrorCode::Poisoned)),
            State::Closed => Err(Error::new(ErrorCode::Closed)),
        }
    }

    /// 调用前完成无副作用校验。开始密码处理后先标为Poisoned，只有完整成功才恢复可用。
    fn mutate<T>(&mut self, action: impl FnOnce(&mut Active) -> Result<T>) -> Result<T> {
        self.active()?;
        let State::Active(mut active) = std::mem::replace(&mut self.state, State::Poisoned) else {
            return Err(Error::poisoned(ErrorCode::Poisoned));
        };
        match action(&mut active) {
            Ok(result) => {
                self.state = State::Active(active);
                Ok(result)
            }
            Err(error) => Err(Error::poisoned(error.code)),
        }
    }

    pub fn identity_key(&self) -> Result<Vec<u8>> {
        Ok(self.active()?.signer.to_public_vec())
    }

    /// 尚未入群时反复返回同一份公开KeyPackage；入群后不再导出已用或多余的加入材料。
    pub fn key_package(&self) -> Result<Vec<u8>> {
        let active = self.active()?;
        require(active.group.is_none(), ErrorCode::AlreadyGrouped)?;
        Ok(active.package.clone())
    }

    fn peer(
        &self,
        account: &str,
        device: &str,
        key: &[u8],
        conversation: &str,
    ) -> Result<Credential> {
        let active = self.active()?;
        require(active.group.is_none(), ErrorCode::AlreadyGrouped)?;
        for value in [account, device, conversation] {
            identity::id(value)?;
        }
        require(key.len() == 32, ErrorCode::InvalidArgument)?;
        require(
            (account, device) != (active.account.as_str(), active.device.as_str())
                && key != active.signer.public(),
            ErrorCode::IdentityMismatch,
        )?;
        Ok(identity::credential(&active.service, account, device))
    }

    /// 固定对方公钥由调用方独立确认；不把KeyPackage中自报身份当作信任来源。
    /// 参数、编码及公开KeyPackage身份不符保持有效状态；实际建群开始后的失败会毒化实例。
    pub fn create_group(
        &mut self,
        conversation_id: String,
        peer_account_id: String,
        peer_device_id: String,
        peer_identity_key: Vec<u8>,
        key_package: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let peer = self.peer(
            &peer_account_id,
            &peer_device_id,
            &peer_identity_key,
            &conversation_id,
        )?;
        protocol_bytes(&key_package)?;
        let package = KeyPackageIn::tls_deserialize_exact(&key_package)
            .map_err(|_| Error::new(ErrorCode::InvalidEncoding))?;
        let package = package
            .validate(self.active()?.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| Error::new(ErrorCode::InvalidEncoding))?;
        require(package.ciphersuite() == SUITE, ErrorCode::InvalidEncoding)?;
        require(
            identity::matches(
                package.leaf_node().credential(),
                package.leaf_node().signature_key().as_slice(),
                &peer,
                &peer_identity_key,
            ),
            ErrorCode::IdentityMismatch,
        )?;
        self.mutate(|active| {
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(SUITE)
                .use_ratchet_tree_extension(true)
                .build();
            let group_id =
                GroupId::from_slice(&identity::group_id(&active.service, &conversation_id));
            let mut group = crypto(MlsGroup::new_with_group_id(
                &active.provider,
                &active.signer,
                &config,
                group_id,
                active.credential.clone(),
            ))?;
            let (_, welcome, _) =
                crypto(group.add_members(&active.provider, &active.signer, &[package]))?;
            crypto(group.merge_pending_commit(&active.provider))?;
            identity::members(
                group.members(),
                &active.credential.credential,
                active.signer.public(),
                &peer,
                &peer_identity_key,
            )?;
            let bytes = crypto(welcome.to_bytes())?;
            protocol_bytes(&bytes)?;
            active.group = Some(group);
            active.package.clear();
            Ok(bytes)
        })
    }

    /// Welcome处理会消耗一次性KeyPackage。进入真实处理后，即使发现固定创建者或群范围
    /// 不符，也返回明确错误并毒化实例；不会复制/回退密码状态后重试。
    pub fn join_group(
        &mut self,
        conversation_id: String,
        creator_account_id: String,
        creator_device_id: String,
        creator_identity_key: Vec<u8>,
        welcome: Vec<u8>,
    ) -> Result<()> {
        let peer = self.peer(
            &creator_account_id,
            &creator_device_id,
            &creator_identity_key,
            &conversation_id,
        )?;
        protocol_bytes(&welcome)?;
        let parsed = MlsMessageIn::tls_deserialize_exact(&welcome)
            .map_err(|_| Error::new(ErrorCode::InvalidEncoding))?;
        let MlsMessageBodyIn::Welcome(welcome) = parsed.extract() else {
            return Err(Error::new(ErrorCode::InvalidEncoding));
        };
        self.mutate(|active| {
            let config = MlsGroupJoinConfig::default();
            let staged = crypto(StagedWelcome::new_from_welcome(
                &active.provider,
                &config,
                welcome,
                None,
            ))?;
            require(
                staged.group_context().group_id().as_slice()
                    == identity::group_id(&active.service, &conversation_id),
                ErrorCode::ScopeMismatch,
            )?;
            let sender = crypto(staged.welcome_sender())?;
            require(
                identity::matches(
                    sender.credential(),
                    sender.signature_key().as_slice(),
                    &peer,
                    &creator_identity_key,
                ),
                ErrorCode::IdentityMismatch,
            )?;
            identity::members(
                staged.members(),
                &active.credential.credential,
                active.signer.public(),
                &peer,
                &creator_identity_key,
            )?;
            active.group = Some(crypto(staged.into_group(&active.provider))?);
            active.package.clear();
            Ok(())
        })
    }

    /// 调用成功即已消耗发送状态；调用方须保留返回密文，不能为网络重试再次调用encrypt。
    pub fn encrypt(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>> {
        require(self.active()?.group.is_some(), ErrorCode::GroupRequired)?;
        require(!plaintext.is_empty(), ErrorCode::InvalidArgument)?;
        require(
            plaintext.len() <= MAX_MESSAGE_BYTES,
            ErrorCode::LimitExceeded,
        )?;
        self.mutate(|active| {
            let group = active
                .group
                .as_mut()
                .ok_or_else(|| Error::new(ErrorCode::GroupRequired))?;
            let message =
                crypto(group.create_message(&active.provider, &active.signer, &plaintext))?;
            let bytes = crypto(message.to_bytes())?;
            protocol_bytes(&bytes)?;
            Ok(bytes)
        })
    }

    /// 只接受当前双设备群应用密文。编码/群范围错误在解密前拒绝；进入解密后任何失败
    /// （包括篡改或重复密文）均毒化实例，不能继续使用可能已推进的接收状态。
    pub fn decrypt(&mut self, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        let group = self
            .active()?
            .group
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::GroupRequired))?;
        protocol_bytes(&ciphertext)?;
        let message = MlsMessageIn::tls_deserialize_exact(&ciphertext)
            .map_err(|_| Error::new(ErrorCode::InvalidEncoding))?;
        let protocol = message
            .try_into_protocol_message()
            .map_err(|_| Error::new(ErrorCode::InvalidEncoding))?;
        require(
            protocol.content_type() == ContentType::Application,
            ErrorCode::InvalidEncoding,
        )?;
        require(
            protocol.group_id() == group.group_id() && protocol.epoch() == group.epoch(),
            ErrorCode::ScopeMismatch,
        )?;
        self.mutate(|active| {
            let group = active
                .group
                .as_mut()
                .ok_or_else(|| Error::new(ErrorCode::GroupRequired))?;
            let processed = crypto(group.process_message(&active.provider, protocol))?;
            let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content()
            else {
                return Err(Error::new(ErrorCode::CryptoFailure));
            };
            let plaintext = message.into_bytes();
            require(
                !plaintext.is_empty() && plaintext.len() <= MAX_MESSAGE_BYTES,
                ErrorCode::LimitExceeded,
            )?;
            Ok(plaintext)
        })
    }

    /// 幂等释放本实例的内存所有权。关闭后除close外全部方法返回Closed。
    pub fn close(&mut self) -> Result<()> {
        self.state = State::Closed;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
