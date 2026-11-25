//! 后继上下文仅复用固定签名身份；不加载、复制或重放旧群/ratchet/KeyPackage 私钥。
use super::{storage::Snapshot, *};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer};

impl Snapshot {
    fn identity_signer(
        &self,
        service: &str,
        account: &str,
        device: &str,
    ) -> Result<SignatureKeyPair> {
        self.validate_identity(service, account, device)
    }
    /// 用既有身份创建全新 provider 与一次性材料；旧快照只读保留。
    pub fn fresh_context(&self, service: &str, account: &str, device: &str) -> Result<Device> {
        let signer = self.identity_signer(service, account, device)?;
        let provider = OpenMlsRustCrypto::default();
        crypto(signer.store(provider.storage()))?;
        let credential = CredentialWithKey {
            credential: identity::credential(service, account, device),
            signature_key: signer.to_public_vec().into(),
        };
        let package =
            crypto(KeyPackage::builder().build(SUITE, &provider, &signer, credential.clone()))?;
        let package = crypto(package.key_package().tls_serialize_detached())?;
        Ok(Device {
            state: State::Active(Box::new(Active {
                service: service.into(),
                account: account.into(),
                device: device.into(),
                provider,
                signer,
                credential,
                package,
                group: None,
                binding: None,
            })),
        })
    }
    pub fn sign_recovery(
        &self,
        service: &str,
        account: &str,
        device: &str,
        bytes: &[u8],
    ) -> Result<Vec<u8>> {
        protocol_bytes(bytes)?;
        crypto(
            self.identity_signer(service, account, device)?
                .sign(&[b"Rocket-IM/SDK/recovery/v1\0".as_slice(), bytes].concat()),
        )
    }
}
pub fn verify_recovery(key: &[u8], bytes: &[u8], signature: &[u8]) -> Result<()> {
    protocol_bytes(bytes)?;
    require(
        key.len() == 32 && signature.len() == 64,
        ErrorCode::InvalidEncoding,
    )?;
    crypto(OpenMlsRustCrypto::default().crypto().verify_signature(
        SUITE.signature_algorithm(),
        &[b"Rocket-IM/SDK/recovery/v1\0".as_slice(), bytes].concat(),
        key,
        signature,
    ))
}
