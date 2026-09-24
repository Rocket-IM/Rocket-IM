use super::{checked, ensure, Context, LabError};
use base64::{engine::general_purpose::STANDARD, Engine};
use openmls::prelude::{tls_codec::Deserialize, *};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};

pub(super) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub(super) fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub(super) fn decode(encoded: &str) -> Result<Vec<u8>, LabError> {
    ensure(
        encoded.len() <= 1024 * 1024,
        "input_limit",
        "编码字段超过上限",
    )?;
    checked("invalid_base64", STANDARD.decode(encoded))
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(super) fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn valid_id(value: &str) -> Result<(), LabError> {
    ensure(
        !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control),
        "invalid_id",
        "标识必须是 1—128 字节且不含控制字符",
    )
}

pub(super) fn credential_context(credential: &Credential) -> Result<Context, LabError> {
    let basic = checked(
        "credential_type",
        BasicCredential::try_from(credential.clone()),
    )?;
    checked(
        "credential_context",
        serde_json::from_slice(basic.identity()),
    )
}

pub(super) fn validated_package(
    raw: &[u8],
    provider: &OpenMlsRustCrypto,
) -> Result<KeyPackage, LabError> {
    let package = checked(
        "key_package_encoding",
        KeyPackageIn::tls_deserialize_exact(raw),
    )?;
    checked(
        "key_package_validation",
        package.validate(provider.crypto(), ProtocolVersion::Mls10),
    )
}

pub(super) fn protocol(raw: &[u8]) -> Result<ProtocolMessage, LabError> {
    let message = checked("message_encoding", MlsMessageIn::tls_deserialize_exact(raw))?;
    checked("message_type", message.try_into_protocol_message())
}
