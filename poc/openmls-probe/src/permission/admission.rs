//! 入群附属材料的公共验证；只读新设备 KeyPackage，不接触用户私密存储。
use super::{check, commit_digest, types, Action, PermissionError, Statement};
use openmls::prelude::{tls_codec::Deserialize as TlsDeserialize, *};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinMaterial {
    pub key_package: String,
    pub welcome: String,
}

pub(crate) fn present_material<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<JoinMaterial>, D::Error> {
    JoinMaterial::deserialize(deserializer).map(Some)
}

pub(crate) fn validate_package(
    encoded: &str,
    service: &str,
    member: &super::Member,
) -> Result<KeyPackage, PermissionError> {
    let raw = types::bytes(encoded, 512 * 1024)?;
    let package = KeyPackageIn::tls_deserialize_exact(&raw)
        .map_err(|_| PermissionError::new("invalid_join_material", "KeyPackage 编码无效"))?;
    let provider = OpenMlsRustCrypto::default();
    let package = package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| PermissionError::new("invalid_join_material", "KeyPackage 验证失败"))?;
    check(
        package.ciphersuite() == Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        "invalid_join_material",
        "KeyPackage 密码套件不符",
    )?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Context {
        service: String,
        account: String,
        device: String,
    }
    let credential = BasicCredential::try_from(package.leaf_node().credential().clone())
        .map_err(|_| PermissionError::new("invalid_join_material", "KeyPackage 身份类型无效"))?;
    let context: Context = serde_json::from_slice(credential.identity())
        .map_err(|_| PermissionError::new("invalid_join_material", "KeyPackage 身份编码无效"))?;
    check(
        context.service == service
            && context.account == member.account_id
            && context.device == member.device_id
            && package.leaf_node().signature_key().as_slice()
                == types::bytes(&member.signature_key, 32)?,
        "join_identity",
        "KeyPackage 与固定身份不匹配",
    )?;
    Ok(package)
}

pub fn verify_material(statement: &Statement, join: &JoinMaterial) -> Result<(), PermissionError> {
    let (Action::AddMember {
        member,
        key_package_sha256,
        welcome_sha256,
        ..
    }
    | Action::AddDevice {
        member,
        key_package_sha256,
        welcome_sha256,
        ..
    }) = &statement.action
    else {
        return Err(PermissionError::new(
            "invalid_join_material",
            "只有 Add 可携带入群材料",
        ));
    };
    check(
        commit_digest(&types::bytes(&join.key_package, 512 * 1024)?) == *key_package_sha256
            && commit_digest(&types::bytes(&join.welcome, 512 * 1024)?) == *welcome_sha256,
        "join_material_mismatch",
        "入群材料与签名摘要不匹配",
    )?;
    validate_package(&join.key_package, &statement.service_id, member)?;
    let message = MlsMessageIn::tls_deserialize_exact(types::bytes(&join.welcome, 512 * 1024)?)
        .map_err(|_| PermissionError::new("invalid_join_material", "Welcome 编码无效"))?;
    check(
        matches!(message.extract(), MlsMessageBodyIn::Welcome(_)),
        "invalid_join_material",
        "入群材料必须是 Welcome",
    )
}
