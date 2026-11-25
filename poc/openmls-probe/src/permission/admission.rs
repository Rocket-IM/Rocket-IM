//! 入群附属材料的公共验证；只读新设备 KeyPackage，不接触用户私密存储。
use super::{check, commit_digest, types, Action, PermissionError, Statement};
use openmls::prelude::{tls_codec::Deserialize as TlsDeserialize, *};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub request: super::receipts::SignedRecord,
    pub receipt: super::receipts::SignedRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinMaterial {
    pub key_package: String,
    pub welcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation: Option<Allocation>,
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

pub fn verify_binding(statement: &Statement, join: &JoinMaterial) -> Result<(), PermissionError> {
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
    match (&statement.allocation_sha256, &join.allocation) {
        (None, None) => {}
        (Some(hash), Some(allocation)) => {
            let request = crate::key_package::parse(&allocation.request)?;
            let receipt_raw = types::bytes(
                &allocation.receipt.statement_bytes,
                crate::key_package::LIMIT,
            )?;
            let receipt: crate::key_package::Receipt = serde_json::from_slice(&receipt_raw)
                .map_err(|_| crate::key_package::error("key_package_invalid"))?;
            receipt.validate()?;
            let crate::key_package::Action::Claim {
                target,
                conversation_id,
                join_kind,
                change_id,
                authorization_version,
                crypto_state_ref,
                ..
            } = request.action
            else {
                return Err(crate::key_package::error("key_package_context"));
            };
            check(
                crate::key_package::digest(&allocation.receipt)? == *hash
                    && request.service_id == statement.service_id
                    && request.actor.identity() == statement.actor
                    && target == *member
                    && conversation_id == statement.conversation_id
                    && change_id == statement.change_id
                    && authorization_version == statement.previous_authorization_version
                    && crypto_state_ref == statement.from_state_ref
                    && join_kind
                        == if matches!(statement.action, Action::AddMember { .. }) {
                            "add_member"
                        } else {
                            "add_device"
                        }
                    && receipt.service_id == statement.service_id
                    && receipt.request_sha256 == crate::key_package::digest(&allocation.request)?
                    && matches!(receipt.result,crate::key_package::ResultBody::Allocated {ref key_package,..} if *key_package==join.key_package),
                "key_package_context",
                "领取与候选不符",
            )?;
        }
        _ => return Err(crate::key_package::error("key_package_allocation_required")),
    }
    let message = MlsMessageIn::tls_deserialize_exact(types::bytes(&join.welcome, 512 * 1024)?)
        .map_err(|_| PermissionError::new("invalid_join_material", "Welcome 编码无效"))?;
    check(
        matches!(message.extract(), MlsMessageBodyIn::Welcome(_)),
        "invalid_join_material",
        "入群材料必须是 Welcome",
    )
}

/// 历史原件绑定不安装 MLS；首次使用仍必须通过当前真实库验证。
pub fn verify_material(statement: &Statement, join: &JoinMaterial) -> Result<(), PermissionError> {
    verify_binding(statement, join)?;
    let (Action::AddMember { member, .. } | Action::AddDevice { member, .. }) = &statement.action
    else {
        return Err(PermissionError::new("invalid_join_material", "必须为 Add"));
    };
    validate_package(&join.key_package, &statement.service_id, member)?;
    Ok(())
}
