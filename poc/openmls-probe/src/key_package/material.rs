//! 公共 KeyPackage 元数据只能从真实库校验后的原件派生。
use super::{check, error};
use crate::permission::{admission, types, Member, PermissionError};
use base64::{engine::general_purpose::STANDARD, Engine};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Material {
    pub key_package_sha256: String,
    pub key_package_ref: String,
    pub init_key: String,
    pub leaf_key: String,
    pub not_before: String,
    pub not_after: String,
    pub suite: String,
}
pub fn metadata(package: &KeyPackage) -> Result<Material, PermissionError> {
    check(!package.last_resort(), "key_package_last_resort")?;
    let life = package.life_time();
    check(
        life.not_after()
            .checked_sub(life.not_before())
            .is_some_and(|span| (1..=86400).contains(&span)),
        "key_package_lifetime",
    )?;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let raw = package
        .tls_serialize_detached()
        .map_err(|_| error("key_package_invalid"))?;
    check(raw.len() <= 8192, "key_package_invalid")?;
    Ok(Material {
        key_package_sha256: crate::permission::commit_digest(&raw),
        key_package_ref: STANDARD.encode(
            package
                .hash_ref(provider.crypto())
                .map_err(|_| error("key_package_invalid"))?
                .as_slice(),
        ),
        init_key: STANDARD.encode(package.hpke_init_key().as_slice()),
        leaf_key: STANDARD.encode(
            package
                .leaf_node()
                .encryption_key()
                .tls_serialize_detached()
                .map_err(|_| error("key_package_invalid"))?,
        ),
        not_before: life.not_before().to_string(),
        not_after: life.not_after().to_string(),
        suite: "1".into(),
    })
}
pub fn inspect(encoded: &str, service: &str, owner: &Member) -> Result<Material, PermissionError> {
    types::bytes(encoded, 8192)?;
    let package = admission::validate_package(encoded, service, owner)?;
    metadata(&package)
}
pub fn current(material: &Material, now: u64) -> Result<(), PermissionError> {
    check(
        types::decimal(&material.not_before)? <= now && now < types::decimal(&material.not_after)?,
        "key_package_expired",
    )
}
