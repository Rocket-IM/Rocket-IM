//! 可信启动器入口：每次新挑战、当前配置及原锚绑定，恢复provider前检查。
use super::{checked, ensure, rollback_io, store::LockedDevice, Context, LabError, Request};
use crate::trusted_startup::{self as protocol, Manifest, Response};
use serde::Deserialize;
use std::path::PathBuf;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    protocol_version: String,
    manifest: Manifest,
    authority_key: String,
    helper_path: PathBuf,
    authority_directory: PathBuf,
}
pub(super) fn check(
    locked: &LockedDevice,
    request: &Request,
    context: &Context,
) -> Result<(), LabError> {
    let Some(path) = std::env::var_os("RIM_TRUSTED_STARTUP_CONFIG") else {
        ensure(
            std::env::var_os("RIM_TRUSTED_STARTUP_REQUIRED").is_none(),
            "startup_required",
            "可信启动器要求配置，禁止无配置运行",
        )?;
        return Ok(());
    };
    let path = PathBuf::from(path);
    ensure(
        path.is_absolute(),
        "startup_config",
        "启动配置必须为绝对路径",
    )?;
    let config: Config = checked(
        "startup_config",
        serde_json::from_slice(&rollback_io::read_file(&path, protocol::LIMIT)?),
    )?;
    let pinned = std::env::var("RIM_TRUSTED_STARTUP_KEY")
        .map_err(|_| LabError::new("startup_required", "缺启动器独立固定的权威根"))?;
    let pinned_helper = std::env::var_os("RIM_TRUSTED_STARTUP_HELPER")
        .ok_or_else(|| LabError::new("startup_required", "缺独立固定的权威入口"))?;
    let pinned_directory = std::env::var_os("RIM_TRUSTED_STARTUP_AUTHORITY")
        .ok_or_else(|| LabError::new("startup_required", "缺独立固定的权威账本"))?;
    ensure(
        config.helper_path.as_os_str() == pinned_helper
            && config.authority_directory.as_os_str() == pinned_directory,
        "startup_transport",
        "配置不能替换启动器固定的权威入口和账本",
    )?;
    ensure(
        config.protocol_version == "rim-startup-client-1"
            && config.authority_key == pinned
            && config.helper_path.is_absolute()
            && config.authority_directory.is_absolute(),
        "startup_config",
        "启动根或版本不符",
    )?;
    config.manifest.validate()?;
    let local = checked("startup_path", std::fs::canonicalize(&request.directory))?;
    let authority = checked(
        "startup_path",
        std::fs::canonicalize(&config.authority_directory),
    )?;
    let trusted = checked("startup_path", std::fs::canonicalize(&path))?;
    ensure(
        !authority.starts_with(&local)
            && !local.starts_with(&authority)
            && !trusted.starts_with(&local)
            && !trusted.starts_with(&authority),
        "startup_path",
        "启动配置/权威/设备必须分开保存",
    )?;
    let challenge = rollback_io::random_hex()?;
    let input = checked(
        "startup_encoding",
        serde_json::to_vec(
            &serde_json::json!({"op":"check","directory":config.authority_directory,"slot":config.manifest.slot,"challenge":challenge}),
        ),
    )?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        ok: bool,
        response: crate::permission::receipts::SignedRecord,
    }
    let raw = rollback_io::invoke(&config.helper_path, &input)?;
    let reply: Reply = checked("startup_response", serde_json::from_slice(&raw))?;
    let response: Response = protocol::verify(&reply.response, protocol::RESPONSE_DOMAIN, &pinned)?;
    ensure(
        reply.ok
            && response.protocol_version == "rim-startup-response-1"
            && response.slot == config.manifest.slot
            && response.challenge == challenge,
        "startup_response",
        "权威响应未绑定本次挑战/范围",
    )?;
    ensure(!response.disabled, "startup_disabled", "安装槽已失陷停用")?;
    ensure(
        response.generation == config.manifest.generation
            && response.manifest_sha256 == config.manifest.hash()?,
        "startup_stale",
        "配置未获独立批准或已被后继取代",
    )?;
    let anchor_path = std::env::var_os("RIM_ROLLBACK_ANCHOR_CONFIG")
        .ok_or_else(|| LabError::new("startup_anchor_required", "可信启动必须同时使用原独立锚"))?;
    let anchor_path = PathBuf::from(anchor_path);
    let bytes = rollback_io::read_file(&anchor_path, rollback_io::LIMIT)?;
    ensure(
        crate::permission::commit_digest(&bytes) == config.manifest.anchor_config_sha256,
        "startup_anchor_binding",
        "锚配置原字节不符",
    )?;
    let anchor = rollback_io::Config::load(&anchor_path, &request.directory)?;
    let m = &config.manifest;
    ensure(
        anchor.scope == m.scope
            && anchor.anchor_public_key == m.anchor_public_key
            && m.scope.service == context.service
            && m.scope.account == context.account
            && m.scope.device == context.device,
        "startup_scope",
        "启动配置或设备范围不符",
    )?;
    let head = rollback_io::state_hash(&request.directory)?;
    let state = locked
        .metadata_committed(
            context,
            &checked("startup_head", crate::rollback_anchor::decode_hex(&head))?,
        )?
        .ok_or_else(|| LabError::new("startup_unprepared", "启动配置不能把空库当作首次安装"))?;
    ensure(
        super::codec::encode(&state.own_signature_key) == base64_key(&m.scope.identity_key)?
            && state
                .identity_source
                .as_ref()
                .is_some_and(|s| s.roots == m.roots),
        "startup_root_binding",
        "身份根或实际设备身份不符",
    )?;
    // 不改写state、暂停、历史、权限或锚；后续原路径仍须独立检查。
    Ok(())
}
fn base64_key(hex: &str) -> Result<String, LabError> {
    Ok(super::codec::encode(&checked(
        "startup_identity",
        crate::rollback_anchor::decode_hex(hex),
    )?))
}
