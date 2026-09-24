//! OpenMLS 候选最小验证；每个参与者使用独立内存状态。
//!
//! API 依据 openmls-v0.9.0/openmls/tests/book_code.rs。
//! 合成凭据直接用于实验，不代表已验证业务身份、设备授权或完整 T16。
//! 本文件最小入口不包含网络、重启恢复、旧密钥底层攻击或四端发布验收。
//! Unix 的合成授权与进程恢复实验独立放在 authorization、snapshot 和 lab 模块。

use openmls::prelude::{tls_codec::Deserialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use std::fmt::Display;

#[cfg(unix)]
pub mod authorization;

#[cfg(unix)]
pub mod permission;

#[cfg(unix)]
pub mod relay_receipt;

#[cfg(unix)]
pub mod message_acceptance;

#[cfg(unix)]
pub mod message_closure;

#[cfg(unix)]
pub mod message_rejection;

#[cfg(unix)]
pub mod consistency;
#[cfg(unix)]
pub mod consistency_exchange;
#[cfg(unix)]
pub mod history_transfer;

#[cfg(unix)]
pub mod snapshot;

#[cfg(unix)]
pub mod rollback_anchor;

#[cfg(unix)]
pub mod rebuild_stream;

#[cfg(unix)]
pub mod stream_page;

#[cfg(unix)]
pub mod lab;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn at<T, E: Display>(step: &str, result: Result<T, E>) -> Result<T, String> {
    result.map_err(|error| format!("{step}: {error}"))
}

fn require(condition: bool, reason: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(reason.to_owned())
    }
}

fn identity(
    name: &[u8],
    provider: &OpenMlsRustCrypto,
) -> Result<(CredentialWithKey, SignatureKeyPair), String> {
    let signer = at(
        "生成独立设备签名密钥",
        SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()),
    )?;
    at("保存设备签名密钥", signer.store(provider.storage()))?;
    let credential = CredentialWithKey {
        credential: BasicCredential::new(name.to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    Ok((credential, signer))
}

fn key_package(
    credential: CredentialWithKey,
    signer: &SignatureKeyPair,
    provider: &OpenMlsRustCrypto,
) -> Result<KeyPackageBundle, String> {
    at(
        "生成 KeyPackage",
        KeyPackage::builder().build(CIPHERSUITE, provider, signer, credential),
    )
}

fn protocol_message(bytes: &[u8]) -> Result<ProtocolMessage, String> {
    let message = at("解码消息", MlsMessageIn::tls_deserialize_exact(bytes))?;
    at("检查消息类型", message.try_into_protocol_message())
}

fn join(
    provider: &OpenMlsRustCrypto,
    config: &MlsGroupJoinConfig,
    welcome_bytes: &[u8],
) -> Result<MlsGroup, String> {
    let message = at(
        "解码 Welcome",
        MlsMessageIn::tls_deserialize_exact(welcome_bytes),
    )?;
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err("入群消息不是 Welcome".to_owned()),
    };
    let staged = at(
        "验证 Welcome",
        StagedWelcome::new_from_welcome(provider, config, welcome, None),
    )?;
    at("提交入群状态", staged.into_group(provider))
}

fn receive_application(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    bytes: &[u8],
    expected: &[u8],
) -> Result<(), String> {
    let message = at(
        "处理应用密文",
        group.process_message(provider, protocol_message(bytes)?),
    )?;
    match message.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            require(message.into_bytes() == expected, "解密内容不匹配")
        }
        _ => Err("预期应用消息，但收到其他协议消息".to_owned()),
    }
}

/// 在原生或浏览器执行相同流程，返回不含正文、身份或密钥的结果摘要。
///
/// 失败携带步骤及库错误。参与者数据只存于本次调用的内存中。
/// 被移除者保留旧状态，直接获得新密文；库拒绝不等于底层旧钥攻击已证明。
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_smoke() -> Result<String, String> {
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let charlie_provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = identity(b"synthetic-a1", &alice_provider)?;
    let (bob_credential, bob_signer) = identity(b"synthetic-b1", &bob_provider)?;
    let (charlie_credential, charlie_signer) = identity(b"synthetic-c1", &charlie_provider)?;
    let bob_package = key_package(bob_credential, &bob_signer, &bob_provider)?;
    let charlie_package = key_package(charlie_credential, &charlie_signer, &charlie_provider)?;
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut alice_group = at(
        "创建群",
        MlsGroup::new(&alice_provider, &alice_signer, &config, alice_credential),
    )?;
    let (_, welcome, _) = at(
        "添加两名成员",
        alice_group.add_members(
            &alice_provider,
            &alice_signer,
            &[
                bob_package.key_package().clone(),
                charlie_package.key_package().clone(),
            ],
        ),
    )?;
    at(
        "创建者提交入群变更",
        alice_group.merge_pending_commit(&alice_provider),
    )?;
    let welcome_bytes = at("序列化 Welcome", welcome.to_bytes())?;
    let mut bob_group = join(&bob_provider, config.join_config(), &welcome_bytes)?;
    let mut charlie_group = join(&charlie_provider, config.join_config(), &welcome_bytes)?;
    require(
        alice_group.members().count() == 3
            && alice_group.members().eq(bob_group.members())
            && alice_group.members().eq(charlie_group.members()),
        "三个参与者的初始成员集合不一致",
    )?;
    let initial_plaintext = b"synthetic-before-remove";
    let initial_message = at(
        "生成初始密文",
        alice_group.create_message(&alice_provider, &alice_signer, initial_plaintext),
    )?;
    let initial_bytes = at("序列化初始密文", initial_message.to_bytes())?;
    receive_application(
        &mut bob_group,
        &bob_provider,
        &initial_bytes,
        initial_plaintext,
    )?;
    receive_application(
        &mut charlie_group,
        &charlie_provider,
        &initial_bytes,
        initial_plaintext,
    )?;

    let removed_index = charlie_group.own_leaf_index();
    let old_epoch = charlie_group.epoch();
    let (removal, _, _) = at(
        "生成移除成员 Commit",
        alice_group.remove_members(&alice_provider, &alice_signer, &[removed_index]),
    )?;
    let removal_bytes = at("序列化移除 Commit", removal.to_bytes())?;
    let processed = at(
        "保留成员处理移除 Commit",
        bob_group.process_message(&bob_provider, protocol_message(&removal_bytes)?),
    )?;
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => commit,
        _ => return Err("移除操作没有产生 StagedCommit".to_owned()),
    };
    let removed: Vec<_> = staged
        .remove_proposals()
        .map(|proposal| proposal.remove_proposal().removed())
        .collect();
    require(removed == [removed_index], "移除 Commit 的成员不符合预期")?;
    at(
        "保留成员提交移除状态",
        bob_group.merge_staged_commit(&bob_provider, *staged),
    )?;
    at(
        "创建者提交移除状态",
        alice_group.merge_pending_commit(&alice_provider),
    )?;
    require(
        alice_group.members().count() == 2
            && alice_group.members().eq(bob_group.members())
            && alice_group.epoch() == bob_group.epoch()
            && alice_group.epoch() != old_epoch,
        "保留成员没有达到一致的新 epoch",
    )?;
    let new_plaintext = b"synthetic-after-remove";
    let new_message = at(
        "新 epoch 生成密文",
        alice_group.create_message(&alice_provider, &alice_signer, new_plaintext),
    )?;
    let new_bytes = at("序列化新 epoch 密文", new_message.to_bytes())?;
    receive_application(&mut bob_group, &bob_provider, &new_bytes, new_plaintext)?;

    // 不给 C Commit，不清理其秘密，也不依靠服务器阻止密文投递。
    // 此处验证公开 API 拒绝旧状态处理新 epoch；完整旧密钥攻击仍待后续 POC。
    require(
        charlie_group.is_active() && charlie_group.epoch() == old_epoch,
        "被移除者未保留撤销前活动状态",
    )?;
    match charlie_group.process_message(&charlie_provider, protocol_message(&new_bytes)?) {
        Err(ProcessMessageError::ValidationError(ValidationError::WrongEpoch)) => {}
        Err(error) => {
            return Err(format!("被移除者应因 WrongEpoch 拒绝，实际错误：{error}"));
        }
        Ok(_) => return Err("被移除者的旧状态意外接受了新 epoch 密文".to_owned()),
    }
    Ok("openmls=0.9.0; members_before=3; members_after=2; initial_receive=pass; remaining_receive=pass; removed_old_state_rejected=pass; rejection=WrongEpoch; identity_validation=not_tested; persistent_storage=not_tested; raw_old_key_attack=not_tested".to_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn membership_change_smoke() -> Result<(), String> {
        super::run_smoke().map(|_| ())
    }
}
