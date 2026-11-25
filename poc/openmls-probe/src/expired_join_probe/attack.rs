//! 合成攻击副本的旧 SenderDataSecret 直接 AEAD 试解；只输出成功/错误类别。
//! 不调用群 epoch/权限门禁。不声明覆盖任意密钥恢复攻击或身份签名钥失陷。
use super::*;
use actor::Actor;
use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};

pub(super) fn secret(actor: &Actor) -> Result<Vec<u8>, String> {
    let values = checked("provider read", actor.provider.storage().values.read())?;
    let mut found = Vec::new();
    for (key, value) in values.iter() {
        if key.starts_with(b"MessageSecrets") {
            let value: Value = checked("secret decode", serde_json::from_slice(value))?;
            if let Some(bytes) =
                value.pointer("/message_secrets/sender_data_secret/secret/value/vec")
            {
                found.push(checked(
                    "secret bytes",
                    serde_json::from_value(bytes.clone()),
                )?);
            }
        }
    }
    ensure(found.len() == 1, "expected one current sender secret")?;
    found.pop().ok_or_else(|| "missing sender secret".into())
}

pub(super) fn expand(
    actor: &Actor,
    secret: &[u8],
    label: &str,
    sample: &[u8],
    len: u16,
) -> Result<Vec<u8>, String> {
    let mut info = len.to_be_bytes().to_vec();
    info.extend(checked(
        "label bytes",
        tls_codec::VLBytes::new(format!("MLS 1.0 {label}").into_bytes()).tls_serialize_detached(),
    )?);
    info.extend(checked(
        "sample bytes",
        tls_codec::VLBytes::new(sample.to_vec()).tls_serialize_detached(),
    )?);
    Ok(checked(
        "hkdf expand",
        actor
            .provider
            .crypto()
            .hkdf_expand(SUITE.hash_algorithm(), secret, &info, len as usize),
    )?
    .as_slice()
    .to_vec())
}

pub(super) fn attempt(actor: &Actor, bytes: &[u8]) -> Result<Result<Vec<u8>, CryptoError>, String> {
    // 用 TLS 类型解码真实密文，私有字段不经 serde 或硬编码偏移访问。
    let mut input = bytes;
    let version = checked("version", ProtocolVersion::tls_deserialize(&mut input))?;
    let wire = checked("wire", WireFormat::tls_deserialize(&mut input))?;
    ensure(
        version == ProtocolVersion::Mls10 && wire == WireFormat::PrivateMessage,
        "expected MLS private message",
    )?;
    let group = checked("group", GroupId::tls_deserialize(&mut input))?;
    let epoch = checked("epoch", GroupEpoch::tls_deserialize(&mut input))?;
    let kind = checked("kind", ContentType::tls_deserialize(&mut input))?;
    let _aad = checked("aad", tls_codec::VLBytes::tls_deserialize(&mut input))?;
    let sender = checked(
        "sender data",
        tls_codec::VLBytes::tls_deserialize(&mut input),
    )?;
    let ciphertext = checked(
        "ciphertext",
        tls_codec::VLBytes::tls_deserialize(&mut input),
    )?;
    ensure(
        input.is_empty() && ciphertext.as_slice().len() >= SUITE.hash_length(),
        "invalid ciphertext framing",
    )?;
    let sample = &ciphertext.as_slice()[..SUITE.hash_length()];
    let secret = secret(actor)?;
    let key = expand(
        actor,
        &secret,
        "key",
        sample,
        SUITE.aead_key_length() as u16,
    )?;
    let nonce = expand(
        actor,
        &secret,
        "nonce",
        sample,
        SUITE.aead_nonce_length() as u16,
    )?;
    let mut aad = checked("group aad", group.tls_serialize_detached())?;
    aad.extend(checked("epoch aad", epoch.tls_serialize_detached())?);
    aad.extend(checked("kind aad", kind.tls_serialize_detached())?);
    Ok(actor.provider.crypto().aead_decrypt(
        SUITE.aead_algorithm(),
        &key,
        sender.as_slice(),
        &nonce,
        &aad,
    ))
}

pub(super) fn verify(
    old: &Actor,
    current: &Actor,
    before: &[u8],
    after: &[u8],
) -> Result<Value, String> {
    let old_control = checked("old secret positive control", attempt(old, before)?)?;
    let new_control = checked("new secret positive control", attempt(current, after)?)?;
    ensure(
        old_control.len() == 12 && new_control.len() == 12,
        "invalid decrypted sender data",
    )?;
    let rejection = match attempt(old, after)? {
        Err(CryptoError::AeadDecryptionError) => "AeadDecryptionError",
        Err(_) => return Err("unexpected raw crypto failure".into()),
        Ok(_) => return Err("old secret decrypted new sender data".into()),
    };
    Ok(
        json!({"old_on_old":"PASS","new_on_new":"PASS","old_on_new":rejection,
        "direct_aead":true,"network_or_epoch_gate":false,"ciphertext_sha256":digest(after),
        "scope":"sender-data AEAD, not exhaustive old-secret recovery or compromised signing key proof"}),
    )
}
