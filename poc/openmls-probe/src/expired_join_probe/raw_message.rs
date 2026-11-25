//! TLS解析与裸AEAD测试；不调用epoch/成员/网络门禁，不返回或打印秘密。
use super::*;
use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};
pub(super) struct Packet {
    pub epoch: u64,
    pub body: Vec<u8>,
    pub aad: Vec<u8>,
    pub sender_offset: usize,
}
#[derive(Clone, Copy)]
pub(super) struct SenderData {
    pub sender: u32,
    pub generation: u32,
    pub reuse_guard: [u8; 4],
}
pub(super) fn packet(bytes: &[u8]) -> Result<Packet, String> {
    ensure(bytes.len() <= 1024 * 1024, "message limit")?;
    let mut input = bytes;
    let version = checked("version", ProtocolVersion::tls_deserialize(&mut input))?;
    let wire = checked("wire", WireFormat::tls_deserialize(&mut input))?;
    ensure(
        version == ProtocolVersion::Mls10 && wire == WireFormat::PrivateMessage,
        "private message required",
    )?;
    let group = checked("group", GroupId::tls_deserialize(&mut input))?;
    let epoch = checked("epoch", GroupEpoch::tls_deserialize(&mut input))?;
    let kind = checked("kind", ContentType::tls_deserialize(&mut input))?;
    ensure(kind == ContentType::Application, "application required")?;
    let auth = checked(
        "authenticated data",
        tls_codec::VLBytes::tls_deserialize(&mut input),
    )?;
    let sender = checked("sender", tls_codec::VLBytes::tls_deserialize(&mut input))?;
    ensure(sender.as_slice().len() == 28, "sender data AEAD size")?;
    let sender_offset = bytes.len() - input.len() - sender.as_slice().len();
    let body = checked("body", tls_codec::VLBytes::tls_deserialize(&mut input))?;
    ensure(
        input.is_empty() && body.as_slice().len() >= 16,
        "body framing",
    )?;
    let mut aad = checked("group aad", group.tls_serialize_detached())?;
    aad.extend(checked("epoch aad", epoch.tls_serialize_detached())?);
    aad.extend(checked("kind aad", kind.tls_serialize_detached())?);
    aad.extend(checked("auth aad", auth.tls_serialize_detached())?);
    Ok(Packet {
        epoch: epoch.as_u64(),
        body: body.as_slice().to_vec(),
        aad,
        sender_offset,
    })
}
pub(super) fn sender(actor: &Actor, bytes: &[u8]) -> Result<SenderData, String> {
    let clear = checked(
        "sender-data positive",
        super::attack::attempt(actor, bytes)?,
    )?;
    ensure(clear.len() == 12, "sender data length")?;
    Ok(SenderData {
        sender: u32::from_be_bytes(checked("sender index", clear[..4].try_into())?),
        generation: u32::from_be_bytes(checked("generation", clear[4..8].try_into())?),
        reuse_guard: checked("reuse guard", clear[8..12].try_into())?,
    })
}
pub(super) fn body(
    actor: &Actor,
    p: &Packet,
    data: SenderData,
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = nonce.to_vec();
    if nonce.len() != 12 || key.len() != 16 {
        return Err(CryptoError::CryptoLibraryError);
    }
    for (n, g) in nonce.iter_mut().zip(data.reuse_guard) {
        *n ^= g;
    }
    actor
        .provider
        .crypto()
        .aead_decrypt(SUITE.aead_algorithm(), key, &p.body, &nonce, &p.aad)
}
pub(super) fn payload(clear: &[u8], expected: &[u8]) -> Result<(), String> {
    let mut input = clear;
    let message = checked(
        "application payload",
        tls_codec::VLBytes::tls_deserialize(&mut input),
    )?;
    ensure(message.as_slice() == expected, "raw payload mismatch")?;
    let signature = checked(
        "application signature",
        tls_codec::VLBytes::tls_deserialize(&mut input),
    )?;
    ensure(
        signature.as_slice().len() == 64 && input.iter().all(|x| *x == 0),
        "signature/padding framing",
    )
}
pub(super) fn rejected(result: Result<Vec<u8>, CryptoError>) -> Result<(), String> {
    match result {
        Err(CryptoError::AeadDecryptionError) => Ok(()),
        Err(_) => Err("unexpected crypto error (not AEAD rejection)".into()),
        Ok(_) => Err("old secret decrypted new ciphertext".into()),
    }
}
