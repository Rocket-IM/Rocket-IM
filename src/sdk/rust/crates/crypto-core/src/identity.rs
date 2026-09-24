//! 身份和群范围采用固定域与长度前缀；身份可信性仍来自调用方独立固定的公钥。
use crate::{error::require, ErrorCode, Result};
use openmls::prelude::{BasicCredential, Credential, Member};

pub(crate) fn id(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        ErrorCode::InvalidArgument,
    )
}

fn encode(domain: &[u8], fields: &[&str]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u16).to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes
}

pub(crate) fn credential(service: &str, account: &str, device: &str) -> Credential {
    BasicCredential::new(encode(
        b"Rocket-IM/SDK/stage0-identity/v1\0",
        &[service, account, device],
    ))
    .into()
}

pub(crate) fn group_id(service: &str, conversation: &str) -> Vec<u8> {
    encode(b"Rocket-IM/SDK/stage0-group/v1\0", &[service, conversation])
}

pub(crate) fn matches(
    credential: &Credential,
    key: &[u8],
    expected: &Credential,
    expected_key: &[u8],
) -> bool {
    credential == expected && key == expected_key
}

pub(crate) fn members(
    actual: impl Iterator<Item = Member>,
    own: &Credential,
    own_key: &[u8],
    peer: &Credential,
    peer_key: &[u8],
) -> Result<()> {
    let members: Vec<_> = actual.collect();
    require(
        members.len() == 2
            && members
                .iter()
                .filter(|m| matches(&m.credential, &m.signature_key, own, own_key))
                .count()
                == 1
            && members
                .iter()
                .filter(|m| matches(&m.credential, &m.signature_key, peer, peer_key))
                .count()
                == 1,
        ErrorCode::IdentityMismatch,
    )
}
