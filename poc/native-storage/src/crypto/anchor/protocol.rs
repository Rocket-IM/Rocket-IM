//! 沿用旧独立锚 helper 的 wire 契约；签名不证明生产故障域独立。
use crate::model::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const PROTOCOL: &str = "rim-rollback-anchor-1";
pub(crate) const INPUT_LIMIT: usize = 32 * 1024;
pub(crate) const STATEMENT_LIMIT: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scope {
    pub service: String,
    pub account: String,
    pub device: String,
    pub identity_key: String,
    pub store_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Reserve,
    Finish,
    Inspect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Reserved,
    ReservedDuplicate,
    Finished,
    FinishedDuplicate,
    Inspected,
    Conflict,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Closure {
    Rebuilt,
    Cancelled,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub protocol_version: String,
    pub scope: Scope,
    pub challenge: String,
    pub action: Action,
    pub expected_revision: String,
    pub txn: String,
    pub head: String,
    pub target: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    pub protocol_version: String,
    pub scope: Scope,
    pub challenge: String,
    pub request_sha256: String,
    pub action: Action,
    pub status: Status,
    pub head: String,
    pub active_txn: Option<String>,
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure: Option<Closure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Signed {
    pub statement_bytes: String,
    pub signature_bytes: String,
}

pub(crate) fn invalid() -> Error {
    Error::new("anchor_invalid", true)
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn decode_hex(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(bytes)
}

pub(crate) fn random_hex() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::new("anchor_random", true))?;
    Ok(encode_hex(&bytes))
}

pub(crate) fn revision(value: &str) -> Result<u64> {
    crate::model::revision(value).map_err(|_| invalid())
}

fn head(value: &str) -> Result<()> {
    if value != "absent" {
        decode_hex(value)?;
    }
    Ok(())
}

impl Scope {
    pub(crate) fn validate(&self) -> Result<()> {
        for value in [&self.service, &self.account, &self.device] {
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                return Err(invalid());
            }
        }
        decode_hex(&self.identity_key)?;
        decode_hex(&self.store_id)?;
        Ok(())
    }
}

impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL {
            return Err(invalid());
        }
        self.scope.validate()?;
        revision(&self.expected_revision)?;
        decode_hex(&self.challenge)?;
        decode_hex(&self.txn)?;
        head(&self.head)?;
        match self.action {
            Action::Finish => {
                decode_hex(&self.target)?;
            }
            Action::Reserve | Action::Inspect if self.target != "absent" => {
                return Err(invalid());
            }
            _ => {}
        }
        Ok(())
    }
}

impl Response {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL {
            return Err(invalid());
        }
        self.scope.validate()?;
        decode_hex(&self.challenge)?;
        decode_hex(&self.request_sha256)?;
        head(&self.head)?;
        if let Some(txn) = &self.active_txn {
            decode_hex(txn)?;
        }
        revision(&self.revision)?;
        if !matches!(
            (self.action, self.status),
            (_, Status::Conflict)
                | (
                    Action::Reserve,
                    Status::Reserved | Status::ReservedDuplicate
                )
                | (Action::Finish, Status::Finished | Status::FinishedDuplicate)
                | (Action::Inspect, Status::Inspected)
        ) {
            return Err(invalid());
        }
        if self.closure.is_some() {
            return Err(Error::new("anchor_closed", true));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn request() -> Request {
        Request {
            protocol_version: PROTOCOL.into(),
            scope: Scope {
                service: "service".into(),
                account: "alice".into(),
                device: "device".into(),
                identity_key: "01".repeat(32),
                store_id: "02".repeat(32),
            },
            challenge: "03".repeat(32),
            action: Action::Reserve,
            expected_revision: "9007199254740993".into(),
            txn: "04".repeat(32),
            head: "05".repeat(32),
            target: "absent".into(),
        }
    }

    #[test]
    fn canonical_fields_and_unknown_fields_are_enforced() {
        let mut value = request();
        value.validate().unwrap();
        for revision in ["01", "-1", "18446744073709551616", "1.0"] {
            value.expected_revision = revision.into();
            assert!(value.validate().is_err());
        }
        value = request();
        value.scope.account = "alice\n".into();
        assert!(value.validate().is_err());
        assert!(decode_hex(&"AF".repeat(32)).is_err());
        let mut json = serde_json::to_value(request()).unwrap();
        json["unexpected"] = true.into();
        assert!(serde_json::from_value::<Request>(json).is_err());
    }
}
