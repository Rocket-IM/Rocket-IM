//! 全量候选快照与原始字节链；逐项注册证明不等于账号授权根。
use super::{check, error};
use crate::permission::{receipts::SignedRecord, types, PermissionError};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub status: String,
    pub registration: SignedRecord,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub protocol_version: String,
    pub service_id: String,
    pub account_id: String,
    pub version: String,
    pub previous_sha256: String,
    pub authorization_source: String,
    pub devices: Vec<Entry>,
}
pub fn parse(encoded: &str) -> Result<Snapshot, PermissionError> {
    let snapshot: Snapshot = serde_json::from_slice(&types::bytes(encoded, 16384)?)
        .map_err(|_| error("directory_invalid"))?;
    check(
        snapshot.protocol_version == "rim-device-directory-1"
            && snapshot.authorization_source == "synthetic-registration-poc",
        "directory_source",
    )?;
    types::id(&snapshot.service_id)?;
    types::id(&snapshot.account_id)?;
    types::hash(&snapshot.previous_sha256)?;
    check(
        (1..=16).contains(&types::decimal(&snapshot.version)?)
            && (1..=8).contains(&snapshot.devices.len()),
        "directory_invalid",
    )?;
    let mut last = String::new();
    let mut keys = std::collections::BTreeSet::new();
    for entry in &snapshot.devices {
        let registered = crate::device_registration::verify_proof(&entry.registration)?;
        check(
            registered.service_id == snapshot.service_id
                && registered.account_id == snapshot.account_id
                && registered.device_id > last
                && keys.insert(registered.signature_key)
                && matches!(entry.status.as_str(), "active" | "revoked"),
            "directory_invalid",
        )?;
        last = registered.device_id;
    }
    Ok(snapshot)
}
pub fn hash(encoded: &str) -> Result<String, PermissionError> {
    Ok(crate::permission::commit_digest(&types::bytes(
        encoded, 16384,
    )?))
}
pub fn successor(previous: &Snapshot, next: &Snapshot) -> Result<(), PermissionError> {
    check(
        previous.service_id == next.service_id
            && previous.account_id == next.account_id
            && types::decimal(&previous.version)?.checked_add(1)
                == Some(types::decimal(&next.version)?),
        "directory_gap",
    )?;
    for entry in &previous.devices {
        check(
            next.devices.iter().any(|new| {
                new.registration == entry.registration
                    && (entry.status != "revoked" || new.status == "revoked")
            }),
            "directory_omission",
        )?;
    }
    Ok(())
}
