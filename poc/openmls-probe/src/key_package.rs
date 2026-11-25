//! 有界 MLS 一次性材料协议；不把注册或 Service 目录声明解释为联系人信任。
pub mod directory;
pub mod material;
#[cfg(test)]
mod tests;
use crate::permission::{
    receipts::{self, SignedRecord},
    types, Member, PermissionError,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const REQUEST_DOMAIN: &[u8] = b"Rocket-IM/POC/key-package-request/v1\0";
pub const RECEIPT_DOMAIN: &[u8] = b"Rocket-IM/POC/key-package-receipt/v1\0";
pub const LIMIT: usize = 49152;
pub fn error(code: &'static str) -> PermissionError {
    PermissionError::new(code, "设备目录或一次性材料的绑定、状态或证据不满足协议")
}
pub fn check(value: bool, code: &'static str) -> Result<(), PermissionError> {
    if value {
        Ok(())
    } else {
        Err(error(code))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Directory {
        account_id: String,
        challenge: String,
    },
    Publish {
        packages: Vec<String>,
    },
    Claim {
        target: Member,
        conversation_id: String,
        join_kind: String,
        change_id: String,
        directory_version: String,
        directory_sha256: String,
        authorization_version: String,
        crypto_state_ref: String,
    },
    Retire {
        key_package_sha256: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_version: String,
    pub service_id: String,
    pub request_id: String,
    pub actor: Member,
    pub action: Action,
}
pub fn member(member: &Member) -> Result<(), PermissionError> {
    types::id(&member.account_id)?;
    types::id(&member.device_id)?;
    receipts::validate_key(&member.signature_key).map(|_| ())
}
impl Request {
    pub fn validate(&self) -> Result<(), PermissionError> {
        check(
            self.protocol_version == "rim-key-package-request-1",
            "key_package_invalid",
        )?;
        types::id(&self.service_id)?;
        types::id(&self.request_id)?;
        member(&self.actor)?;
        match &self.action {
            Action::Directory {
                account_id,
                challenge,
            } => {
                types::id(account_id)?;
                types::hash(challenge)?;
            }
            Action::Publish { packages } => {
                check((1..=4).contains(&packages.len()), "key_package_invalid")?;
                let mut seen = std::collections::BTreeSet::new();
                for package in packages {
                    check(
                        seen.insert(types::bytes(package, 8192)?),
                        "key_package_invalid",
                    )?;
                }
            }
            Action::Claim {
                target,
                conversation_id,
                join_kind,
                change_id,
                directory_version,
                directory_sha256,
                authorization_version,
                crypto_state_ref,
            } => {
                member(target)?;
                types::id(conversation_id)?;
                types::id(change_id)?;
                check(
                    matches!(join_kind.as_str(), "add_member" | "add_device"),
                    "key_package_invalid",
                )?;
                check(
                    types::decimal(directory_version)? > 0,
                    "key_package_invalid",
                )?;
                types::decimal(authorization_version)?;
                types::hash(directory_sha256)?;
                types::hash(crypto_state_ref)?;
            }
            Action::Retire { key_package_sha256 } => types::hash(key_package_sha256)?,
        }
        Ok(())
    }
}
pub fn parse(proof: &SignedRecord) -> Result<Request, PermissionError> {
    let raw = types::bytes(&proof.statement_bytes, LIMIT)?;
    let request: Request =
        serde_json::from_slice(&raw).map_err(|_| error("key_package_invalid"))?;
    request.validate()?;
    receipts::signature(
        &request.actor.signature_key,
        REQUEST_DOMAIN,
        &raw,
        &proof.signature_bytes,
    )?;
    Ok(request)
}
pub fn sign(request: &Request, signer: &impl Signer) -> Result<SignedRecord, PermissionError> {
    request.validate()?;
    let raw = serde_json::to_vec(request).map_err(|_| error("key_package_invalid"))?;
    check(raw.len() <= LIMIT, "resource_exhausted")?;
    let mut message = REQUEST_DOMAIN.to_vec();
    message.extend(&raw);
    let proof = SignedRecord {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(
            signer
                .sign(&message)
                .map_err(|_| error("key_package_signature"))?,
        ),
    };
    parse(&proof)?;
    Ok(proof)
}
pub fn digest(record: &SignedRecord) -> Result<String, PermissionError> {
    // 有序结构序列化同时绑定原文及签名；不对签名原文重新编码。
    Ok(crate::permission::commit_digest(
        &serde_json::to_vec(record).map_err(|_| error("key_package_invalid"))?,
    ))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResultBody {
    Directory {
        challenge: String,
        snapshots: Vec<String>,
    },
    Published {
        hashes: Vec<String>,
        inventory_version: String,
    },
    Allocated {
        key_package: String,
        key_package_sha256: String,
        inventory_version: String,
        allocated_at_ms: String,
    },
    Unavailable {
        inventory_version: String,
    },
    Retired {
        key_package_sha256: String,
        inventory_version: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub protocol_version: String,
    pub service_id: String,
    pub request_sha256: String,
    pub result: ResultBody,
}
impl Receipt {
    pub fn validate(&self) -> Result<(), PermissionError> {
        check(
            self.protocol_version == "rim-key-package-receipt-1",
            "key_package_invalid",
        )?;
        types::id(&self.service_id)?;
        types::hash(&self.request_sha256)?;
        match &self.result {
            ResultBody::Directory {
                challenge,
                snapshots,
            } => {
                types::hash(challenge)?;
                check((1..=16).contains(&snapshots.len()), "key_package_invalid")?;
                for snapshot in snapshots {
                    directory::parse(snapshot)?;
                }
            }
            ResultBody::Published {
                hashes,
                inventory_version,
            } => {
                check((1..=4).contains(&hashes.len()), "key_package_invalid")?;
                for hash in hashes {
                    types::hash(hash)?;
                }
                types::decimal(inventory_version)?;
            }
            ResultBody::Allocated {
                key_package,
                key_package_sha256,
                inventory_version,
                allocated_at_ms,
            } => {
                let raw = types::bytes(key_package, 8192)?;
                types::hash(key_package_sha256)?;
                check(
                    crate::permission::commit_digest(&raw) == *key_package_sha256,
                    "key_package_invalid",
                )?;
                types::decimal(inventory_version)?;
                types::decimal(allocated_at_ms)?;
            }
            ResultBody::Unavailable { inventory_version } => {
                types::decimal(inventory_version)?;
            }
            ResultBody::Retired {
                key_package_sha256,
                inventory_version,
            } => {
                types::hash(key_package_sha256)?;
                types::decimal(inventory_version)?;
            }
        }
        Ok(())
    }
}
pub fn verify_receipt(key: &str, record: &SignedRecord) -> Result<Receipt, PermissionError> {
    let raw = types::bytes(&record.statement_bytes, LIMIT)?;
    let receipt: Receipt =
        serde_json::from_slice(&raw).map_err(|_| error("key_package_invalid"))?;
    receipt.validate()?;
    receipts::signature(key, RECEIPT_DOMAIN, &raw, &record.signature_bytes)?;
    Ok(receipt)
}
pub(crate) fn execute(input: &str) -> Result<Value, PermissionError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        operation: String,
        proof: Option<SignedRecord>,
        key_package: Option<String>,
        service_id: Option<String>,
        owner: Option<Member>,
    }
    let input: Input = serde_json::from_str(input).map_err(|_| error("key_package_invalid"))?;
    let result = match input.operation.as_str() {
        "verify_key_package_request" => {
            json!({"statement":parse(&input.proof.ok_or_else(||error("key_package_invalid"))?)?})
        }
        "verify_key_package" => {
            json!({"material":material::inspect(&input.key_package.ok_or_else(||error("key_package_invalid"))?, &input.service_id.ok_or_else(||error("key_package_invalid"))?, &input.owner.ok_or_else(||error("key_package_invalid"))?)?})
        }
        _ => return Err(error("key_package_invalid")),
    };
    Ok(json!({"ok":true,"result":result}))
}
