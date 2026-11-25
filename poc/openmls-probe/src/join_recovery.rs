//! 已接受入群入口的有界恢复契约；普通 Add 与本协议保持独立。
pub mod types;
mod validate;
mod verify;
mod version;
pub mod witness;
mod witness_binding;
mod witness_format;
mod witness_policy;
mod witness_types;
mod witness_validate;
mod witness_wire;
#[cfg(test)]
mod witness_wire_tests;
pub use types::*;
pub use verify::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod witness_tests;
use crate::permission::{
    receipts::{self, SignedRecord},
    types as scalar, PermissionError, Proof,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use openmls_traits::signatures::Signer;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

pub const REQUEST_W1_DOMAIN: &[u8] = b"Rocket-IM/POC/recovery-request/v2\0";
pub const CHANGE_W1_DOMAIN: &[u8] = b"Rocket-IM/POC/permission-change/v4\0";
pub const RECEIPT_W1_DOMAIN: &[u8] = b"Rocket-IM/POC/recovery-receipt/v2\0";
pub const REQUEST_DOMAIN: &[u8] = b"Rocket-IM/POC/recovery-request/v1\0";
pub const CHANGE_DOMAIN: &[u8] = b"Rocket-IM/POC/permission-change/v3\0";
pub const RECEIPT_DOMAIN: &[u8] = b"Rocket-IM/POC/recovery-receipt/v1\0";
pub fn require(value: bool, code: &'static str) -> Result<(), PermissionError> {
    if value {
        Ok(())
    } else {
        Err(PermissionError::new(
            code,
            "恢复证据、授权或原件绑定不满足契约",
        ))
    }
}
pub fn raw<T: DeserializeOwned>(encoded: &str) -> Result<T, PermissionError> {
    witness_format::decode(encoded, 16384)
}
pub fn commit_group(encoded: &str) -> Result<String, PermissionError> {
    use openmls::prelude::{tls_codec::Deserialize, MlsMessageIn};
    let message = MlsMessageIn::tls_deserialize_exact(scalar::bytes(encoded, 524288)?)
        .map_err(|_| PermissionError::new("recovery_invalid", "Commit 编码无效"))?;
    let protocol = message
        .try_into_protocol_message()
        .map_err(|_| PermissionError::new("recovery_invalid", "不是群协议消息"))?;
    Ok(STANDARD.encode(protocol.group_id().as_slice()))
}
pub fn sign<T: Serialize>(
    value: &T,
    domain: &[u8],
    signer: &impl Signer,
) -> Result<SignedRecord, PermissionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| PermissionError::new("recovery_invalid", "声明编码失败"))?;
    require(bytes.len() <= 16384, "resource_exhausted")?;
    let mut payload = domain.to_vec();
    payload.extend(&bytes);
    Ok(SignedRecord {
        statement_bytes: STANDARD.encode(bytes),
        signature_bytes: STANDARD.encode(
            signer
                .sign(&payload)
                .map_err(|_| PermissionError::new("recovery_invalid", "声明签名失败"))?,
        ),
    })
}
fn hash(domain: &[u8], fields: &[(&str, usize)]) -> Result<String, PermissionError> {
    let mut hash = Sha256::new();
    hash.update(domain);
    for (encoded, limit) in fields {
        let bytes = scalar::bytes(encoded, *limit)?;
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(format!("{:x}", hash.finalize()))
}
pub fn signed_digest(record: &SignedRecord) -> Result<String, PermissionError> {
    hash(
        b"Rocket-IM/POC/recovery-signed-record/v1\0",
        &[
            (&record.statement_bytes, 16384),
            (&record.signature_bytes, 64),
        ],
    )
}
pub fn candidate_digest(proof: &Proof) -> Result<String, PermissionError> {
    hash(
        b"Rocket-IM/POC/recovery-candidate/v1\0",
        &[
            (&proof.statement_bytes, 16384),
            (&proof.signature_bytes, 64),
            (&proof.commit_bytes, 524288),
        ],
    )
}
pub fn admission_ref(
    change_id: &str,
    proof: &Proof,
    receipt: &SignedRecord,
) -> Result<AdmissionRef, PermissionError> {
    Ok(AdmissionRef {
        change_id: change_id.into(),
        record_sha256: hash(
            b"Rocket-IM/POC/admission-record/v1\0",
            &[
                (&proof.statement_bytes, 16384),
                (&proof.signature_bytes, 64),
                (&proof.commit_bytes, 524288),
                (&receipt.statement_bytes, 16384),
                (&receipt.signature_bytes, 64),
            ],
        )?,
    })
}
pub fn parse_request(proof: &SignedRecord) -> Result<Request, PermissionError> {
    let request: Request = raw(&proof.statement_bytes)?;
    request.validate()?;
    receipts::signature(
        &request.signer().signature_key,
        request.domain()?,
        &scalar::bytes(&proof.statement_bytes, 16384)?,
        &proof.signature_bytes,
    )?;
    Ok(request)
}
pub fn parse_intent(proof: &SignedRecord) -> Result<Intent, PermissionError> {
    match parse_request(proof)? {
        Request::Intent(i) => Ok(*i),
        _ => Err(PermissionError::new("recovery_invalid", "需要目标签名意图")),
    }
}
pub fn verify_receipt(key: &str, proof: &SignedRecord) -> Result<Receipt, PermissionError> {
    let receipt: Receipt = raw(&proof.statement_bytes)?;
    receipt.validate()?;
    receipts::signature(
        key,
        receipt.domain()?,
        &scalar::bytes(&proof.statement_bytes, 16384)?,
        &proof.signature_bytes,
    )?;
    Ok(receipt)
}
