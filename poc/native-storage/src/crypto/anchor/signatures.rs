//! wire 签名域与旧 helper 一致；本地恢复记录采用独立域和更大有界载荷。
use super::protocol::{self, Request, Response, Signed, STATEMENT_LIMIT};
use crate::model::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{de::DeserializeOwned, Serialize};

const REQUEST_DOMAIN: &[u8] = b"Rockets-IM/POC/rollback-anchor-request/v1\0";
const RESPONSE_DOMAIN: &[u8] = b"Rockets-IM/POC/rollback-anchor-response/v1\0";
pub(crate) const LOCAL_DOMAIN: &[u8] = b"Rockets-IM/native-anchor-journal/v1\0";
pub(crate) const LOCAL_LIMIT: usize = 256 * 1024;
pub(crate) const LOCAL_JSON_LIMIT: usize = 512 * 1024;

pub(crate) fn decode(value: &str, limit: usize) -> Result<Vec<u8>> {
    if value.len() > limit.div_ceil(3) * 4 {
        return Err(protocol::invalid());
    }
    let bytes = STANDARD.decode(value).map_err(|_| protocol::invalid())?;
    if bytes.len() > limit || STANDARD.encode(&bytes) != value {
        return Err(protocol::invalid());
    }
    Ok(bytes)
}

pub(crate) fn sign<T: Serialize>(
    value: &T,
    key: &SigningKey,
    domain: &[u8],
    limit: usize,
) -> Result<Signed> {
    let raw = serde_json::to_vec(value).map_err(|_| protocol::invalid())?;
    if raw.len() > limit {
        return Err(protocol::invalid());
    }
    let mut message = domain.to_vec();
    message.extend(&raw);
    Ok(Signed {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(key.sign(&message).to_bytes()),
    })
}

pub(crate) fn verify<T: DeserializeOwned>(
    signed: &Signed,
    key: &str,
    domain: &[u8],
    limit: usize,
) -> Result<T> {
    let raw = decode(&signed.statement_bytes, limit)?;
    let signature = Signature::from_slice(&decode(&signed.signature_bytes, 64)?)
        .map_err(|_| protocol::invalid())?;
    let key =
        VerifyingKey::from_bytes(&protocol::decode_hex(key)?).map_err(|_| protocol::invalid())?;
    if key.is_weak() {
        return Err(Error::new("anchor_signature", true));
    }
    let mut message = domain.to_vec();
    message.extend(&raw);
    key.verify_strict(&message, &signature)
        .map_err(|_| Error::new("anchor_signature", true))?;
    serde_json::from_slice(&raw).map_err(|_| protocol::invalid())
}

pub(crate) fn sign_request(request: &Request, key: &SigningKey) -> Result<Signed> {
    request.validate()?;
    sign(request, key, REQUEST_DOMAIN, STATEMENT_LIMIT)
}

pub(crate) fn verify_response(signed: &Signed, key: &str, request: &Signed) -> Result<Response> {
    let response: Response = verify(signed, key, RESPONSE_DOMAIN, STATEMENT_LIMIT)?;
    response.validate()?;
    let original: Request =
        serde_json::from_slice(&decode(&request.statement_bytes, STATEMENT_LIMIT)?)
            .map_err(|_| protocol::invalid())?;
    original.validate()?;
    let hash = protocol::hash(&serde_json::to_vec(request).map_err(|_| protocol::invalid())?);
    if response.request_sha256 != hash
        || response.challenge != original.challenge
        || response.scope != original.scope
        || response.action != original.action
    {
        return Err(Error::new("anchor_response_binding", true));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::anchor::protocol::{tests::request, Closure, Status};
    use serde_json::{json, Value};

    #[test]
    fn signed_response_binds_challenge_request_and_closure() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let public = protocol::encode_hex(key.verifying_key().as_bytes());
        let request = request();
        let signed_request = sign_request(&request, &key).unwrap();
        let mut response = Response {
            protocol_version: protocol::PROTOCOL.into(),
            scope: request.scope.clone(),
            challenge: request.challenge.clone(),
            request_sha256: protocol::hash(&serde_json::to_vec(&signed_request).unwrap()),
            action: request.action,
            status: Status::Reserved,
            head: request.head.clone(),
            active_txn: Some(request.txn.clone()),
            revision: "9007199254740994".into(),
            closure: None,
        };
        let signed = sign(&response, &key, RESPONSE_DOMAIN, STATEMENT_LIMIT).unwrap();
        assert!(verify_response(&signed, &public, &signed_request).is_ok());
        response.challenge = "ff".repeat(32);
        let signed = sign(&response, &key, RESPONSE_DOMAIN, STATEMENT_LIMIT).unwrap();
        let error = verify_response(&signed, &public, &signed_request)
            .err()
            .unwrap();
        assert_eq!(error.code, "anchor_response_binding");
        assert!(error.paused);
        response.challenge = request.challenge;
        response.request_sha256 = "ff".repeat(32);
        let signed = sign(&response, &key, RESPONSE_DOMAIN, STATEMENT_LIMIT).unwrap();
        assert_eq!(
            verify_response(&signed, &public, &signed_request)
                .err()
                .unwrap()
                .code,
            "anchor_response_binding"
        );
        response.request_sha256 = protocol::hash(&serde_json::to_vec(&signed_request).unwrap());
        response.closure = Some(Closure::Rebuilt);
        let signed = sign(&response, &key, RESPONSE_DOMAIN, STATEMENT_LIMIT).unwrap();
        assert_eq!(
            verify_response(&signed, &public, &signed_request)
                .err()
                .unwrap()
                .code,
            "anchor_closed"
        );
    }

    #[test]
    fn local_signature_rejects_tampering_wrong_domain_and_oversize() {
        let key = SigningKey::from_bytes(&[41; 32]);
        let public = protocol::encode_hex(key.verifying_key().as_bytes());
        let mut signed = sign(&json!({"result":"中文"}), &key, LOCAL_DOMAIN, LOCAL_LIMIT).unwrap();
        let read: Value = verify(&signed, &public, LOCAL_DOMAIN, LOCAL_LIMIT).unwrap();
        assert_eq!(read["result"], "中文");
        assert!(verify::<Value>(&signed, &public, REQUEST_DOMAIN, LOCAL_LIMIT).is_err());
        signed.statement_bytes = STANDARD.encode(br#"{"result":"changed"}"#);
        assert!(verify::<Value>(&signed, &public, LOCAL_DOMAIN, LOCAL_LIMIT).is_err());
        assert!(sign(&"x".repeat(LOCAL_LIMIT), &key, LOCAL_DOMAIN, LOCAL_LIMIT).is_err());
        assert!(decode("YQ", 10).is_err());
        assert!(decode("YQ==", 0).is_err());
    }
}
