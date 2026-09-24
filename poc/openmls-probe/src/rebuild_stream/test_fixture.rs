//! 这些单测验证公共签名契约；Commit 为合成字节，实际 MLS/HTTP 由联合测试证明。
use super::*;
use crate::permission::{Member, PermissionCheckpoint, Proof, Statement};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

pub const AUTHOR: [u8; 32] = [81; 32];
pub const SUCCESSOR: [u8; 32] = [82; 32];
pub const SERVICE: [u8; 32] = [83; 32];
pub const ANCHOR: [u8; 32] = [84; 32];

pub fn public(seed: &[u8; 32]) -> String {
    STANDARD.encode(SigningKey::from_bytes(seed).verifying_key().as_bytes())
}

pub fn signed<T: Serialize>(value: &T, domain: &[u8], seed: &[u8; 32]) -> SignedRecord {
    let raw = serde_json::to_vec(value).unwrap();
    let mut message = domain.to_vec();
    message.extend(&raw);
    SignedRecord {
        statement_bytes: STANDARD.encode(raw),
        signature_bytes: STANDARD.encode(SigningKey::from_bytes(seed).sign(&message).to_bytes()),
    }
}

pub fn decoded<T: DeserializeOwned>(record: &SignedRecord) -> T {
    serde_json::from_slice(&STANDARD.decode(&record.statement_bytes).unwrap()).unwrap()
}

fn member(account: &str, device: &str, seed: &[u8; 32]) -> Member {
    Member {
        account_id: account.into(),
        device_id: device.into(),
        signature_key: public(seed),
    }
}

pub fn fixture() -> (Trust, Registration) {
    let old = anchor::Scope {
        service: "S1".into(),
        account: "A".into(),
        device: "A1".into(),
        identity_key: anchor::public_key(&[85; 32]),
        store_id: anchor::hash_bytes(b"old store"),
    };
    let authorizer = member("A", "A2", &AUTHOR);
    let trusted = Trust {
        old_scope: old.clone(),
        anchor_public_key: anchor::public_key(&ANCHOR),
        trust: rebuild::RebuildTrust {
            authorizer: authorizer.clone(),
            checkpoint: PermissionCheckpoint {
                service_id: "S1".into(),
                conversation_id: "G2".into(),
                authorization_version: "9007199254740993".into(),
                crypto_state_ref: anchor::hash_bytes(b"before join"),
                owner_account_id: "B".into(),
                members: vec![authorizer, member("B", "B1", &[86; 32])],
            },
            relay_receipt_key: public(&SERVICE),
        },
    };
    let plan = rebuild::Plan {
        protocol_version: rebuild::PROTOCOL.into(),
        rebuild_id: anchor::hash_bytes(b"rebuild"),
        old_scope: old,
        old_head: anchor::hash_bytes(b"old head"),
        old_txn: anchor::hash_bytes(b"old txn"),
        old_revision: "1".into(),
        old_conversation_id: "G1".into(),
        old_group_id: STANDARD.encode(b"old group"),
        anchor_public_key: trusted.anchor_public_key.clone(),
        successor_scope: anchor::Scope {
            service: "S1".into(),
            account: "A".into(),
            device: "A3".into(),
            identity_key: anchor::public_key(&SUCCESSOR),
            store_id: anchor::hash_bytes(b"new store"),
        },
        successor_head: anchor::hash_bytes(b"new head"),
        successor_client_public_key: anchor::public_key(&[87; 32]),
        key_package_sha256: anchor::hash_bytes(b"new KeyPackage"),
        trust: trusted.trust.clone(),
    };
    let request = rebuild::sign_rebuild_request(
        &plan,
        &anchor::hash_bytes(b"link challenge"),
        rebuild::Action::Link,
        &[88; 32],
    )
    .unwrap();
    let response = rebuild::Response {
        protocol_version: rebuild::PROTOCOL.into(),
        plan_sha256: plan.digest().unwrap(),
        request_sha256: anchor::request_digest(&request).unwrap(),
        challenge: anchor::hash_bytes(b"link challenge"),
        action: rebuild::Action::Link,
        status: rebuild::Status::Linked,
        old_scope: plan.old_scope.clone(),
        old_head: plan.old_head.clone(),
        old_txn: plan.old_txn.clone(),
        old_revision: plan.old_revision.clone(),
        successor_scope: plan.successor_scope.clone(),
        successor_head: plan.successor_head.clone(),
        successor_revision: "0".into(),
        cancelled: false,
    };
    let statement = Statement {
        protocol_version: "rim-permission-1".into(),
        change_id: "join_A3".into(),
        service_id: "S1".into(),
        conversation_id: "G2".into(),
        actor: trusted.trust.authorizer.identity(),
        previous_authorization_version: trusted.trust.checkpoint.authorization_version.clone(),
        authorization_version: "9007199254740994".into(),
        from_state_ref: trusted.trust.checkpoint.crypto_state_ref.clone(),
        to_state_ref: anchor::hash_bytes(b"after join"),
        action: permission::Action::AddDevice {
            member: member("A", "A3", &SUCCESSOR),
            key_package_sha256: plan.key_package_sha256.clone(),
            welcome_sha256: anchor::hash_bytes(b"synthetic Welcome"),
            history_policy: "from_join".into(),
        },
        commit_sha256: anchor::hash_bytes(b"synthetic Commit"),
        nonce: anchor::hash_bytes(b"join nonce"),
        issued_at_unix_secs: "1700000000".into(),
        expires_at_unix_secs: "1700000300".into(),
    };
    let signed_change = signed(&statement, permission::SIGNING_DOMAIN, &AUTHOR);
    let proof = Proof {
        statement_bytes: signed_change.statement_bytes,
        signature_bytes: signed_change.signature_bytes,
        commit_bytes: STANDARD.encode(b"synthetic Commit"),
    };
    let stream_request = RequestStatement {
        protocol_version: "rim-rebuild-stream-request-1".into(),
        plan_sha256: plan.digest().unwrap(),
        successor_scope: plan.successor_scope.clone(),
        conversation_id: "G2".into(),
        stream_id: anchor::hash_bytes(b"new stream"),
        initial_cursor: "0".into(),
        join_proof_sha256: receipts::proof_digest(&proof).unwrap(),
    };
    let receipt = receipts::ReceiptStatement {
        protocol_version: "rim-permission-receipt-1".into(),
        service_id: "S1".into(),
        conversation_id: "G2".into(),
        actor: statement.actor.clone(),
        change_id: statement.change_id.clone(),
        proof_sha256: receipts::proof_digest(&proof).unwrap(),
        outcome: receipts::Outcome::Accepted,
        authorization_version: statement.authorization_version.clone(),
        crypto_state_ref: statement.to_state_ref.clone(),
    };
    let registration = Registration {
        approval: rebuild::sign_approval(&plan, &AUTHOR).unwrap(),
        plan,
        anchor_request: request,
        anchor_response: anchor_response(&response),
        request: signed(&stream_request, REQUEST_DOMAIN, &SUCCESSOR),
        join_record: receipts::RecoveryRecord {
            change: proof,
            receipt: signed(&receipt, receipts::RECEIPT_DOMAIN, &SERVICE),
        },
    };
    (trusted, registration)
}

pub fn anchor_response(value: &rebuild::Response) -> anchor::Signed {
    let record = signed(
        value,
        b"Rockets-IM/POC/anchor-rebuild-response/v1\0",
        &ANCHOR,
    );
    anchor::Signed {
        statement_bytes: record.statement_bytes,
        signature_bytes: record.signature_bytes,
    }
}

pub fn binding(registration: &Registration) -> BindingStatement {
    let request: RequestStatement = decoded(&registration.request);
    BindingStatement {
        protocol_version: "rim-rebuild-stream-binding-1".into(),
        request_sha256: request_digest(&registration.request).unwrap(),
        plan_sha256: request.plan_sha256,
        successor_scope: request.successor_scope,
        conversation_id: request.conversation_id,
        stream_id: request.stream_id,
        initial_cursor: request.initial_cursor,
        join_proof_sha256: request.join_proof_sha256,
    }
}

pub fn pull(binding: &BindingStatement) -> PullStatement {
    PullStatement {
        protocol_version: "rim-rebuild-stream-pull-1".into(),
        service_id: binding.successor_scope.service.clone(),
        conversation_id: binding.conversation_id.clone(),
        successor_scope: binding.successor_scope.clone(),
        stream_id: binding.stream_id.clone(),
        binding_sha256: binding_digest(&signed(binding, BINDING_DOMAIN, &SERVICE)).unwrap(),
        after_seq: "9007199254740993".into(),
        limit: "100".into(),
        challenge: anchor::hash_bytes(b"pull challenge"),
    }
}

pub fn page(pull: &PullStatement, request: &SignedRecord) -> PageStatement {
    PageStatement {
        protocol_version: "rim-rebuild-stream-page-1".into(),
        binding_sha256: pull.binding_sha256.clone(),
        request_sha256: request_digest(request).unwrap(),
        service_id: pull.service_id.clone(),
        conversation_id: pull.conversation_id.clone(),
        successor_scope: pull.successor_scope.clone(),
        stream_id: pull.stream_id.clone(),
        after_seq: pull.after_seq.clone(),
        limit: pull.limit.clone(),
        challenge: pull.challenge.clone(),
        page_sha256: anchor::hash_bytes(b"exact page bytes"),
    }
}

pub fn replace_join(registration: &mut Registration, value: &Statement) {
    let record = signed(value, permission::SIGNING_DOMAIN, &AUTHOR);
    registration.join_record.change.statement_bytes = record.statement_bytes;
    registration.join_record.change.signature_bytes = record.signature_bytes;
    let mut receipt: receipts::ReceiptStatement = decoded(&registration.join_record.receipt);
    receipt.actor = value.actor.clone();
    receipt.proof_sha256 = receipts::proof_digest(&registration.join_record.change).unwrap();
    registration.join_record.receipt = signed(&receipt, receipts::RECEIPT_DOMAIN, &SERVICE);
    let mut request: RequestStatement = decoded(&registration.request);
    request.join_proof_sha256 = receipt.proof_sha256;
    registration.request = signed(&request, REQUEST_DOMAIN, &SUCCESSOR);
}
