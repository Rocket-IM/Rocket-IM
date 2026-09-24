use super::*;
use crate::crypto::anchor::rebuild_remote::{self, Action, Response, Status};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn member(account: &str, device: &str, seed: u8) -> Member {
    Member {
        account_id: account.into(),
        device_id: device.into(),
        signature_key: STANDARD.encode(key(seed).verifying_key().as_bytes()),
    }
}
fn plan() -> Plan {
    let authorizer = member("alice", "source", 51);
    Plan {
        protocol_version: PROTOCOL.into(),
        rebuild_id: "11".repeat(32),
        old_scope: Scope {
            service: "service".into(),
            account: "alice".into(),
            device: "old".into(),
            identity_key: member("alice", "old", 52).identity_key().unwrap(),
            store_id: "12".repeat(32),
        },
        old_head: "13".repeat(32),
        old_txn: "14".repeat(32),
        old_revision: "9007199254740993".into(),
        old_conversation_id: "old_group".into(),
        old_group_id: STANDARD.encode(b"old actual group"),
        anchor_public_key: protocol::encode_hex(key(53).verifying_key().as_bytes()),
        successor_scope: Scope {
            service: "service".into(),
            account: "alice".into(),
            device: "successor".into(),
            identity_key: member("alice", "successor", 54).identity_key().unwrap(),
            store_id: "15".repeat(32),
        },
        successor_head: "16".repeat(32),
        successor_client_public_key: protocol::encode_hex(key(55).verifying_key().as_bytes()),
        key_package_sha256: protocol::hash(b"synthetic public package bytes"),
        trust: RebuildTrust {
            authorizer: authorizer.clone(),
            checkpoint: Checkpoint {
                service_id: "service".into(),
                conversation_id: "new_group".into(),
                authorization_version: "1".into(),
                crypto_state_ref: "17".repeat(32),
                owner_account_id: "alice".into(),
                members: vec![authorizer, member("bob", "peer", 56)],
            },
            relay_receipt_key: STANDARD.encode(key(57).verifying_key().as_bytes()),
        },
    }
}
fn admission(plan: &Plan) -> AddAdmission {
    let identity = Identity {
        service: plan.successor_scope.service.clone(),
        account: plan.successor_scope.account.clone(),
        device: plan.successor_scope.device.clone(),
        identity_key: STANDARD
            .encode(protocol::decode_hex(&plan.successor_scope.identity_key).unwrap()),
        key_package: STANDARD.encode(b"synthetic public package bytes"),
    };
    let mut after = plan.trust.checkpoint.clone();
    after.authorization_version = "2".into();
    after.crypto_state_ref = "18".repeat(32);
    after.members.push(Member::from_identity(&identity));
    after
        .members
        .sort_by(|left, right| left.identity().cmp(&right.identity()));
    AddAdmission {
        plan_sha256: plan.digest().unwrap(),
        checkpoint_before: plan.trust.checkpoint.clone(),
        checkpoint_after: after,
        successor_identity: identity,
        group_id: STANDARD.encode(b"new actual group"),
        welcome_sha256: "19".repeat(32),
        commit_sha256: "1a".repeat(32),
        history_policy: "from_join".into(),
        approver: plan.trust.authorizer.clone(),
    }
}

#[test]
fn plan_rejects_missing_trust_reused_identity_and_unbound_target() {
    let original = plan();
    original.validate().unwrap();
    for variant in 0..12 {
        let mut plan = original.clone();
        match variant {
            0 => {
                plan.trust.checkpoint.members.pop().unwrap();
            }
            1 => plan.trust.authorizer = member("alice", "old", 52),
            2 => plan.old_revision = "0".into(),
            3 => plan.old_revision = "01".into(),
            4 => plan.successor_scope.account = "bob".into(),
            5 => plan.successor_scope.store_id = plan.old_scope.store_id.clone(),
            6 => plan.successor_scope.identity_key = plan.old_scope.identity_key.clone(),
            7 => plan.successor_scope.identity_key = plan.trust.authorizer.identity_key().unwrap(),
            8 => plan.old_conversation_id = plan.trust.checkpoint.conversation_id.clone(),
            9 => plan.trust.checkpoint.members.reverse(),
            10 => plan.trust.relay_receipt_key = STANDARD.encode([0; 32]),
            _ => plan.successor_scope.device = "bad/device".into(),
        }
        assert!(plan.validate().is_err(), "variant {variant}");
    }
    let mut value = serde_json::to_value(original).unwrap();
    value["admin_approved"] = true.into();
    assert!(serde_json::from_value::<Plan>(value).is_err());
}

#[test]
fn approval_binds_full_plan_and_uses_exact_helper_signing_domain() {
    let plan = plan();
    let signed = signatures::sign(&plan, &key(51), APPROVAL_DOMAIN, STATEMENT_LIMIT).unwrap();
    verify_approval(&plan, &signed).unwrap();
    let bytes = approval_signing_bytes(&plan).unwrap();
    assert_eq!(&bytes[..APPROVAL_DOMAIN.len()], APPROVAL_DOMAIN);
    assert_eq!(
        &bytes[APPROVAL_DOMAIN.len()..],
        serde_json::to_vec(&plan).unwrap()
    );
    // helper 以类型声明字段顺序序列化；排序的 Value JSON 不是相同的签名输入。
    assert_ne!(
        serde_json::to_vec(&plan).unwrap(),
        serde_json::to_vec(&serde_json::to_value(&plan).unwrap()).unwrap()
    );
    let wrong_key = signatures::sign(&plan, &key(52), APPROVAL_DOMAIN, STATEMENT_LIMIT).unwrap();
    assert!(verify_approval(&plan, &wrong_key).is_err());
    let wrong_domain =
        signatures::sign(&plan, &key(51), ADMISSION_DOMAIN, STATEMENT_LIMIT).unwrap();
    assert!(verify_approval(&plan, &wrong_domain).is_err());
    for field in [
        "old_head",
        "old_txn",
        "successor_head",
        "key_package_sha256",
        "rebuild_id",
        "successor_client_public_key",
    ] {
        let mut value = serde_json::to_value(&plan).unwrap();
        value[field] = "fe".repeat(32).into();
        let changed: Plan = serde_json::from_value(value).unwrap();
        assert!(verify_approval(&changed, &signed).is_err(), "field {field}");
    }
}

fn response(plan: &Plan, request: &Signed) -> Response {
    let request_value: rebuild_remote::Request = serde_json::from_slice(
        &signatures::decode(&request.statement_bytes, STATEMENT_LIMIT).unwrap(),
    )
    .unwrap();
    Response {
        protocol_version: PROTOCOL.into(),
        plan_sha256: plan.digest().unwrap(),
        request_sha256: protocol::hash(&serde_json::to_vec(request).unwrap()),
        challenge: request_value.challenge,
        action: request_value.action,
        status: Status::Linked,
        old_scope: plan.old_scope.clone(),
        old_head: plan.old_head.clone(),
        old_txn: plan.old_txn.clone(),
        old_revision: plan.old_revision.clone(),
        successor_scope: plan.successor_scope.clone(),
        successor_head: plan.successor_head.clone(),
        successor_revision: "0".into(),
        cancelled: false,
    }
}
fn verify_reply(response: &Response, plan: &Plan, request: &Signed) -> Result<Response> {
    let signed = signatures::sign(
        response,
        &key(53),
        rebuild_remote::RESULT_DOMAIN,
        STATEMENT_LIMIT,
    )?;
    rebuild_remote::verify_response(&signed, &plan.anchor_public_key, plan, request)
}

#[test]
fn rebuild_reply_binds_scope_request_challenge_revision_and_status() {
    let plan = plan();
    let request =
        rebuild_remote::sign_request(&plan, &"21".repeat(32), Action::Link, &key(58)).unwrap();
    let original = response(&plan, &request);
    verify_reply(&original, &plan, &request).unwrap();
    for variant in 0..11 {
        let mut reply = original.clone();
        match variant {
            0 => reply.challenge = "fe".repeat(32),
            1 => reply.request_sha256 = "fe".repeat(32),
            2 => reply.old_scope.store_id = "fe".repeat(32),
            3 => reply.successor_scope.device = "imposter".into(),
            4 => reply.old_head = "fe".repeat(32),
            5 => reply.old_txn = "fe".repeat(32),
            6 => reply.old_revision = "1".into(),
            7 => reply.successor_head = "fe".repeat(32),
            8 => reply.successor_revision = "2".into(),
            9 => reply.status = Status::Unlinked,
            _ => reply.cancelled = true,
        }
        assert!(
            verify_reply(&reply, &plan, &request).is_err(),
            "variant {variant}"
        );
    }
    let replay =
        rebuild_remote::sign_request(&plan, &"22".repeat(32), Action::Link, &key(58)).unwrap();
    assert!(verify_reply(&original, &plan, &replay).is_err());
}

#[test]
fn duplicate_reply_may_report_advanced_child_but_cannot_reset_it() {
    let plan = plan();
    let request =
        rebuild_remote::sign_request(&plan, &"23".repeat(32), Action::Link, &key(58)).unwrap();
    let mut reply = response(&plan, &request);
    reply.status = Status::Duplicate;
    reply.successor_head = "24".repeat(32);
    reply.successor_revision = "9007199254740994".into();
    verify_reply(&reply, &plan, &request).unwrap();
    reply.cancelled = true;
    assert!(verify_reply(&reply, &plan, &request).unwrap().cancelled);
    reply.successor_revision = "0".into();
    assert!(verify_reply(&reply, &plan, &request).is_err());
}

#[test]
fn add_admission_binds_real_join_inputs_and_complete_successor_checkpoint() {
    let plan = plan();
    let original = admission(&plan);
    original.validate(&plan).unwrap();
    let signed = signatures::sign(&original, &key(51), ADMISSION_DOMAIN, STATEMENT_LIMIT).unwrap();
    assert_eq!(verify_admission(&plan, &signed).unwrap(), original);
    assert!(admission_signing_bytes(&original, &plan)
        .unwrap()
        .starts_with(ADMISSION_DOMAIN));
    for variant in 0..10 {
        let mut changed = original.clone();
        match variant {
            0 => changed.plan_sha256 = "fe".repeat(32),
            1 => changed.history_policy = "all_history".into(),
            2 => changed.group_id = plan.old_group_id.clone(),
            3 => changed.successor_identity.key_package = STANDARD.encode(b"other package"),
            4 => changed.successor_identity.device = "other_device".into(),
            5 => {
                changed.checkpoint_after.members.pop().unwrap();
            }
            6 => {
                changed.checkpoint_after.crypto_state_ref =
                    changed.checkpoint_before.crypto_state_ref.clone()
            }
            7 => changed.checkpoint_after.authorization_version = "3".into(),
            8 => changed.approver = member("alice", "old", 52),
            _ => changed.checkpoint_after.conversation_id = "other_group".into(),
        }
        let signed =
            signatures::sign(&changed, &key(51), ADMISSION_DOMAIN, STATEMENT_LIMIT).unwrap();
        assert!(
            verify_admission(&plan, &signed).is_err(),
            "variant {variant}"
        );
    }
}
