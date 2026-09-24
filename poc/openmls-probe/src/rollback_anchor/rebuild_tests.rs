use super::*;
use crate::rollback_anchor::{self as anchor, authority, storage::LockedAnchor};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

const OLD_CLIENT: [u8; 32] = [71; 32];
const NEW_CLIENT: [u8; 32] = [72; 32];
const SOURCE: [u8; 32] = [73; 32];
const ANCHOR: [u8; 32] = [74; 32];

fn member(account: &str, device: &str, seed: &[u8; 32]) -> Member {
    Member {
        account_id: account.into(),
        device_id: device.into(),
        signature_key: STANDARD.encode(decode_hex(&public_key(seed)).unwrap()),
    }
}

fn plan() -> Plan {
    let source = member("a", "a2", &SOURCE);
    Plan {
        protocol_version: PROTOCOL.into(),
        rebuild_id: hash_bytes(b"one rebuild"),
        old_scope: Scope {
            service: "s".into(),
            account: "a".into(),
            device: "a1".into(),
            identity_key: public_key(&[75; 32]),
            store_id: hash_bytes(b"old store"),
        },
        old_head: hash_bytes(b"old snapshot"),
        old_txn: hash_bytes(b"uncertain transaction"),
        old_revision: "1".into(),
        old_conversation_id: "old_group".into(),
        old_group_id: STANDARD.encode(b"old actual MLS group"),
        anchor_public_key: public_key(&ANCHOR),
        successor_scope: Scope {
            service: "s".into(),
            account: "a".into(),
            device: "a3".into(),
            identity_key: public_key(&[76; 32]),
            store_id: hash_bytes(b"new store"),
        },
        successor_head: hash_bytes(b"fresh candidate snapshot"),
        successor_client_public_key: public_key(&NEW_CLIENT),
        key_package_sha256: hash_bytes(b"new real key package"),
        trust: RebuildTrust {
            authorizer: source.clone(),
            checkpoint: PermissionCheckpoint {
                service_id: "s".into(),
                conversation_id: "new_group".into(),
                authorization_version: "1".into(),
                crypto_state_ref: hash_bytes(b"independent new communication state"),
                owner_account_id: "b".into(),
                members: vec![source, member("b", "b1", &[77; 32])],
            },
            relay_receipt_key: STANDARD.encode(decode_hex(&public_key(&[78; 32])).unwrap()),
        },
    }
}

struct Fixture {
    directory: PathBuf,
    plan: Plan,
}

impl Fixture {
    fn new(trusted: bool) -> Self {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rim-rebuild-{}", encode_hex(&random)));
        let plan = plan();
        authority::execute(
            &json!({"op":"init","directory":directory,
            "scope":plan.old_scope,"head":plan.old_head,
            "client_public_key":public_key(&OLD_CLIENT),"anchor_seed":encode_hex(&ANCHOR),
            "rebuild_trust":trusted.then_some(&plan.trust)})
            .to_string(),
        )
        .unwrap();
        let fixture = Self { directory, plan };
        let reserve = fixture.normal_request(false, anchor::Action::Reserve, 1);
        assert_eq!(
            fixture.normal(&reserve, &OLD_CLIENT).unwrap().status,
            anchor::Status::Reserved
        );
        fixture
    }

    fn normal_request(&self, child: bool, action: anchor::Action, number: u8) -> anchor::Request {
        anchor::Request {
            protocol_version: anchor::PROTOCOL.into(),
            scope: if child {
                self.plan.successor_scope.clone()
            } else {
                self.plan.old_scope.clone()
            },
            challenge: hash_bytes(&[number, 1]),
            action,
            expected_revision: if action == anchor::Action::Finish {
                "1"
            } else {
                "0"
            }
            .into(),
            txn: if child {
                hash_bytes(&[number, 2])
            } else {
                self.plan.old_txn.clone()
            },
            head: if child {
                self.plan.successor_head.clone()
            } else {
                self.plan.old_head.clone()
            },
            target: if action == anchor::Action::Finish {
                hash_bytes(&[number, 3])
            } else {
                "absent".into()
            },
        }
    }

    fn normal(
        &self,
        request: &anchor::Request,
        seed: &[u8; 32],
    ) -> Result<anchor::Response, AnchorError> {
        let signed = sign_request(request, seed)?;
        let value = authority::execute(
            &json!({"op":"request","directory":self.directory,"request":signed}).to_string(),
        )?;
        verify_response(
            &serde_json::from_value(value["response"].clone()).unwrap(),
            &public_key(&ANCHOR),
            &signed,
        )
    }

    fn command(&self, plan: &Plan, action: Action) -> Value {
        let op = match action {
            Action::Link => "rebuild",
            Action::Cancel => "cancel_rebuild",
            Action::Inspect => "inspect_rebuild",
        };
        let challenge = hash_bytes(op.as_bytes());
        json!({"op":op,
            "directory":self.directory,"plan":plan,"approval":sign_approval(plan, &SOURCE).unwrap(),
            "client_proof":sign_rebuild_request(plan,&challenge,action,&OLD_CLIENT).unwrap(),
            "challenge":challenge})
    }

    fn call(&self, action: Action) -> Result<Response, AnchorError> {
        let command = self.command(&self.plan, action);
        let value = authority::execute(&command.to_string())?;
        verify_rebuild_response(
            &serde_json::from_value(value["response"].clone()).unwrap(),
            &public_key(&ANCHOR),
            &self.plan,
            &serde_json::from_value(command["client_proof"].clone()).unwrap(),
        )
    }

    fn snapshot(&self) -> Vec<u8> {
        fs::read(self.directory.join("state.enc")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn exact_link_seals_old_state_and_routes_new_client_to_single_child() {
    let fixture = Fixture::new(true);
    let before = fixture.snapshot();
    assert_eq!(
        fixture.call(Action::Inspect).unwrap().status,
        Status::Unlinked
    );
    assert_eq!(fixture.snapshot(), before);
    let result = fixture.call(Action::Link).unwrap();
    assert_eq!(result.status, Status::Linked);
    assert_eq!(result.old_head, fixture.plan.old_head);
    assert_eq!(result.old_txn, fixture.plan.old_txn);
    let old_finish = fixture.normal_request(false, anchor::Action::Finish, 1);
    assert_eq!(
        fixture.normal(&old_finish, &OLD_CLIENT).unwrap().status,
        anchor::Status::Conflict
    );
    assert_eq!(
        fixture
            .normal(
                &fixture.normal_request(false, anchor::Action::Reserve, 1),
                &OLD_CLIENT
            )
            .unwrap()
            .status,
        anchor::Status::Conflict
    );
    let child = fixture.normal_request(true, anchor::Action::Reserve, 4);
    assert_eq!(
        fixture.normal(&child, &OLD_CLIENT).unwrap_err().code,
        "anchor_signature"
    );
    assert_eq!(
        fixture.normal(&child, &NEW_CLIENT).unwrap().status,
        anchor::Status::Reserved
    );
    assert_eq!(
        fixture.normal(&child, &NEW_CLIENT).unwrap().status,
        anchor::Status::ReservedDuplicate
    );
    let finish = fixture.normal_request(true, anchor::Action::Finish, 4);
    assert_eq!(
        fixture.normal(&finish, &NEW_CLIENT).unwrap().status,
        anchor::Status::Finished
    );
    let before = fixture.snapshot();
    let repeated = fixture.call(Action::Link).unwrap();
    assert_eq!(repeated.status, Status::Duplicate);
    assert_eq!(repeated.successor_head, finish.target);
    assert_eq!(repeated.successor_revision, "2");
    assert_eq!(fixture.snapshot(), before);
    let query = fixture.call(Action::Inspect).unwrap();
    assert_eq!(query.status, Status::Linked);
    assert_eq!(query.successor_head, finish.target);
    assert_eq!(fixture.snapshot(), before);
    let old = fixture
        .normal(
            &fixture.normal_request(false, anchor::Action::Inspect, 9),
            &OLD_CLIENT,
        )
        .unwrap();
    assert_eq!(old.active_txn, Some(fixture.plan.old_txn.clone()));
    assert_eq!(old.head, fixture.plan.old_head);
    assert_eq!(old.revision, "1");
}

#[test]
fn no_trust_wrong_fixed_trust_and_old_reservation_mismatch_preserve_snapshot() {
    let untrusted = Fixture::new(false);
    let before = untrusted.snapshot();
    assert_eq!(
        untrusted.call(Action::Link).unwrap_err().code,
        "anchor_rebuild_denied"
    );
    assert_eq!(untrusted.snapshot(), before);
    let fixture = Fixture::new(true);
    let before = fixture.snapshot();
    for field in ["head", "txn", "revision", "anchor", "trust"] {
        let mut plan = fixture.plan.clone();
        match field {
            "head" => plan.old_head = hash_bytes(b"other head"),
            "txn" => plan.old_txn = hash_bytes(b"other txn"),
            "revision" => plan.old_revision = "3".into(),
            "anchor" => plan.anchor_public_key = public_key(&[90; 32]),
            _ => plan.trust.checkpoint.crypto_state_ref = hash_bytes(b"other source state"),
        }
        assert_eq!(
            authority::execute(&fixture.command(&plan, Action::Link).to_string())
                .unwrap_err()
                .code,
            "anchor_rebuild_denied"
        );
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn signed_approval_request_and_challenge_cannot_be_cross_bound() {
    let fixture = Fixture::new(true);
    let before = fixture.snapshot();
    for field in ["approval", "client", "challenge", "action"] {
        let mut command = fixture.command(&fixture.plan, Action::Link);
        match field {
            "approval" => {
                command["approval"] =
                    serde_json::to_value(sign_approval(&fixture.plan, &[91; 32]).unwrap()).unwrap()
            }
            "client" => {
                command["client_proof"] = serde_json::to_value(
                    sign_rebuild_request(
                        &fixture.plan,
                        &hash_bytes(b"link"),
                        Action::Link,
                        &NEW_CLIENT,
                    )
                    .unwrap(),
                )
                .unwrap()
            }
            "challenge" => command["challenge"] = json!(hash_bytes(b"wrong challenge")),
            _ => command["op"] = json!("cancel_rebuild"),
        }
        assert!(authority::execute(&command.to_string()).is_err());
        assert_eq!(fixture.snapshot(), before);
    }
    let command = fixture.command(&fixture.plan, Action::Link);
    let value = authority::execute(&command.to_string()).unwrap();
    let signed = serde_json::from_value(value["response"].clone()).unwrap();
    let other = sign_rebuild_request(
        &fixture.plan,
        &hash_bytes(b"other call"),
        Action::Link,
        &OLD_CLIENT,
    )
    .unwrap();
    assert_eq!(
        verify_rebuild_response(&signed, &public_key(&ANCHOR), &fixture.plan, &other)
            .unwrap_err()
            .code,
        "anchor_response_binding"
    );
}

#[test]
fn cancellation_is_permanent_preserves_active_child_and_prevents_finish() {
    let fixture = Fixture::new(true);
    assert!(fixture.call(Action::Cancel).is_err());
    fixture.call(Action::Link).unwrap();
    let reserve = fixture.normal_request(true, anchor::Action::Reserve, 3);
    fixture.normal(&reserve, &NEW_CLIENT).unwrap();
    assert!(fixture.call(Action::Cancel).unwrap().cancelled);
    let before = fixture.snapshot();
    assert!(fixture.call(Action::Cancel).unwrap().cancelled);
    assert!(fixture.call(Action::Link).unwrap().cancelled);
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(
        fixture
            .normal(
                &fixture.normal_request(true, anchor::Action::Finish, 3),
                &NEW_CLIENT
            )
            .unwrap()
            .status,
        anchor::Status::Conflict
    );
    let inspect = fixture
        .normal(
            &fixture.normal_request(true, anchor::Action::Inspect, 8),
            &NEW_CLIENT,
        )
        .unwrap();
    assert_eq!(inspect.active_txn, Some(reserve.txn));
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn competing_rebuilds_create_only_one_successor_and_never_change_winner() {
    let fixture = Fixture::new(true);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(6));
    let joins: Vec<_> = (0..6)
        .map(|index| {
            let mut plan = fixture.plan.clone();
            plan.rebuild_id = hash_bytes(&[index, 1]);
            plan.successor_scope.store_id = hash_bytes(&[index, 2]);
            let command = fixture.command(&plan, Action::Link).to_string();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                authority::execute(&command)
            })
        })
        .collect();
    let results: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.iter().all(|result| result.is_ok()
        || result
            .as_ref()
            .is_err_and(|e| matches!(e.code, "anchor_busy" | "anchor_rebuild_denied"))));
    let before = fixture.snapshot();
    assert!(fixture.call(Action::Link).is_err());
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn inherited_identity_scope_group_and_oversized_fields_are_rejected() {
    for index in 0..9 {
        let mut plan = plan();
        match index {
            0 => plan.successor_scope.service.push('x'),
            1 => plan.successor_scope.account.push('x'),
            2 => plan.successor_scope.device = plan.old_scope.device.clone(),
            3 => plan.successor_scope.identity_key = plan.old_scope.identity_key.clone(),
            4 => plan.successor_scope.store_id = plan.old_scope.store_id.clone(),
            5 => plan.old_conversation_id = plan.trust.checkpoint.conversation_id.clone(),
            6 => plan.old_group_id = STANDARD.encode([0; 129]),
            7 => plan.successor_scope.device = "x".repeat(129),
            _ => plan.trust.authorizer = plan.trust.checkpoint.members[1].clone(),
        }
        assert!(plan.validate().is_err(), "accepted invalid variant {index}");
    }
}

#[test]
fn successor_identifiers_must_fit_the_real_add_device_contract_before_linking() {
    let fixture = Fixture::new(true);
    let before = fixture.snapshot();
    for invalid_id in ["x".repeat(65), "new device".into(), "新设备".into()] {
        let mut plan = fixture.plan.clone();
        plan.successor_scope.device = invalid_id;
        assert_eq!(plan.validate().unwrap_err().code, "anchor_invalid");
        // 即使输入沿旧范围格式能通过，实际权限协议不接受的ID也必须在认证/保存前拒绝。
        plan.successor_scope.validate().unwrap();
        let mut command = fixture.command(&fixture.plan, Action::Link);
        command["plan"] = serde_json::to_value(&plan).unwrap();
        assert_eq!(
            authority::execute(&command.to_string()).unwrap_err().code,
            "anchor_invalid"
        );
        assert_eq!(fixture.snapshot(), before);
    }
    let mut boundary = fixture.plan.clone();
    boundary.successor_scope.device = "x".repeat(64);
    boundary.validate().unwrap();
}

#[test]
fn persistent_authority_rejects_nested_successors_and_invalid_child_binding() {
    let fixture = Fixture::new(true);
    fixture.call(Action::Link).unwrap();
    let anchor = LockedAnchor::open(&fixture.directory).unwrap();
    let state = anchor.load().unwrap();
    assert!(serde_json::to_vec(&state).unwrap().len() < 16 * 1024);
    let mut nested = state.clone();
    nested.rebuild_link.as_mut().unwrap().child.rebuild_link = state.rebuild_link.clone();
    assert!(nested.validate().is_err());
    let mut wrong = state;
    wrong.rebuild_link.as_mut().unwrap().child.scope.store_id = hash_bytes(b"rebound child");
    assert!(wrong.validate().is_err());
}

#[test]
fn child_compare_and_swap_has_no_new_permission_on_stale_snapshot() {
    let fixture = Fixture::new(true);
    fixture.call(Action::Link).unwrap();
    let reserve = fixture.normal_request(true, anchor::Action::Reserve, 1);
    fixture.normal(&reserve, &NEW_CLIENT).unwrap();
    let finish = fixture.normal_request(true, anchor::Action::Finish, 1);
    fixture.normal(&finish, &NEW_CLIENT).unwrap();
    let before = fixture.snapshot();
    assert_eq!(
        fixture.normal(&reserve, &NEW_CLIENT).unwrap().status,
        anchor::Status::Conflict
    );
    assert_eq!(fixture.snapshot(), before);
}
