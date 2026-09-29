//! 最终拒绝先落盘，真实权限链补齐后才消费同内容后继；每次命令重新加载快照。
#[path = "wire_rejection_boundary_tests.rs"]
mod boundaries;
#[path = "wire_rejection_chain_tests.rs"]
mod chain;
#[path = "wire_rejection_test_support.rs"]
pub(super) mod support;
use super::wire_send_order_test_support::*;
use super::{codec, wire_tests::Fixture};
use crate::{message_rejection, permission::receipts::SignedRecord};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::fs;
use support::*;

#[test]
fn rejection_persists_before_sync_and_only_verified_checkpoint_enables_successor() {
    let (f, key) = setup();
    enable(&f, "B");
    let sent = f.send("B", "M1");
    let (record, cp) = advance(&f, &key, "C");
    let proof = rejection(&body(&sent, &cp, "R1", None), &key);
    let saved = f.call("B", proof.clone());
    assert_eq!(saved["status"], "rejected");
    assert_eq!(saved["duplicate"], false);
    assert_eq!(
        saved["send_order"]["pending"],
        json!({"logical_message_id":"M1","attempt_id":"P1","status":"rejected_awaiting_checkpoint","closure_id":"R1","required_authorization_version":"2","required_crypto_state_ref":cp["crypto_state_ref"]})
    );
    reject(
        &f,
        "B",
        successor("P2", "P1", "R1"),
        "rejection_checkpoint_required",
    );
    reject(&f, "B", next(), "send_order_pending");
    assert_eq!(f.send("B", "M1")["envelope"], sent["envelope"]);
    apply(&f, "B", &record);
    assert_eq!(
        inspect(&f, "B")["send_order"]["pending"]["status"],
        "rejected_awaiting_successor"
    );
    let next_packet = f.call("B", successor("P2", "P1", "R1"));
    assert_eq!(next_packet["reused"], false);
    let header: Value = serde_json::from_slice(
        &codec::decode(next_packet["envelope"]["header_bytes"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(header["authorization_version"], "2");
    assert_eq!(header["crypto_state_ref"], cp["crypto_state_ref"]);
    for accepted in [false, true] {
        if accepted {
            f.call("B", accept(&next_packet, &key, "K1"));
            f.call("B", next());
        }
        let before = fs::read(f.root.join("B/state.enc")).unwrap();
        let pending = inspect(&f, "B")["send_order"].clone();
        let duplicate = f.call("B", proof.clone());
        assert_eq!(duplicate["duplicate"], true);
        assert_eq!(duplicate["send_order"], pending);
        assert!(before == fs::read(f.root.join("B/state.enc")).unwrap());
    }
}

#[test]
fn rejection_first_saved_terminal_wins_in_both_directions() {
    for prior in ["accepted", "closed", "rejected"] {
        let (f, key) = setup();
        enable(&f, "B");
        let sent = f.send("B", "M1");
        let (_, cp) = advance(&f, &key, "C");
        let proof = rejection(&body(&sent, &cp, "R1", None), &key);
        let cancelled = close(&f, &key, "P1", "C1");
        match prior {
            "accepted" => {
                f.call("B", accept(&sent, &key, "K1"));
                reject(&f, "B", proof, "rejection_conflict");
            }
            "closed" => {
                f.call("B", cancelled);
                reject(&f, "B", proof, "rejection_conflict");
            }
            _ => {
                f.call("B", proof);
                reject(&f, "B", cancelled, "rejection_conflict");
                reject(&f, "B", accept(&sent, &key, "K1"), "rejection_conflict");
                reject(
                    &f,
                    "B",
                    json!({"operation":"wire_close_request","logical_message_id":"M1","attempt_id":"P1"}),
                    "rejection_conflict",
                );
            }
        }
    }
}

#[test]
fn rejection_remains_recordable_under_permission_pending_removed_and_consistency_pause() {
    for paused in ["pending", "removed", "consistency"] {
        let (f, key) = setup();
        enable(&f, "A");
        let sent = f.send("A", "M1");
        let target = json!({"authorization_version":"2","crypto_state_ref":"a".repeat(64)});
        match paused {
            "pending" => {
                f.call("A",json!({"operation":"permission_prepare","change_id":"removeC","action":{"kind":"remove_member","account_id":"C"}}));
            }
            "consistency" => {
                f.call("A", json!({"operation":"consistency_challenge"}));
            }
            _ => alter_invalid(&f, "A", |state| {
                state.permissions.recovery.access_removed = true
            }),
        }
        f.call("A", rejection(&body(&sent, &target, "R1", None), &key));
        assert_eq!(
            inspect(&f, "A")["send_order"]["pending"]["status"],
            "rejected_awaiting_checkpoint"
        );
        reject(
            &f,
            "A",
            successor("P2", "P1", "R1"),
            match paused {
                "pending" => "permission_pending",
                "removed" => "access_removed",
                _ => "consistency_paused",
            },
        );
    }
}

#[test]
fn rejection_higher_version_alone_and_future_wrong_branch_do_not_satisfy_floor() {
    for missing in [true, false] {
        let f = Fixture::with_devices(&["A", "B", "C", "D"]);
        let key = SigningKey::from_bytes(&[74; 32]);
        pin(&f, &key);
        enable(&f, "B");
        let sent = f.send("B", "M1");
        let (first, mut cp) = advance(&f, &key, "C");
        if !missing {
            cp["crypto_state_ref"] = json!("0".repeat(64));
        }
        f.call("B", rejection(&body(&sent, &cp, "R1", None), &key));
        apply(&f, "B", &first);
        let (second, _) = advance(&f, &key, "D");
        apply(&f, "B", &second);
        if missing {
            alter_invalid(&f, "B", |state| {
                state.permissions.recovery.verified_refs.remove("2");
            });
        }
        assert_eq!(
            inspect(&f, "B")["configuration"]["authorization_version"],
            "3"
        );
        reject(
            &f,
            "B",
            successor("P2", "P1", "R1"),
            "rejection_checkpoint_required",
        );
    }
}

#[cfg(feature = "wire-send-probe")]
#[test]
fn rejection_storage_retry_and_unsynced_successor_create_zero_messages() {
    use super::wire_send_probe::{calls, reset};
    let (f, key) = setup();
    enable(&f, "B");
    let sent = f.send("B", "M1");
    let (record, cp) = advance(&f, &key, "C");
    reset();
    let proof = rejection(&body(&sent, &cp, "R1", None), &key);
    f.call("B", proof.clone());
    f.call("B", proof);
    f.send("B", "M1");
    reject(
        &f,
        "B",
        successor("P2", "P1", "R1"),
        "rejection_checkpoint_required",
    );
    assert_eq!(calls(), 0);
    apply(&f, "B", &record);
    assert_eq!(calls(), 0);
    f.call("B", successor("P2", "P1", "R1"));
    assert_eq!(calls(), 1);
    reset();
    f.call("B", successor("P2", "P1", "R1"));
    assert_eq!(calls(), 0);
}
