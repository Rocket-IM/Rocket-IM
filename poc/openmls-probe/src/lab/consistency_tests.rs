use super::{
    accepted, checkpoint, closed, fail_atomic, prepare, recover, resign, setup, Context, Fixture,
    LockedDevice, SigningKey,
};
use crate::{
    consistency::{HeadStatement, SIGNING_DOMAIN},
    lab::{
        codec,
        consistency_state::{ForkEvidence, HeadEvidence, MAX_CHECKPOINTS, MAX_EVIDENCE},
        state::DeviceState,
        CrashPoint,
    },
    permission::{self, receipts::SignedRecord, Identity, PermissionCheckpoint},
};
use ed25519_dalek::Signer;
use serde_json::{json, Value};
use std::fs;

fn edit(f: &Fixture, device: &str, body: impl FnOnce(&mut DeviceState)) {
    let locked = LockedDevice::open(&f.root.join(device)).unwrap();
    let mut state = locked
        .load(&Context {
            service: "S1".into(),
            account: device.into(),
            device: device.into(),
        })
        .unwrap()
        .unwrap();
    body(&mut state);
    locked.save(&mut state, CrashPoint::None).unwrap();
}
fn inspect(f: &Fixture, device: &str) -> Value {
    f.call(device, json!({"operation":"consistency_inspect"}))
}
fn sign_raw(key: &SigningKey, raw: &[u8], domain: &[u8]) -> SignedRecord {
    let mut message = domain.to_vec();
    message.extend(raw);
    SignedRecord {
        statement_bytes: codec::encode(raw),
        signature_bytes: codec::encode(&key.sign(&message).to_bytes()),
    }
}
fn head(f: &Fixture, key: &SigningKey, device: &str, cp: &PermissionCheckpoint) -> SignedRecord {
    let challenge = f.call(device, json!({"operation":"consistency_challenge"}));
    let s = HeadStatement {
        protocol_version: "rim-consistency-head-1".into(),
        service_id: "S1".into(),
        conversation_id: "G1".into(),
        actor: Identity {
            account_id: device.into(),
            device_id: device.into(),
        },
        challenge: challenge["challenge"].as_str().unwrap().into(),
        checkpoint: cp.clone(),
    };
    sign_raw(key, &serde_json::to_vec(&s).unwrap(), SIGNING_DOMAIN)
}
fn observe(f: &Fixture, device: &str, head: &SignedRecord, resume: bool) -> Value {
    f.call(device,json!({"operation":if resume {"consistency_resume"} else {"consistency_observe_head"},"head":head}))
}

#[test]
fn consistency_challenge_strict_signature_context_and_replay_are_atomic() {
    let (f, key) = setup();
    let cp = checkpoint(&f);
    let original = f.send("B", "cached");
    let good = head(&f, &key, "B", &cp);
    let raw = codec::decode(&good.statement_bytes).unwrap();
    let before = inspect(&f, "B");
    assert_eq!(before["checking"], true);
    f.fails("B",json!({"operation":"wire_send","logical_message_id":"cached","attempt_id":"P1","payload":"synthetic test content"}),"consistency_paused");
    for bad in [
        sign_raw(&key, &raw, b"wrong-domain"),
        sign_raw(&SigningKey::from_bytes(&[37; 32]), &raw, SIGNING_DOMAIN),
    ] {
        fail_atomic(
            &f,
            "B",
            json!({"operation":"consistency_observe_head","head":bad}),
            "consistency_signature",
        );
    }
    for field in ["service_id", "conversation_id", "actor", "challenge"] {
        let mut s: Value = serde_json::from_slice(&raw).unwrap();
        let code = if field == "challenge" {
            "consistency_challenge_required"
        } else {
            "consistency_context"
        };
        s[field] = match field {
            "actor" => json!({"account_id":"C","device_id":"C"}),
            "challenge" => json!("a".repeat(64)),
            _ => json!("other"),
        };
        let bad = sign_raw(&key, &serde_json::to_vec(&s).unwrap(), SIGNING_DOMAIN);
        fail_atomic(
            &f,
            "B",
            json!({"operation":"consistency_observe_head","head":bad}),
            code,
        );
    }
    let mut unknown: Value = serde_json::from_slice(&raw).unwrap();
    unknown["unknown"] = json!(true);
    let mut missing: Value = serde_json::from_slice(&raw).unwrap();
    missing["actor"] = json!({"account_id":"Z","device_id":"Z"});
    let duplicate = String::from_utf8(raw.clone()).unwrap().replacen(
        "{",
        "{\"protocol_version\":\"rim-consistency-head-1\",",
        1,
    );
    for raw in [
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec(&missing).unwrap(),
        duplicate.into_bytes(),
    ] {
        let bad = sign_raw(&key, &raw, SIGNING_DOMAIN);
        fail_atomic(
            &f,
            "B",
            json!({"operation":"consistency_observe_head","head":bad}),
            "invalid_consistency",
        );
    }
    assert_eq!(inspect(&f, "B"), before);
    assert_eq!(observe(&f, "B", &good, false)["paused"], false);
    let next = f.call("B", json!({"operation":"consistency_challenge"}));
    assert_eq!(observe(&f, "B", &good, true)["duplicate"], true);
    assert_eq!(inspect(&f, "B")["challenge"], next["challenge"]);
    let fresh = head(&f, &key, "B", &cp);
    assert_eq!(observe(&f, "B", &fresh, true)["freshness"], "unknown");
    assert_eq!(f.send("B", "cached")["envelope"], original["envelope"]);
}

#[test]
fn consistency_actual_recovery_and_explicit_resume_preserve_other_gates() {
    let (f, key) = setup();
    let old = checkpoint(&f);
    let proof = prepare(&f, "A", "first");
    let next = permission::verify(&old, &proof).unwrap().0;
    let ahead = head(&f, &key, "B", &next);
    assert_eq!(observe(&f, "B", &ahead, false)["status"], "needs_sync");
    recover(&f, "B", &accepted(&key, &proof));
    assert_eq!(inspect(&f, "B")["status"], "needs_sync");
    let matching = head(&f, &key, "B", &next);
    assert_eq!(observe(&f, "B", &matching, false)["paused"], true);
    let matching = head(&f, &key, "B", &next);
    assert_eq!(observe(&f, "B", &matching, true)["paused"], false);
    let lower = head(&f, &key, "B", &old);
    assert_eq!(
        observe(&f, "B", &lower, false)["status"],
        "rollback_detected"
    );
    let matching = head(&f, &key, "B", &next);
    assert_eq!(observe(&f, "B", &matching, true)["paused"], false);
    let a = head(&f, &key, "A", &old);
    observe(&f, "A", &a, true);
    assert_eq!(
        f.call("A", json!({"operation":"permission_inspect"}))["recovery_status"],
        "pending"
    );
    f.fails("A",json!({"operation":"wire_send","logical_message_id":"blocked","attempt_id":"P","payload":"test"}),"permission_pending");
}

#[test]
fn consistency_only_distinct_accepted_successors_prove_permanent_fork() {
    let (f, key) = setup();
    let cp = checkpoint(&f);
    let first = prepare(&f, "A", "first");
    let left = accepted(&key, &first);
    let mut equivalent = first.clone();
    let mut s: Value =
        serde_json::from_slice(&codec::decode(&first.statement_bytes).unwrap()).unwrap();
    s["change_id"] = json!("same_successor");
    s["nonce"] = json!("e".repeat(64));
    resign(&f, "A", &mut equivalent, &s);
    assert_eq!(
        permission::verify(&cp, &first).unwrap().0,
        permission::verify(&cp, &equivalent).unwrap().0
    );
    f.call("B", json!({"operation":"consistency_challenge"}));
    let op = |right: Value| json!({"operation":"consistency_observe_fork","predecessor":cp,"left":left,"right":right});
    fail_atomic(
        &f,
        "B",
        op(json!(accepted(&key, &equivalent))),
        "invalid_consistency",
    );
    fail_atomic(
        &f,
        "B",
        op(json!(closed(&key, &first))),
        "invalid_consistency",
    );
    recover(&f, "A", &closed(&key, &first));
    let second = prepare(&f, "A", "second");
    let right = accepted(&key, &second);
    let fork = op(json!(right));
    assert_eq!(f.call("B", fork.clone())["status"], "fork_detected");
    let own = head(&f, &key, "B", &cp);
    assert_eq!(observe(&f, "B", &own, true)["paused"], true);
    recover(&f, "B", &left);
    assert_eq!(inspect(&f, "B")["status"], "fork_detected");
    let challenge = f.call("B", json!({"operation":"consistency_challenge"}));
    assert_eq!(f.call("B", fork)["duplicate"], true);
    assert_eq!(inspect(&f, "B")["challenge"], challenge["challenge"]);
}

#[test]
fn consistency_old_snapshot_starts_at_actual_current_not_public_history() {
    let (f, key) = setup();
    let initial = checkpoint(&f);
    let proof = prepare(&f, "A", "first");
    let accepted = accepted(&key, &proof);
    recover(&f, "B", &accepted);
    edit(&f, "B", |state| {
        let provider = std::mem::take(&mut state.provider);
        let mut json = serde_json::to_value(&*state).unwrap();
        json["permissions"]
            .as_object_mut()
            .unwrap()
            .remove("consistency");
        *state = serde_json::from_value(json).unwrap();
        state.provider = provider;
    });
    assert_eq!(inspect(&f, "B")["verified_checkpoint_count"], 0);
    f.call("B", json!({"operation":"consistency_challenge"}));
    assert_eq!(inspect(&f, "B")["coverage_from"], "2");
    assert_eq!(inspect(&f, "B")["verified_checkpoint_count"], 1);
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_observe_fork","predecessor":initial,"left":accepted,"right":accepted}),
        "consistency_coverage",
    );
}

#[test]
fn consistency_preflight_saves_detected_local_rollback_before_cached_send() {
    let (f, key) = setup();
    let oldcp = checkpoint(&f);
    let cached = f.send("B", "cached");
    let old = fs::read(f.root.join("B/state.enc")).unwrap();
    let proof = prepare(&f, "A", "first");
    recover(&f, "B", &accepted(&key, &proof));
    let mut index = None;
    edit(&f, "B", |s| {
        index = Some(std::mem::take(&mut s.permissions.consistency));
    });
    fs::write(f.root.join("B/state.enc"), old).unwrap();
    edit(&f, "B", |s| {
        s.permissions.consistency = index.unwrap();
    });
    f.fails("B",json!({"operation":"wire_send","logical_message_id":"cached","attempt_id":"P1","payload":"synthetic test content"}),"consistency_paused");
    let saved = fs::read(f.root.join("B/state.enc")).unwrap();
    assert_eq!(inspect(&f, "B")["status"], "rollback_detected");
    assert_eq!(fs::read(f.root.join("B/state.enc")).unwrap(), saved);
    let head = head(&f, &key, "B", &oldcp);
    let result = observe(&f, "B", &head, true);
    assert_eq!(result["status"], "rollback_detected");
    assert_eq!(result["reason"], inspect(&f, "B")["reason"]);
    edit(&f, "B", |s| {
        assert_eq!(s.wire.outbox.len(), 1);
        assert_eq!(
            serde_json::to_value(&s.wire.outbox.values().next().unwrap().envelope).unwrap(),
            cached["envelope"]
        );
    });
}

#[test]
fn consistency_evidence_and_checkpoint_capacity_never_consume_check_or_r1() {
    {
        let (f, key) = setup();
        let cp = checkpoint(&f);
        let first = prepare(&f, "A", "fork_first");
        recover(&f, "A", &closed(&key, &first));
        let second = prepare(&f, "A", "fork_second");
        recover(&f, "A", &closed(&key, &second));
        let third = prepare(&f, "A", "fork_third");
        f.call("B", json!({"operation":"consistency_challenge"}));
        let evidence = ForkEvidence {
            predecessor: cp.clone(),
            left: accepted(&key, &first),
            right: accepted(&key, &second),
        };
        edit(&f, "B", |state| {
            state.permissions.consistency.forks = vec![evidence; MAX_EVIDENCE];
        });
        fail_atomic(
            &f,
            "B",
            json!({"operation":"consistency_observe_fork","predecessor":cp,
            "left":accepted(&key,&first),"right":accepted(&key,&third)}),
            "resource_exhausted",
        );
        assert_eq!(inspect(&f, "B")["checking"], true);
        assert_eq!(inspect(&f, "B")["fork_evidence_count"], MAX_EVIDENCE);
    }
    let (f, key) = setup();
    let cp = checkpoint(&f);
    let valid = head(&f, &key, "B", &cp);
    let statement: HeadStatement =
        serde_json::from_slice(&codec::decode(&valid.statement_bytes).unwrap()).unwrap();
    edit(&f, "B", |state| {
        for _ in 0..MAX_EVIDENCE {
            let mut previous = statement.clone();
            previous.challenge = "f".repeat(64);
            let head = sign_raw(
                &key,
                &serde_json::to_vec(&previous).unwrap(),
                SIGNING_DOMAIN,
            );
            state.permissions.consistency.heads.push(HeadEvidence {
                head,
                statement: previous,
            });
        }
    });
    fail_atomic(
        &f,
        "B",
        json!({"operation":"consistency_observe_head","head":valid}),
        "resource_exhausted",
    );
    assert_eq!(inspect(&f, "B")["checking"], true);
    // 仅将容量边界装入合成状态；不把这些条目宣传为执行过的 MLS 变更。
    for device in ["A", "B"] {
        edit(&f, device, |state| {
            state.permissions.consistency = Default::default();
            state
                .permissions
                .checkpoint
                .as_mut()
                .unwrap()
                .authorization_version = "5000".into();
            state
                .wire
                .configuration
                .as_mut()
                .unwrap()
                .authorization_version = "5000".into();
            let current = state.permissions.checkpoint.clone().unwrap();
            let c = &mut state.permissions.consistency;
            c.checkpoints.clear();
            c.checkpoints.insert(5000, current.clone());
            if device == "B" {
                for i in 1..MAX_CHECKPOINTS {
                    let mut cp = current.clone();
                    cp.authorization_version = i.to_string();
                    c.checkpoints.insert(i as u64, cp);
                }
            }
        });
    }
    let prepared = prepare(&f, "A", "capacity");
    fail_atomic(
        &f,
        "B",
        json!({"operation":"permission_recover","record":accepted(&key,&prepared)}),
        "resource_exhausted",
    );
    assert_eq!(
        f.call("B", json!({"operation":"permission_inspect"}))["checkpoint"]
            ["authorization_version"],
        "5000"
    );
}
