use super::*;
use crate::crypto::{
    anchor::client::{Config, ControlTrust},
    engine::Engine,
};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    scope: Scope,
    old: Client,
    slot: State,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "native-rebuild-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let directory = fs::canonicalize(directory).unwrap();
        let scope = Scope {
            service: "service".into(),
            account: "alice".into(),
            device: "alice-new".into(),
        };
        let old = Client::new(Config {
            program: fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
            directory: directory.clone(),
            scope: super::super::protocol::Scope {
                service: scope.service.clone(),
                account: scope.account.clone(),
                device: "alice-old".into(),
                identity_key: "08".repeat(32),
                store_id: "09".repeat(32),
            },
            anchor_public_key: super::super::protocol::encode_hex(
                SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes(),
            ),
            client_seed: "05".repeat(32),
            rebuild_trust: None,
            rebuild_origin: None,
        })
        .unwrap();
        let slot = State {
            stage: "initializing".into(),
            input_hash: "06".repeat(32),
            details: json!({"old_binding":old.fingerprint()}),
        };
        Self {
            path: directory.join("candidate.sqlite"),
            directory,
            scope,
            old,
            slot,
        }
    }
    fn create(&self) -> Store {
        Store::open_rebuild(
            &self.path,
            self.scope.clone(),
            self.old.clone(),
            Some(self.slot.clone()),
        )
        .unwrap()
    }
    fn reopen(&self) -> Store {
        Store::open_rebuild(&self.path, self.scope.clone(), self.old.clone(), None).unwrap()
    }
    fn prepare(&self, engine: &Engine) -> State {
        let mut config = self.old.config.clone();
        config.scope.device = self.scope.device.clone();
        config.scope.identity_key = super::super::protocol::encode_hex(
            &model::decode(&engine.identity().identity_key).unwrap(),
        );
        config.scope.store_id = "10".repeat(32);
        config.client_seed = "11".repeat(32);
        config.rebuild_origin = Some(ControlTrust {
            client_public_key: self.old.client_public_key.clone(),
            fingerprint: self.old.fingerprint(),
        });
        let mut next = self.slot.clone();
        next.stage = "prepared".into();
        next.details["new_config"] = serde_json::to_value(config).unwrap();
        next
    }
    fn initialized(&self) -> (Store, State) {
        let mut store = self.create();
        let engine = Engine::new(&self.scope).unwrap();
        let next = self.prepare(&engine);
        store
            .rebuild_initialize(
                &self.slot,
                candidate(
                    &engine,
                    "initialize",
                    "1",
                    serde_json::to_value(engine.identity()).unwrap(),
                ),
                &next,
                &self.old,
                Fault::None,
            )
            .unwrap();
        (store, next)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}
fn candidate(engine: &Engine, kind: &str, revision: &str, value: Value) -> Candidate {
    Candidate {
        provider: engine.export().unwrap(),
        identity: engine.identity(),
        conversation: engine.conversation(),
        encryptions: "0".into(),
        processed_cursor: "0".into(),
        decryptions: "0".into(),
        outcome: Outcome {
            revision: revision.into(),
            kind: kind.into(),
            cached: false,
            value,
        },
    }
}
fn snapshot(store: &mut Store) -> (String, Option<Reservation>, usize, String, String) {
    transaction::run(
        &mut store.connection,
        TransactionBehavior::Deferred,
        Fault::None,
        |tx| {
            let meta = query::load(tx, &store.scope)?;
            Ok((
                meta.revision,
                query::pending(tx)?,
                meta.provider_bytes,
                meta.processed_cursor,
                meta.download_cursor,
            ))
        },
    )
    .unwrap()
}

fn old_send_candidate(fixture: &Fixture) -> (Store, Client, Request, Reservation, Candidate) {
    use crate::crypto::{contract::Preparation, operations, Metrics};
    let scope = Scope {
        service: fixture.old.scope().service.clone(),
        account: fixture.old.scope().account.clone(),
        device: fixture.old.scope().device.clone(),
    };
    let path = fixture.directory.join("old.sqlite");
    let mut store = Store::open(&path, scope.clone(), true).unwrap();
    let peer = Engine::new(&Scope {
        service: scope.service.clone(),
        account: "bob".into(),
        device: "bob-old-peer".into(),
    })
    .unwrap();
    for (id, action) in [
        ("old-initialize", Action::Initialize {}),
        (
            "old-group",
            Action::CreateGroup {
                conversation: "old-group".into(),
                peer: peer.identity(),
            },
        ),
    ] {
        let request = Request {
            request_id: id.into(),
            action,
            fault: Default::default(),
        };
        let Preparation::Reserved(prepared) = store.prepare(&request).unwrap() else {
            panic!("fresh request unexpectedly cached")
        };
        let (reservation, candidate) =
            operations::compute(&scope, &request, *prepared, &mut Metrics::default()).unwrap();
        store.commit(&request, &reservation, candidate).unwrap();
    }
    let identity = store.inspect().unwrap().identity.unwrap();
    let mut config = fixture.old.config.clone();
    config.scope.identity_key =
        super::super::protocol::encode_hex(&model::decode(&identity.identity_key).unwrap());
    let remote = Client::new(config).unwrap();
    store.bind_anchor(&remote).unwrap();
    let gate = store
        .anchor_begin(&"31".repeat(32), &"32".repeat(32))
        .unwrap();
    // 本地门单元测试模拟已核验的远端 Reserve；真实 helper 验收由独立进程矩阵完成。
    let gate = store.anchor_reserved(&gate, "1").unwrap();
    store.anchor_activate(&gate).unwrap();
    let request = Request {
        request_id: "old-send".into(),
        action: Action::Send {
            attempt_id: "old-attempt".into(),
            message_id: "old-message".into(),
            text: "old synthetic content".into(),
        },
        fault: Default::default(),
    };
    let Preparation::Reserved(prepared) = store.prepare(&request).unwrap() else {
        panic!("fresh send unexpectedly cached")
    };
    let (reservation, candidate) =
        operations::compute(&scope, &request, *prepared, &mut Metrics::default()).unwrap();
    (store, remote, request, reservation, candidate)
}

#[test]
fn rebuild_fence_rejects_an_already_computed_old_permit_without_changing_business() {
    let fixture = Fixture::new();
    let (mut late, remote, request, reservation, candidate) = old_send_candidate(&fixture);
    let before = snapshot(&mut late);
    let head = late.anchor_local().unwrap().head;
    let original_gate = late.anchor_local().unwrap().gate.unwrap();
    let path = fixture.directory.join("old.sqlite");
    let mut fencer = Store::open_bound(&path, late.scope.clone(), remote.clone()).unwrap();
    let evidence = fencer.rebuild_fence(&remote).unwrap();
    assert!(evidence["fence"].as_str().is_some());
    assert_ne!(fencer.anchor_local().unwrap().gate.unwrap(), original_gate);
    let slot = State {
        stage: "initializing".into(),
        input_hash: fixture.slot.input_hash.clone(),
        details: json!({"old":evidence}),
    };
    Store::open_rebuild(
        &fixture.path,
        fixture.scope.clone(),
        remote.clone(),
        Some(slot),
    )
    .unwrap()
    .close()
    .unwrap();
    let failure = late.commit(&request, &reservation, candidate).unwrap_err();
    assert_eq!(failure.code, "anchor_local_unresolved");
    assert!(failure.paused);
    assert_eq!(snapshot(&mut late), before);
    assert_eq!(late.anchor_local().unwrap().head, head);
    assert!(late.anchor_local().unwrap().journal.is_none());
    assert_eq!(fencer.rebuild_fence(&remote).unwrap(), evidence);
    late.close().unwrap();
    fencer.close().unwrap();
}

#[test]
fn complete_old_journal_forces_exact_recovery_and_cannot_be_fenced() {
    let fixture = Fixture::new();
    let (mut store, remote, request, reservation, candidate) = old_send_candidate(&fixture);
    store.commit(&request, &reservation, candidate).unwrap();
    let before = snapshot(&mut store);
    let local = store.anchor_local().unwrap();
    assert!(local.journal.is_some());
    let failure = store.rebuild_fence(&remote).unwrap_err();
    assert_eq!(failure.code, "anchor_recovery_required");
    let after = store.anchor_local().unwrap();
    assert_eq!(after.head, local.head);
    assert_eq!(after.gate, local.gate);
    assert_eq!(after.journal, local.journal);
    assert_eq!(snapshot(&mut store), before);
    store.close().unwrap();
}

#[test]
fn slot_reopen_preserves_unresolved_generation_and_rejects_exclusive_create() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let before = snapshot(&mut store);
    assert_eq!(before.0, "0");
    assert_eq!(before.1.as_ref().unwrap().operation, "initialize");
    assert_eq!(before.2, 0);
    assert!(store.rebuild_state().unwrap() == fixture.slot);
    store.close().unwrap();
    assert_eq!(
        Store::open_rebuild(
            &fixture.path,
            fixture.scope.clone(),
            fixture.old.clone(),
            Some(fixture.slot.clone())
        )
        .err()
        .unwrap()
        .code,
        "crypto_store_exists"
    );
    let mut store = fixture.reopen();
    assert_eq!(snapshot(&mut store), before);
    assert_eq!(
        Store::open(&fixture.path, fixture.scope.clone(), false)
            .err()
            .unwrap()
            .code,
        "anchor_required"
    );
    assert_eq!(
        store
            .anchor_begin(&"01".repeat(32), &"02".repeat(32))
            .unwrap_err()
            .code,
        "rebuild_approval_required"
    );
    store.close().unwrap();
}

#[test]
fn initialized_candidate_reopens_same_identity_and_has_zero_history_and_cursors() {
    let fixture = Fixture::new();
    let (mut store, prepared) = fixture.initialized();
    let head = store.anchor_local().unwrap().head;
    let before = snapshot(&mut store);
    assert_eq!(
        (before.0.as_str(), before.3.as_str(), before.4.as_str()),
        ("1", "0", "0")
    );
    assert!(before.1.is_none());
    assert!(before.2 > 0);
    store.close().unwrap();
    let mut store = fixture.reopen();
    assert!(store.rebuild_state().unwrap() == prepared);
    assert_eq!(snapshot(&mut store), before);
    assert_eq!(store.anchor_local().unwrap().head, head);
    let new = new_client(&prepared).unwrap();
    store.close().unwrap();
    let mut bound = Store::open_bound(&fixture.path, fixture.scope.clone(), new).unwrap();
    assert!(bound.rebuild_state().unwrap() == prepared);
    assert_eq!(
        bound.received_anchored("1", &head).unwrap_err().code,
        "rebuild_approval_required"
    );
    bound.close().unwrap();
}

#[test]
fn refused_identity_commit_keeps_slot_and_generation_reservation() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let before = snapshot(&mut store);
    let engine = Engine::new(&fixture.scope).unwrap();
    let prepared = fixture.prepare(&engine);
    let failure = store
        .rebuild_initialize(
            &fixture.slot,
            candidate(
                &engine,
                "initialize",
                "1",
                serde_json::to_value(engine.identity()).unwrap(),
            ),
            &prepared,
            &fixture.old,
            Fault::RefuseCommit,
        )
        .unwrap_err();
    assert_eq!(failure.code, "commit_failed");
    assert!(failure.paused);
    store.close().unwrap();
    let mut reopened = fixture.reopen();
    assert!(reopened.rebuild_state().unwrap() == fixture.slot);
    assert_eq!(snapshot(&mut reopened), before);
    reopened.close().unwrap();
}

#[test]
fn plan_stage_cannot_skip_mutate_origin_or_replace_another_committed_state() {
    let fixture = Fixture::new();
    let (mut store, prepared) = fixture.initialized();
    let head = store.anchor_local().unwrap().head;
    let mut planned = prepared.clone();
    planned.stage = "active".into();
    assert!(store
        .rebuild_replace_state(&prepared, &planned, &fixture.old)
        .is_err());
    planned.stage = "planned".into();
    planned.details["old_binding"] = "changed".into();
    assert_eq!(
        store
            .rebuild_replace_state(&prepared, &planned, &fixture.old)
            .unwrap_err()
            .code,
        "rebuild_plan_conflict"
    );
    planned.details = prepared.details.clone();
    planned.details["plan"] = json!({"id":"fixed-plan"});
    store
        .rebuild_replace_state(&prepared, &planned, &fixture.old)
        .unwrap();
    assert_eq!(store.anchor_local().unwrap().head, head);
    assert_eq!(
        store
            .rebuild_replace_state(&prepared, &planned, &fixture.old)
            .unwrap_err()
            .code,
        "rebuild_state_conflict"
    );
    assert!(store.rebuild_state().unwrap() == planned);
    store.close().unwrap();
}

#[test]
fn unsigned_stage_edit_is_rejected_by_old_and_successor_entries() {
    let fixture = Fixture::new();
    let (mut store, prepared) = fixture.initialized();
    let new = new_client(&prepared).unwrap();
    transaction::run(
        &mut store.connection,
        TransactionBehavior::Immediate,
        Fault::None,
        |tx| {
            let mut altered = prepared.clone();
            altered.stage = "active".into();
            tx.execute(
                "UPDATE rebuild_control SET state_json=?1 WHERE singleton=1",
                [query::serialized(&altered)?],
            )
            .map_err(Error::database)?;
            Ok(())
        },
    )
    .unwrap();
    assert!(store.rebuild_state().is_err());
    store.close().unwrap();
    assert!(Store::open_rebuild(
        &fixture.path,
        fixture.scope.clone(),
        fixture.old.clone(),
        None
    )
    .is_err());
    assert!(Store::open_bound(&fixture.path, fixture.scope.clone(), new).is_err());
}

#[test]
fn valid_old_signature_cannot_transplant_another_successor_configuration() {
    let fixture = Fixture::new();
    let (mut store, prepared) = fixture.initialized();
    let original = new_client(&prepared).unwrap();
    let mut other = prepared.clone();
    other.details["new_config"]["client_seed"] = "12".repeat(32).into();
    let signed = fixture.old.sign_local(&other).unwrap();
    assert!(fixture.old.verify_local::<State>(&signed).unwrap() == other);
    transaction::run(
        &mut store.connection,
        TransactionBehavior::Immediate,
        Fault::None,
        |tx| {
            tx.execute(
                "UPDATE rebuild_control SET state_json=?1 WHERE singleton=1",
                [signed],
            )
            .map_err(Error::database)?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        store.rebuild_state().unwrap_err().code,
        "rebuild_scope_mismatch"
    );
    store.close().unwrap();
    assert!(Store::open_bound(&fixture.path, fixture.scope.clone(), original).is_err());
    assert!(Store::open_rebuild(
        &fixture.path,
        fixture.scope.clone(),
        fixture.old.clone(),
        None
    )
    .is_err());
}

#[test]
fn foreign_control_signer_cannot_advance_a_valid_candidate() {
    let fixture = Fixture::new();
    let (mut store, prepared) = fixture.initialized();
    let mut foreign_config = fixture.old.config.clone();
    foreign_config.client_seed = "13".repeat(32);
    let foreign = Client::new(foreign_config).unwrap();
    let mut next = prepared.clone();
    next.stage = "planned".into();
    let head = store.anchor_local().unwrap().head;
    assert!(store
        .rebuild_replace_state(&prepared, &next, &foreign)
        .is_err());
    assert!(store.rebuild_state().unwrap() == prepared);
    assert_eq!(store.anchor_local().unwrap().head, head);
    store.close().unwrap();
}

#[test]
fn joining_commit_records_exact_provider_result_and_journal_together() {
    use super::super::rebuild_protocol::{Member, Plan, RebuildTrust, PROTOCOL};
    let fixture = Fixture::new();
    let (mut store, mut state) = fixture.initialized();
    let peer_scope = Scope {
        service: fixture.scope.service.clone(),
        account: "alice".into(),
        device: "authorizer".into(),
    };
    let mut peer = Engine::new(&peer_scope).unwrap();
    let bob = Engine::new(&Scope {
        service: fixture.scope.service.clone(),
        account: "bob".into(),
        device: "bob-device".into(),
    })
    .unwrap()
    .identity();
    peer.create_group("new-group", &bob).unwrap();
    let own = transaction::run(
        &mut store.connection,
        TransactionBehavior::Deferred,
        Fault::None,
        |tx| {
            query::load(tx, &fixture.scope)?
                .identity
                .ok_or_else(blocked)
        },
    )
    .unwrap();
    let new = new_client(&state).unwrap();
    let plan = Plan {
        protocol_version: PROTOCOL.into(),
        rebuild_id: "21".repeat(32),
        old_scope: fixture.old.scope().clone(),
        old_head: "22".repeat(32),
        old_txn: "23".repeat(32),
        old_revision: "4".into(),
        old_conversation_id: "old-group".into(),
        old_group_id: model::encode(b"old actual group"),
        anchor_public_key: new.config.anchor_public_key.clone(),
        successor_scope: new.scope().clone(),
        successor_head: store.anchor_local().unwrap().head,
        successor_client_public_key: new.client_public_key.clone(),
        key_package_sha256: model::hash(&model::decode(&own.key_package).unwrap()),
        trust: RebuildTrust {
            authorizer: Member::from_identity(&peer.identity()),
            checkpoint: serde_json::from_value(peer.checkpoint().unwrap()).unwrap(),
            relay_receipt_key: peer.identity().identity_key,
        },
    };
    plan.validate().unwrap();
    for stage in ["planned", "linked"] {
        let mut next = state.clone();
        next.stage = stage.into();
        next.details["plan"] = json!(plan);
        store
            .rebuild_replace_state(&state, &next, &fixture.old)
            .unwrap();
        state = next;
    }
    let request = Request {
        request_id: "rebuild-join".into(),
        action: Action::CreateGroup {
            conversation: "new-group".into(),
            peer: peer.identity(),
        },
        fault: Default::default(),
    };
    assert!(request.action.validate().is_err());
    assert!(validate_join_request(&state, &request).is_ok());
    for changed in 0..6 {
        let mut invalid = request.clone();
        let Action::CreateGroup { conversation, peer } = &mut invalid.action else {
            unreachable!()
        };
        match changed {
            0 => *conversation = "wrong-target".into(),
            1 => peer.service = "wrong-service".into(),
            2 => peer.account = "wrong-account".into(),
            3 => peer.device = "wrong-device".into(),
            4 => peer.identity_key = bob.identity_key.clone(),
            _ => invalid.request_id = "wrong-request".into(),
        }
        assert!(validate_join_request(&state, &invalid).is_err());
    }
    let gate = store
        .anchor_begin_rebuild(&"01".repeat(32), &"02".repeat(32))
        .unwrap();
    let gate = store.anchor_reserved(&gate, "1").unwrap();
    store.anchor_activate(&gate).unwrap();
    let mut joining = state.clone();
    joining.stage = "joining".into();
    let prepared = store
        .rebuild_prepare_join(&state, &joining, &request, &fixture.old)
        .unwrap();
    assert!(store
        .rebuild_prepare_join(&state, &joining, &request, &fixture.old)
        .is_err());
    let mut engine = Engine::restore(&prepared.provider.unwrap(), &fixture.scope).unwrap();
    let members = vec![peer.identity(), bob, engine.identity()];
    let added = peer
        .add_rebuild_member(&engine.identity(), &json!(plan))
        .unwrap();
    let welcome = added["welcome"].as_str().unwrap().to_string();
    engine
        .join_rebuild("new-group", &members, &peer.identity(), &welcome)
        .unwrap();
    let mut joined = joining.clone();
    joined.stage = "joined".into();
    let outcome = store
        .rebuild_join(
            &joining,
            &request,
            candidate(&engine, "create_group", "2", json!({"welcome":welcome})),
            &joined,
            &fixture.old,
            Fault::None,
        )
        .unwrap();
    let local = store.anchor_local().unwrap();
    assert_eq!(
        local.journal.as_ref().unwrap().result.value,
        serde_json::to_value(outcome).unwrap()
    );
    assert_eq!(local.journal.as_ref().unwrap().target, local.head);
    let before = snapshot(&mut store);
    assert_eq!(
        (before.0.as_str(), before.3.as_str(), before.4.as_str()),
        ("2", "0", "0")
    );
    assert!(before.1.is_none());
    let mut active = joined.clone();
    active.stage = "active".into();
    assert!(store
        .rebuild_replace_state(&joined, &active, &fixture.old)
        .is_err());
    store.close().unwrap();
    let mut reopened = fixture.reopen();
    assert!(reopened.rebuild_state().unwrap() == joined);
    assert_eq!(snapshot(&mut reopened), before);
    let journal = reopened.anchor_local().unwrap().journal.unwrap();
    reopened
        .anchor_clear(&journal.gate, &journal.target)
        .unwrap();
    reopened
        .rebuild_replace_state(&joined, &active, &fixture.old)
        .unwrap();
    assert!(reopened.rebuild_state().unwrap() == active);
    let head = reopened.anchor_local().unwrap().head;
    // 重放同一候选曾经合法签名的 linked 控制，不恢复旧 provider，也不能取得业务许可。
    transaction::run(
        &mut reopened.connection,
        TransactionBehavior::Immediate,
        Fault::None,
        |tx| {
            tx.execute(
                "UPDATE rebuild_control SET state_json=?1 WHERE singleton=1",
                [fixture.old.sign_local(&state)?],
            )
            .map_err(Error::database)?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        reopened
            .anchor_begin(&"41".repeat(32), &"42".repeat(32))
            .unwrap_err()
            .code,
        "rebuild_approval_required"
    );
    assert_eq!(reopened.anchor_local().unwrap().head, head);
    reopened.close().unwrap();
}
