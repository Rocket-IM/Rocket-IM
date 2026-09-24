use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

const CLIENT: [u8; 32] = [61; 32];
const ANCHOR: [u8; 32] = [62; 32];

fn initial() -> State {
    State {
        protocol_version: PROTOCOL.to_owned(),
        scope: Scope {
            service: "s".to_owned(),
            account: "a".to_owned(),
            device: "d".to_owned(),
            identity_key: public_key(&CLIENT),
            store_id: hash_bytes(b"store-a"),
        },
        client_public_key: public_key(&CLIENT),
        anchor_seed: encode_hex(&ANCHOR),
        head: "absent".to_owned(),
        revision: 0,
        active: None,
        last: None,
        rebuild_trust: None,
        rebuild_link: None,
    }
}

fn request(state: &State, action: Action, number: u8) -> Request {
    Request {
        protocol_version: PROTOCOL.to_owned(),
        scope: state.scope.clone(),
        challenge: hash_bytes(&[number, 1]),
        action,
        txn: hash_bytes(&[number]),
        head: state.head.clone(),
        expected_revision: if action == Action::Inspect {
            "0".to_owned()
        } else {
            state.revision.to_string()
        },
        target: if action == Action::Finish {
            hash_bytes(&[number, 2])
        } else {
            "absent".to_owned()
        },
    }
}

#[test]
fn reserve_compare_and_swap_duplicate_and_conflict_preserve_original() {
    let mut state = initial();
    let reserve = request(&state, Action::Reserve, 1);
    assert_eq!(state.apply(&reserve).unwrap(), (Status::Reserved, true));
    let original = serde_json::to_vec(&state).unwrap();
    let mut repeat = reserve.clone();
    repeat.challenge = hash_bytes(b"new challenge does not grant a new permit");
    assert_eq!(
        state.apply(&repeat).unwrap(),
        (Status::ReservedDuplicate, false)
    );
    let conflict = request(&state, Action::Reserve, 2);
    assert_eq!(state.apply(&conflict).unwrap(), (Status::Conflict, false));
    let mut wrong_base = reserve;
    wrong_base.head = hash_bytes(b"old snapshot");
    assert_eq!(state.apply(&wrong_base).unwrap(), (Status::Conflict, false));
    assert_eq!(serde_json::to_vec(&state).unwrap(), original);
}

#[test]
fn finish_requires_exact_active_transaction_and_does_not_release_on_conflict() {
    let mut state = initial();
    state.apply(&request(&state, Action::Reserve, 1)).unwrap();
    let original = serde_json::to_vec(&state).unwrap();
    let wrong = request(&state, Action::Finish, 2);
    assert_eq!(state.apply(&wrong).unwrap(), (Status::Conflict, false));
    let mut finish = request(&state, Action::Finish, 1);
    finish.head = hash_bytes(b"wrong-base");
    assert_eq!(state.apply(&finish).unwrap(), (Status::Conflict, false));
    assert_eq!(serde_json::to_vec(&state).unwrap(), original);
    finish.head = "absent".to_owned();
    assert_eq!(state.apply(&finish).unwrap(), (Status::Finished, true));
    assert_eq!(state.head, finish.target);
    assert!(state.active.is_none());
    assert_eq!(state.revision, 2);
    assert_eq!(
        state.apply(&finish).unwrap(),
        (Status::FinishedDuplicate, false)
    );
    let mut conflicting_target = finish;
    conflicting_target.target = hash_bytes(b"other-target");
    assert_eq!(
        state.apply(&conflicting_target).unwrap(),
        (Status::Conflict, false)
    );
    assert_eq!(
        state.apply(&request(&state, Action::Reserve, 1)).unwrap(),
        (Status::Conflict, false)
    );
}

#[test]
fn unchanged_head_reads_advance_revision_without_reusing_last_transaction() {
    let mut state = initial();
    state.head = hash_bytes(b"read-state");
    state.apply(&request(&state, Action::Reserve, 1)).unwrap();
    let mut finish = request(&state, Action::Finish, 1);
    finish.target = state.head.clone();
    assert_eq!(state.apply(&finish).unwrap(), (Status::Finished, true));
    assert_eq!(state.revision, 2);
    assert_eq!(
        state.apply(&request(&state, Action::Reserve, 1)).unwrap(),
        (Status::Conflict, false)
    );
    assert_eq!(
        state.apply(&request(&state, Action::Reserve, 2)).unwrap(),
        (Status::Reserved, true)
    );
    assert_eq!(
        state.apply(&finish).unwrap(),
        (Status::FinishedDuplicate, false)
    );
    assert_eq!(state.active.as_ref().unwrap().txn, hash_bytes(&[2]));
}

#[test]
fn older_than_last_reserve_replay_is_rejected_even_when_head_is_unchanged() {
    let mut state = initial();
    state.head = hash_bytes(b"stable-read-state");
    let old_reserve = request(&state, Action::Reserve, 1);
    for number in 1..=3 {
        let reserve = request(&state, Action::Reserve, number);
        assert_eq!(state.apply(&reserve).unwrap(), (Status::Reserved, true));
        let mut finish = request(&state, Action::Finish, number);
        finish.target = state.head.clone();
        assert_eq!(state.apply(&finish).unwrap(), (Status::Finished, true));
    }
    let original = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        state.apply(&old_reserve).unwrap(),
        (Status::Conflict, false)
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), original);
}

#[test]
fn reservation_preserves_capacity_to_finish_at_revision_limit() {
    let mut state = initial();
    state.revision = u64::MAX - 1;
    let original = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        state
            .apply(&request(&state, Action::Reserve, 1))
            .unwrap_err()
            .code,
        "anchor_capacity"
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), original);
    state.revision = u64::MAX - 2;
    assert_eq!(
        state.apply(&request(&state, Action::Reserve, 1)).unwrap(),
        (Status::Reserved, true)
    );
    assert_eq!(
        state.apply(&request(&state, Action::Finish, 1)).unwrap(),
        (Status::Finished, true)
    );
    assert_eq!(state.revision, u64::MAX);
}

#[test]
fn revision_exhaustion_and_wrong_scope_do_not_partially_change_state() {
    let mut state = initial();
    state.revision = u64::MAX;
    let original = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        state
            .apply(&request(&state, Action::Reserve, 1))
            .unwrap_err()
            .code,
        "anchor_capacity"
    );
    for index in 0..5 {
        let mut wrong = request(&state, Action::Inspect, 1);
        match index {
            0 => wrong.scope.service.push('x'),
            1 => wrong.scope.account.push('x'),
            2 => wrong.scope.device.push('x'),
            3 => wrong.scope.identity_key = public_key(&ANCHOR),
            _ => wrong.scope.store_id = hash_bytes(b"other-store"),
        }
        assert_eq!(state.apply(&wrong).unwrap_err().code, "anchor_scope");
    }
    assert_eq!(serde_json::to_vec(&state).unwrap(), original);
}

struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut suffix = [0; 16];
        getrandom::getrandom(&mut suffix).unwrap();
        Self {
            directory: std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("rim-anchor-{}", encode_hex(&suffix))),
        }
    }

    fn init(&self) -> Value {
        let state = initial();
        execute(&json!({"op":"init","directory":self.directory,"scope":state.scope,"client_public_key":state.client_public_key,"anchor_seed":state.anchor_seed,"head":state.head}).to_string()).unwrap()
    }

    fn call(&self, request: &Request) -> Result<Response, AnchorError> {
        let signed = sign_request(request, &CLIENT)?;
        let result = execute(
            &json!({"op":"request","directory":self.directory,"request":signed}).to_string(),
        )?;
        let response = serde_json::from_value(result["response"].clone()).unwrap();
        verify_response(&response, &public_key(&ANCHOR), &signed)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.directory.exists() {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }
}

#[test]
fn signed_persisted_authority_round_trip_and_no_reinitialization() {
    let fixture = Fixture::new();
    assert_eq!(fixture.init()["anchor_public_key"], public_key(&ANCHOR));
    let state = initial();
    let reserve = request(&state, Action::Reserve, 1);
    let response = fixture.call(&reserve).unwrap();
    assert_eq!(response.status, Status::Reserved);
    assert_eq!(
        fixture.call(&reserve).unwrap().status,
        Status::ReservedDuplicate
    );
    let snapshot = fs::read(fixture.directory.join("state.enc")).unwrap();
    assert!(!snapshot
        .windows(state.anchor_seed.len())
        .any(|part| part == state.anchor_seed.as_bytes()));
    let wrong_init = json!({"op":"init","directory":fixture.directory,"scope":state.scope,"client_public_key":state.client_public_key,"anchor_seed":state.anchor_seed,"head":state.head});
    assert!(execute(&wrong_init.to_string()).is_err());
    assert_eq!(
        fs::read(fixture.directory.join("state.enc")).unwrap(),
        snapshot
    );
    let response = fixture.call(&request(&state, Action::Inspect, 2)).unwrap();
    assert_eq!(response.active_txn, Some(reserve.txn));
    assert_eq!(response.revision, "1");
    assert_eq!(
        fs::metadata(&fixture.directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for name in ["anchor.key", "state.enc", "writer.lock"] {
        assert_eq!(
            fs::metadata(fixture.directory.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn unavailable_busy_forged_scope_and_corrupt_snapshot_fail_closed() {
    let fixture = Fixture::new();
    let mut inspect = request(&initial(), Action::Inspect, 1);
    assert!(fixture.call(&inspect).is_err());
    assert!(!fixture.directory.exists());
    fixture.init();
    let held = LockedAnchor::open(&fixture.directory).unwrap();
    assert_eq!(fixture.call(&inspect).unwrap_err().code, "anchor_busy");
    drop(held);
    let snapshot = fs::read(fixture.directory.join("state.enc")).unwrap();
    inspect.scope.device.push('x');
    assert_eq!(fixture.call(&inspect).unwrap_err().code, "anchor_scope");
    assert_eq!(
        fs::read(fixture.directory.join("state.enc")).unwrap(),
        snapshot
    );
    let mut corrupt = snapshot;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    fs::write(fixture.directory.join("state.enc"), &corrupt).unwrap();
    assert_eq!(fixture.call(&inspect).unwrap_err().code, "anchor_io");
    assert_eq!(
        fs::read(fixture.directory.join("state.enc")).unwrap(),
        corrupt
    );
}

#[test]
fn simultaneous_reserve_has_only_one_first_success() {
    let fixture = Fixture::new();
    fixture.init();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let joins: Vec<_> = (1..=8)
        .map(|number| {
            let directory = fixture.directory.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let signed =
                    sign_request(&request(&initial(), Action::Reserve, number), &CLIENT).unwrap();
                barrier.wait();
                execute(&json!({"op":"request","directory":directory,"request":signed}).to_string())
                    .map(|value| {
                        verify_response(
                            &serde_json::from_value(value["response"].clone()).unwrap(),
                            &public_key(&ANCHOR),
                            &signed,
                        )
                        .unwrap()
                        .status
                    })
            })
        })
        .collect();
    let results: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Ok(Status::Reserved)))
            .count(),
        1
    );
    assert!(results
        .iter()
        .all(|r| matches!(r, Ok(Status::Reserved | Status::Conflict))
            || r.as_ref().is_err_and(|e| e.code == "anchor_busy")));
    assert_eq!(
        fixture
            .call(&request(&initial(), Action::Inspect, 9))
            .unwrap()
            .revision,
        "1"
    );
}

#[test]
fn oversized_command_and_directory_capacity_reject_without_snapshot_change() {
    assert_eq!(
        execute(&" ".repeat(INPUT_LIMIT + 1)).unwrap_err().code,
        "anchor_invalid"
    );
    let fixture = Fixture::new();
    fixture.init();
    let snapshot = fs::read(fixture.directory.join("state.enc")).unwrap();
    for index in 0..6 {
        fs::write(fixture.directory.join(format!("unexpected-{index}")), b"x").unwrap();
    }
    assert_eq!(
        fixture
            .call(&request(&initial(), Action::Inspect, 1))
            .unwrap_err()
            .code,
        "anchor_capacity"
    );
    assert_eq!(
        fs::read(fixture.directory.join("state.enc")).unwrap(),
        snapshot
    );
}
