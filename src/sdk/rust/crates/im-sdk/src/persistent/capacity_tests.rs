use super::{data::Saved, tests::Pair, *};

pub(super) fn measured(device: &PersistentDevice) -> Capacity {
    let before = device.database.call(|db| db.read(Ok)).unwrap();
    let result = device.capacity().unwrap();
    let after = device.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(
        operations::fingerprint(&before).unwrap(),
        operations::fingerprint(&after).unwrap()
    );
    assert_eq!(result.scope, before.data.state.scope);
    assert_eq!(result.revision, before.data.state.revision);
    let values = [
        before.data.requests.len(),
        before.data.messages.len(),
        network_count(&before),
        encode(&before.data).unwrap().len(),
        before.crypto.len(),
        encode(&before.meta).unwrap().len(),
        before.meta.history.len(),
        before.meta.archives.len(),
        before.data.transitions.len(),
    ];
    assert_eq!(result.budgets.len(), values.len());
    for (budget, value) in result.budgets.iter().zip(values) {
        assert_eq!(budget.used, value.to_string());
        assert_eq!(
            number(&budget.hard_remaining).unwrap(),
            number(&budget.limit).unwrap().saturating_sub(value as u64)
        );
    }
    assert_eq!(result.reserve.state, "not_enabled");
    assert!(
        result.reserve.ordinary_available.is_none() && result.reserve.protected_remaining.is_none()
    );
    for operation in &result.operations {
        assert_eq!(
            operation.state == CapacityOperationState::Blocked,
            !operation.blockers.is_empty()
        );
    }
    result
}
fn network_count(saved: &Saved) -> usize {
    network::capacity(saved, &metering::EncodedSaved::new(saved).unwrap())
        .unwrap()
        .events
}
fn operation<'a>(v: &'a Capacity, name: &str) -> &'a CapacityOperation {
    v.operations.iter().find(|v| v.operation == name).unwrap()
}

#[test]
fn empty_normal_closed_and_unknown_capacity_preserve_originals() {
    let mut pair = Pair::new();
    let empty = measured(&pair.a);
    assert!(empty.cursors.is_none());
    assert!(operation(&empty, "new_send")
        .blockers
        .contains(&"initialize_required".into()));
    pair.group();
    let normal = measured(&pair.a);
    assert_eq!(
        operation(&normal, "new_send").state,
        CapacityOperationState::RequiresInput
    );
    assert_ne!(normal.observation_id, measured(&pair.a).observation_id);
    recovery_tests::lose_candidate(
        &mut pair.a,
        "unknown",
        Action::Send {
            message_id: "unknown".into(),
            text: "private-capacity-sample".into(),
        },
    );
    let unknown = measured(&pair.a);
    assert_eq!(unknown.recovery.pending, "executing_unknown");
    assert!(operation(&unknown, "recover_pending")
        .blockers
        .contains(&"successor_required".into()));
    assert_eq!(
        operation(&unknown, "retry_request").state,
        CapacityOperationState::RequiresInput
    );
    assert!(
        pair.a
            .recover_request("init".into(), Action::Initialize)
            .unwrap()
            .cached
    );
    assert!(!String::from_utf8(encode(&unknown).unwrap())
        .unwrap()
        .contains("private-capacity-sample"));
    pair.reopen();
    measured(&pair.a);
    pair.a.close().unwrap();
    assert_eq!(pair.a.capacity().unwrap_err().code, "closed");
}

#[test]
fn exact_candidate_bytes_include_crypto_json_and_simultaneous_limits() {
    let mut pair = Pair::new();
    pair.group();
    let mut saved = pair.a.database.call(|db| db.read(Ok)).unwrap();
    let action = Action::Send {
        message_id: "candidate".into(),
        text: "sample".into(),
    };
    operations::prepare(&mut saved, "candidate", &action).unwrap();
    saved.meta.journal = Some(journal::Journal {
        request: "candidate".into(),
        input: action.clone(),
        phase: journal::Phase::Executing,
        seed: None,
        candidate: None,
    });
    let (next, _) = candidate::apply(Box::new(saved.clone()), "candidate", &action).unwrap();
    let candidate = journal::Candidate {
        data: next.data,
        crypto: next.crypto,
    };
    let expected = encode(&candidate).unwrap().len();
    assert!(expected > encode(&candidate.data).unwrap().len() + candidate.crypto.len());
    saved.meta.journal.as_mut().unwrap().candidate = Some(candidate);
    budget_tests::pad_meta(&mut saved, store::MAX_META - 32);
    pair.a
        .database
        .call(move |db| {
            db.update(false, |s| {
                *s = saved;
                Ok(())
            })
        })
        .unwrap();
    let diagnostic = measured(&pair.a);
    assert_eq!(diagnostic.components[0].bytes, expected.to_string());
    assert_eq!(diagnostic.recovery.pending, "complete_candidate");
    assert_eq!(
        operation(&diagnostic, "install_candidate").state,
        CapacityOperationState::NotReserved
    );
    assert!(diagnostic
        .blockers
        .iter()
        .any(|b| b.code == "meta_preflight_limit"));
    assert!(diagnostic
        .blockers
        .iter()
        .any(|b| b.code == "recovery_preflight_limit"));
    assert!(operation(&diagnostic, "first_backup")
        .blockers
        .contains(&"backup_guard_limit".into()));
    pair.a.recover_request("candidate".into(), action).unwrap();
    measured(&pair.a);
}

#[test]
fn capacity_never_observes_uncommitted_sqlite_state() {
    let pair = Pair::new();
    let path = pair
        .a
        .database
        .call(|db| Ok(PathBuf::from(db.connection.path().unwrap())))
        .unwrap();
    let mut reader = PersistentDevice::open(path, pair.a.state().unwrap().scope, false).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            pair.a.database.call(move |db| {
                let tx = db
                    .connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let mut saved = store::load(&tx, &db.scope)?;
                budget_tests::pad_data(&mut saved.data, 4096);
                store::write(&tx, &saved)?;
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                tx.rollback()?;
                Ok(())
            })
        });
        started_rx.recv().unwrap();
        assert_eq!(reader.capacity().unwrap().budgets[0].used, "0");
        release_tx.send(()).unwrap();
        writer.join().unwrap().unwrap();
    });
    measured(&reader);
    reader.close().unwrap();
}
