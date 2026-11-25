use super::{
    super::{
        tests::{send, Pair},
        types::*,
    },
    types::*,
};
fn attach(pair: &mut Pair) {
    let peer = pair.a.state().unwrap().identity.unwrap();
    pair.b
        .database
        .call(move |db| {
            db.update(false, |s| {
                s.data.network = Some(NetworkData::new(Binding {
                    url: "wss://127.0.0.1:1/v1/ws".into(),
                    ca_hash: "01".repeat(32),
                    conversation: "chat".into(),
                    peer,
                    creator: false,
                }));
                Ok(())
            })
        })
        .unwrap();
}
fn event(envelope: Envelope) -> Event {
    Event {
        sequence: "1".into(),
        kind: "message".into(),
        acceptance: Acceptance {
            request_id: "s1".into(),
            message_id: envelope.message_id.clone(),
            sequence: "1".into(),
            envelope_hash: hash(&encode(&envelope).unwrap()),
        },
        envelope: Some(envelope),
    }
}
#[test]
fn downloaded_ciphertext_survives_restart_and_processing_commits_with_crypto() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let envelope = send(&mut p.a, "s1");
    let entry = event(envelope.clone());
    p.b.database
        .call(move |db| {
            db.update(false, |s| {
                let mut n = s.data.network.take().unwrap();
                n.download(
                    &s.data,
                    Page {
                        after: "0".into(),
                        upper: "1".into(),
                        next: "1".into(),
                        events: vec![entry],
                    },
                )?;
                s.data.network = Some(n);
                Ok(())
            })
        })
        .unwrap();
    assert_eq!(p.b.state().unwrap().received_count, "0");
    p.reopen();
    p.b.execute(
        "network-receive-1".into(),
        Action::Receive {
            envelope: envelope.clone(),
        },
    )
    .unwrap();
    let saved = p.b.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(saved.data.network.unwrap().processed, "1");
    assert_eq!(saved.data.messages.len(), 1);
    p.reopen();
    assert!(
        p.b.execute("network-receive-1".into(), Action::Receive { envelope })
            .unwrap()
            .cached
    );
}
#[test]
fn malformed_pages_and_tampering_keep_download_cursor() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let envelope = send(&mut p.a, "s1");
    for variant in 0..5 {
        let mut e = event(envelope.clone());
        let mut upper = "1".to_string();
        let mut next = "1".to_string();
        match variant {
            0 => e.sequence = "2".into(),
            1 => e.envelope.as_mut().unwrap().ciphertext = "aabb".into(),
            2 => upper = "0".into(),
            3 => next = "2".into(),
            _ => e.envelope.as_mut().unwrap().sender_account = "intruder".into(),
        }
        let result = p.b.database.call(move |db| {
            db.update(false, |s| {
                let mut n = s.data.network.take().unwrap();
                n.download(
                    &s.data,
                    Page {
                        after: "0".into(),
                        upper,
                        next,
                        events: vec![e],
                    },
                )?;
                s.data.network = Some(n);
                Ok(())
            })
        });
        assert!(result.is_err());
        let saved = p.b.database.call(|db| db.read(Ok)).unwrap();
        assert!(saved.data.network.unwrap().events.is_empty());
    }
}
#[test]
fn acceptance_is_bound_to_exact_persisted_request_and_ciphertext() {
    let mut p = Pair::new();
    p.group();
    let envelope = send(&mut p.a, "s1");
    let saved = p.a.database.call(|db| db.read(Ok)).unwrap();
    let ack = event(envelope).acceptance;
    super::ledger::validate_ack(&saved.data, &ack).unwrap();
    for change in 0..4 {
        let mut bad = ack.clone();
        match change {
            0 => bad.request_id = "other".into(),
            1 => bad.envelope_hash = "00".repeat(32),
            2 => bad.message_id = "other".into(),
            _ => bad.sequence = "0".into(),
        };
        assert!(super::ledger::validate_ack(&saved.data, &bad).is_err())
    }
}

#[test]
#[cfg(feature = "network")]
fn binding_is_rechecked_against_current_transaction_not_pre_tls_snapshot() {
    let mut p = Pair::new();
    p.a.execute("init".into(), Action::Initialize).unwrap();
    p.b.execute("init".into(), Action::Initialize).unwrap();
    let peer = p.a.state().unwrap().identity.unwrap();
    let first = Binding {
        url: "wss://127.0.0.1:1/v1/ws".into(),
        ca_hash: "01".repeat(32),
        conversation: "chat".into(),
        peer,
        creator: false,
    };
    let expected = first.clone();
    p.b.database
        .call(move |db| db.update(false, |s| super::ledger::bind(&mut s.data, first)))
        .unwrap();
    let mut stale = expected.clone();
    stale.url = "wss://127.0.0.1:2/v1/ws".into();
    let error =
        p.b.database
            .call(move |db| db.update(false, |s| super::ledger::bind(&mut s.data, stale)))
            .unwrap_err();
    assert_eq!(error.code, "network_binding_mismatch");
    let saved = p.b.database.call(|db| db.read(Ok)).unwrap();
    assert!(saved.data.network.unwrap().binding == Some(expected));
}
#[test]
fn delivered_marker_requires_a_processed_receipt_event() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let envelope = send(&mut p.b, "s1");
    let ack = event(envelope).acceptance;
    let error =
        p.b.database
            .call(move |db| {
                db.update(false, |s| {
                    let n = s.data.network.as_mut().unwrap();
                    n.accepted.insert(ack.message_id.clone(), ack.clone());
                    n.delivered.insert(ack.message_id);
                    Ok(())
                })
            })
            .unwrap_err();
    assert_eq!(error.code, "network_store_invalid");
    let saved = p.b.database.call(|db| db.read(Ok)).unwrap();
    assert!(saved.data.network.unwrap().accepted.is_empty());
}
