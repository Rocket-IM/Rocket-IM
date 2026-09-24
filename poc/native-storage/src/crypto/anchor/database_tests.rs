use super::*;
use crate::crypto::{
    contract::{Action, DownloadRecord, DownloadRequest, Fault as CryptoFault, Request, Scope},
    model::{Envelope, Identity},
    Client as CryptoClient, MemoryPeer,
};
use ed25519_dalek::SigningKey;
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
    client: Client,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "native-anchor-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let directory = fs::canonicalize(directory).unwrap();
        let path = directory.join("state.sqlite");
        let scope = Scope {
            service: "test-service".into(),
            account: "alice".into(),
            device: "alice-device".into(),
        };
        let mut crypto = CryptoClient::open(path.clone(), scope.clone(), true).unwrap();
        let initialized = crypto.execute(Request {
            request_id: "init".into(),
            action: Action::Initialize {},
            fault: CryptoFault::None,
        });
        assert!(initialized.ok);
        let identity: Identity =
            serde_json::from_value(initialized.result.unwrap()["value"].clone()).unwrap();
        let peer_scope = Scope {
            service: scope.service.clone(),
            account: "bob".into(),
            device: "bob-device".into(),
        };
        let peer = MemoryPeer::new(&peer_scope).unwrap();
        assert!(
            crypto
                .execute(Request {
                    request_id: "group".into(),
                    action: Action::CreateGroup {
                        conversation: "group".into(),
                        peer: peer.identity()
                    },
                    fault: CryptoFault::None
                })
                .ok
        );
        assert!(
            crypto
                .download(DownloadRequest {
                    records: vec![DownloadRecord {
                        sequence: "1".into(),
                        envelope: Envelope {
                            service: scope.service.clone(),
                            conversation: "group".into(),
                            sender_account: "bob".into(),
                            sender_device: "bob-device".into(),
                            message_id: "downloaded".into(),
                            ciphertext: "AQ==".into(),
                        }
                    }],
                    fault: CryptoFault::None
                })
                .ok
        );
        assert!(crypto.close().ok);
        let config = super::super::client::Config {
            program: fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
            directory: directory.clone(),
            scope: super::super::protocol::Scope {
                service: scope.service.clone(),
                account: scope.account.clone(),
                device: scope.device.clone(),
                identity_key: super::super::protocol::encode_hex(
                    &model::decode(&identity.identity_key).unwrap(),
                ),
                store_id: "03".repeat(32),
            },
            anchor_public_key: super::super::protocol::encode_hex(
                SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes(),
            ),
            client_seed: "05".repeat(32),
            rebuild_trust: None,
            rebuild_origin: None,
        };
        Self {
            directory,
            path,
            scope,
            client: Client::new(config).unwrap(),
        }
    }
    fn store(&self) -> Store {
        Store::open(&self.path, self.scope.clone(), false).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn commitment_covers_actual_provider_raw_download_and_both_cursors() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    store.bind_anchor(&fixture.client).unwrap();
    for sql in [
        "UPDATE crypto_meta SET provider=CAST(provider || X'00' AS BLOB) WHERE singleton=1",
        "UPDATE crypto_downloads SET envelope_json=replace(envelope_json,'downloaded','altered') WHERE sequence='1'",
        "UPDATE crypto_downloads SET ciphertext_hash=printf('%064d',0) WHERE sequence='1'",
        "UPDATE crypto_meta SET processed_cursor='1',download_cursor='2' WHERE singleton=1",
    ] {
        let result: Result<()> = transaction::run(&mut store.connection, TransactionBehavior::Immediate, Fault::None, |tx| {
            let before = commitment::head(tx, false)?;
            tx.execute(sql, []).map_err(Error::database)?;
            assert_ne!(before, commitment::head(tx, false)?);
            Err(Error::new("test_rollback", false))
        });
        assert_eq!(result.unwrap_err().code, "test_rollback");
    }
    store.close().unwrap();
}

#[test]
fn edited_gate_signature_cannot_activate_or_be_read_as_valid() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    store.bind_anchor(&fixture.client).unwrap();
    let gate = store
        .anchor_begin(&"01".repeat(32), &"02".repeat(32))
        .unwrap();
    let gate = store.anchor_reserved(&gate, "1").unwrap();
    transaction::run(
        &mut store.connection,
        TransactionBehavior::Immediate,
        Fault::None,
        |tx| {
            let signed: String = tx
                .query_row(
                    "SELECT gate_json FROM anchor_control WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .map_err(Error::database)?;
            let mut signed: serde_json::Value = serde_json::from_str(&signed).unwrap();
            let signature = signed["signature_bytes"].as_str().unwrap();
            let changed = format!(
                "{}{}",
                if signature.starts_with('A') { "B" } else { "A" },
                &signature[1..]
            );
            signed["signature_bytes"] = changed.into();
            tx.execute(
                "UPDATE anchor_control SET gate_json=?1 WHERE singleton=1",
                [signed.to_string()],
            )
            .map_err(Error::database)?;
            Ok(())
        },
    )
    .unwrap();
    assert!(store.anchor_local().is_err());
    assert!(store.anchor_activate(&gate).is_err());
    assert!(store.anchor.as_ref().unwrap().permit.is_none());
    store.close().unwrap();
}

#[test]
fn unresolved_gate_without_journal_cannot_be_cleared() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    store.bind_anchor(&fixture.client).unwrap();
    let gate = store
        .anchor_begin(&"01".repeat(32), &"02".repeat(32))
        .unwrap();
    assert_eq!(
        store.anchor_clear(&gate, &gate.base).unwrap_err().code,
        "anchor_local_unresolved"
    );
    assert_eq!(store.anchor_local().unwrap().gate, Some(gate));
    store.close().unwrap();
}

#[test]
fn previously_open_unbound_handle_rejects_reads_after_another_handle_binds() {
    let fixture = Fixture::new();
    let mut old = fixture.store();
    let mut binder = fixture.store();
    binder.bind_anchor(&fixture.client).unwrap();
    assert_eq!(old.inspect().unwrap_err().code, "anchor_required");
    assert_eq!(old.received("1").unwrap_err().code, "anchor_required");
    let original = binder.anchor_local().unwrap().head;
    assert_eq!(
        binder
            .received_anchored("1", &"ff".repeat(32))
            .unwrap_err()
            .code,
        "anchor_head_mismatch"
    );
    assert_eq!(
        binder.received_anchored("1", &original).unwrap_err().code,
        "receive_not_found"
    );
    old.close().unwrap();
    binder.close().unwrap();
}
