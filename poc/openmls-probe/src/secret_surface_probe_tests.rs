use super::*;
use std::os::unix::fs::{symlink, DirBuilderExt};

struct Fixture {
    root: PathBuf,
    request: Value,
    snapshot: Vec<u8>,
    signature: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).unwrap();
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rim-secret-observer-{}", scan::digest(&random)));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let directory = root.join("a1-before");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let key = [7u8; 32];
        let signature = vec![11u8; 32];
        let hpke = vec![19u8; 32];
        let secret = vec![23u8; 32];
        let context = Context {
            service: "synthetic-secret-observer".into(),
            account: "alice".into(),
            device: "a1".into(),
        };
        // 只模拟已锁定依赖的序列化形状；真实 MLS 取样由联合装置证明。
        let entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                b"SignatureKeyPair-fixture".to_vec(),
                serde_json::to_vec(&json!({
                "private":signature,"public":vec![101u8;32]}))
                .unwrap(),
            ),
            (
                b"EpochKeyPairs-fixture".to_vec(),
                serde_json::to_vec(&json!([{
                "private_key":{"key":{"vec":hpke}},"public_key":{"key":vec![102u8;32]}}]))
                .unwrap(),
            ),
            (
                b"MessageSecrets-fixture".to_vec(),
                serde_json::to_vec(&json!({
                "message_secrets":{"sender_data_secret":{"secret":{"value":{"vec":secret}}},
                    "serialized_context":vec![103u8;32]}}))
                .unwrap(),
            ),
        ];
        let state = json!({"version":1,"context":context,"provider_entries":entries});
        fs::write(directory.join("device.key"), key).unwrap();
        fs::set_permissions(
            directory.join("device.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        openmls_probe::snapshot::save(
            &directory.join("state.enc"),
            &key,
            &serde_json::to_vec(&("Rocket-IM/state-lab/v1", &context)).unwrap(),
            &serde_json::to_vec(&state).unwrap(),
            openmls_probe::snapshot::Failpoint::None,
        )
        .unwrap();
        fs::write(root.join("observed.bin"), &signature).unwrap();
        let snapshot = fs::read(directory.join("state.enc")).unwrap();
        let request = json!({"root":root,"devices":[{"name":"a1-before", "directory":directory,
            "context":context}],"files":[{"label":"response", "path":root.join("observed.bin")}],
            "plaintexts":[]});
        Self {
            root,
            request,
            snapshot,
            signature,
        }
    }

    fn run(&self) -> Result<Value> {
        run(&serde_json::to_vec(&self.request).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn reads_nested_actual_shapes_without_exporting_or_changing_snapshot() {
    let fixture = Fixture::new();
    let result = fixture.run().unwrap();
    assert_eq!(result["needle_count"], 4);
    assert_eq!(result["pattern_count"], 36);
    assert_eq!(result["controls"]["positive_encoding_checks"], 36);
    assert_eq!(result["controls"]["wrong_sample_negative_checks"], 36);
    assert_eq!(result["secret_coverage"][0]["samples"]["hpke_private"], 1);
    assert!(result["surfaces"][0]["hits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["category"] == "signature_private" && h["encoding"] == "raw"));
    let report = serde_json::to_vec(&result).unwrap();
    assert!(!report
        .windows(fixture.signature.len())
        .any(|w| w == fixture.signature));
    assert_eq!(
        fs::read(fixture.root.join("a1-before/state.enc")).unwrap(),
        fixture.snapshot
    );
    assert_eq!(
        fs::read(fixture.root.join("a1-before/device.key")).unwrap(),
        [7u8; 32]
    );
}

#[test]
fn private_selection_excludes_public_context_and_epoch_authenticator() {
    let mut needles = Vec::new();
    let value = json!({"init_secret":{"secret":{"value":{"vec":vec![31u8;32]}}},
        "epoch_authenticator":{"secret":{"value":{"vec":vec![32u8;32]}}},
        "public_key":vec![33u8;32],"serialized_context":vec![34u8;32],
        "message_secrets":{"secret_tree":{"parent_nodes":[{"secret":{"value":{"vec":vec![35u8;32]}}}]}}});
    private_values(&value, "mls_secret", "a1", false, 0, &mut needles).unwrap();
    assert_eq!(needles.len(), 2);
    let patterns = scan::patterns(&needles).unwrap();
    for public in [32u8, 33, 34] {
        assert!(scan::scan(&[public; 32], &patterns).unwrap().is_empty());
    }
    for private in [31u8, 35] {
        assert!(!scan::scan(&[private; 32], &patterns).unwrap().is_empty());
    }
}

#[test]
fn compact_spaced_and_nested_encodings_reach_the_same_samples() {
    let raw: Vec<u8> = (41..73).collect();
    let mut needles = Vec::new();
    scan::add(&mut needles, "hpke_private", "b1", raw.clone()).unwrap();
    let patterns = scan::patterns(&needles).unwrap();
    assert_eq!(
        scan::controls(&needles).unwrap()["positive_encoding_checks"],
        9
    );
    let inner = json!({"secret":{"vec":raw}});
    let layer = json!({"statement_bytes":STANDARD.encode(serde_json::to_vec(&inner).unwrap())});
    let outer = json!({"saved_json":serde_json::to_string(&layer).unwrap()});
    let hits = scan::scan(&serde_json::to_vec(&outer).unwrap(), &patterns).unwrap();
    assert!(hits
        .iter()
        .any(|hit| hit["view"] == "json_byte_array" && hit["encoding"] == "raw"));
    assert!(hits.iter().any(|hit| hit["view"] == "base64_decoded"));
    assert!(scan::scan(
        b"unrelated public metadata, no synthetic key here",
        &patterns
    )
    .unwrap()
    .is_empty());
}

#[test]
fn explicit_markers_and_plaintext_have_separate_categories() {
    let mut fixture = Fixture::new();
    let marker = b"isolated-service-token-for-observer";
    let text = "synthetic body with no production data";
    fixture.request["markers"] = json!([{"name":"service-token","base64":STANDARD.encode(marker)}]);
    fixture.request["plaintexts"] = json!([text]);
    fs::write(
        fixture.root.join("observed.bin"),
        serde_json::to_vec(&json!({"token":STANDARD.encode(marker),"text":text})).unwrap(),
    )
    .unwrap();
    let result = fixture.run().unwrap();
    let hits = result["surfaces"][0]["hits"].as_array().unwrap();
    assert!(hits
        .iter()
        .any(|h| h["category"] == "marker" && h["device"] == "service-token"));
    assert!(hits
        .iter()
        .any(|h| h["category"] == "plaintext" && h["device"] == "harness"));
    let report = serde_json::to_string(&result).unwrap();
    assert!(!report.contains(text));
    assert!(!report.contains(&STANDARD.encode(marker)));
}

#[test]
fn path_escape_and_symlink_are_rejected_without_reading() {
    let mut fixture = Fixture::new();
    let link = fixture.root.join("linked");
    symlink(fixture.root.join("observed.bin"), &link).unwrap();
    fixture.request["files"][0]["path"] = json!(link);
    assert_eq!(fixture.run().err(), Some("surface_path"));
    fixture.request["files"][0]["path"] = json!(fixture.root.join("../other"));
    assert_eq!(fixture.run().err(), Some("surface_path"));
    fixture.request["files"][0]["path"] = json!("/etc/passwd");
    assert_eq!(fixture.run().err(), Some("surface_path"));
    fixture.request["devices"][0]["directory"] = json!(fixture.root.join("linked"));
    assert_eq!(fixture.run().err(), Some("surface_path"));
}

#[test]
fn malformed_inputs_and_unknown_fields_never_echo_values() {
    assert_eq!(
        run(&vec![b'x'; MAX_INPUT_BYTES + 1]).err(),
        Some("input_limit")
    );
    assert_eq!(run(b"not-json-secret-value").err(), Some("input_schema"));
    let mut fixture = Fixture::new();
    fixture.request["accidental_secret"] = json!("must-not-appear-in-error");
    assert_eq!(fixture.run().err(), Some("input_schema"));
    fixture
        .request
        .as_object_mut()
        .unwrap()
        .remove("accidental_secret");
    fixture.request["devices"] = json!([]);
    assert_eq!(fixture.run().err(), Some("input_count"));
}

#[test]
fn wrong_context_and_tampered_snapshot_fail_closed() {
    let mut fixture = Fixture::new();
    fixture.request["devices"][0]["context"]["account"] = json!("wrong-account");
    assert_eq!(fixture.run().err(), Some("snapshot_load"));
    fixture.request["devices"][0]["context"]["account"] = json!("alice");
    let path = fixture.root.join("a1-before/state.enc");
    let mut changed = fixture.snapshot.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(&path, &changed).unwrap();
    assert_eq!(fixture.run().err(), Some("snapshot_load"));
    assert_eq!(fs::read(path).unwrap(), changed);
}

#[test]
fn missing_private_samples_and_excessive_decoding_cannot_pass() {
    let fixture = Fixture::new();
    let directory = fixture.root.join("a1-before");
    let context: Context =
        serde_json::from_value(fixture.request["devices"][0]["context"].clone()).unwrap();
    openmls_probe::snapshot::save(
        &directory.join("state.enc"),
        &[7u8; 32],
        &serde_json::to_vec(&("Rocket-IM/state-lab/v1", &context)).unwrap(),
        &serde_json::to_vec(&json!({"version":1,"context":context,"provider_entries":[]})).unwrap(),
        openmls_probe::snapshot::Failpoint::None,
    )
    .unwrap();
    assert_eq!(fixture.run().err(), Some("secret_coverage_missing"));
    let mut nested = json!("unrelated non-secret text");
    for _ in 0..30 {
        nested = json!({"nested":nested});
    }
    assert_eq!(
        scan::scan(&serde_json::to_vec(&nested).unwrap(), &[]).err(),
        Some("decode_structure_limit")
    );
}
