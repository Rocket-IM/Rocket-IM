use super::*;
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};

const KEY: [u8; 32] = [19; 32];
const CONTEXT: &[u8] = b"synthetic-service/account-a/device-a1/v1";
const ORIGINAL: &[u8] = b"synthetic MLS state and persisted outbox";

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rockets-snapshot-test-{suffix}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("state.snapshot");
        Self { directory, path }
    }

    fn save_original(&self) {
        save(&self.path, &KEY, CONTEXT, ORIGINAL, Failpoint::None).unwrap();
    }

    fn files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files: Vec<_> = fs::read_dir(&self.directory)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        files.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        files
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn encrypted_snapshot_round_trip_permissions_and_fresh_nonce() {
    let fixture = Fixture::new();
    fixture.save_original();
    let first = fs::read(&fixture.path).unwrap();
    assert!(!first
        .windows(ORIGINAL.len())
        .any(|window| window == ORIGINAL));
    assert_eq!(
        fs::metadata(&fixture.path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(load(&fixture.path, &KEY, CONTEXT).unwrap(), ORIGINAL);
    fixture.save_original();
    let second = fs::read(&fixture.path).unwrap();
    assert_ne!(
        &first[MAGIC.len() + 1..PREFIX_LEN],
        &second[MAGIC.len() + 1..PREFIX_LEN]
    );
    assert_eq!(load(&fixture.path, &KEY, CONTEXT).unwrap(), ORIGINAL);
}

#[test]
fn wrong_key_context_tampering_and_truncation_fail_closed() {
    let fixture = Fixture::new();
    fixture.save_original();
    let original_file = fs::read(&fixture.path).unwrap();
    assert!(matches!(
        load(&fixture.path, &[20; 32], CONTEXT),
        Err(SnapshotError::AuthenticationFailed)
    ));
    assert!(matches!(
        load(&fixture.path, &KEY, b"other-service/account-a/device-a1/v1"),
        Err(SnapshotError::AuthenticationFailed)
    ));
    assert_eq!(fs::read(&fixture.path).unwrap(), original_file);
    let mut changed = original_file.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    fs::write(&fixture.path, &changed).unwrap();
    assert!(matches!(
        load(&fixture.path, &KEY, CONTEXT),
        Err(SnapshotError::AuthenticationFailed)
    ));
    fs::write(&fixture.path, &original_file[..PREFIX_LEN]).unwrap();
    assert!(matches!(
        load(&fixture.path, &KEY, CONTEXT),
        Err(SnapshotError::InvalidFormat)
    ));
    changed = original_file.clone();
    changed[0] ^= 1;
    fs::write(&fixture.path, &changed).unwrap();
    assert!(matches!(
        load(&fixture.path, &KEY, CONTEXT),
        Err(SnapshotError::InvalidFormat)
    ));
    changed = original_file;
    changed[MAGIC.len()] = VERSION + 1;
    fs::write(&fixture.path, &changed).unwrap();
    assert!(matches!(
        load(&fixture.path, &KEY, CONTEXT),
        Err(SnapshotError::UnsupportedVersion)
    ));
}

#[test]
fn failure_before_rename_preserves_formal_snapshot_and_hook_precedes_commit() {
    let fixture = Fixture::new();
    fixture.save_original();
    let original_file = fs::read(&fixture.path).unwrap();
    assert!(matches!(
        save(
            &fixture.path,
            &KEY,
            CONTEXT,
            b"new state",
            Failpoint::BeforeRename
        ),
        Err(SnapshotError::InjectedFailure)
    ));
    assert_eq!(fs::read(&fixture.path).unwrap(), original_file);
    assert_eq!(fs::read_dir(&fixture.directory).unwrap().count(), 1);
    let mut called = false;
    save_with_hook(
        &fixture.path,
        &KEY,
        CONTEXT,
        b"committed new state",
        |point| {
            assert_eq!(point, SavePoint::BeforeRename);
            assert_eq!(fs::read(&fixture.path).unwrap(), original_file);
            assert_eq!(fs::read_dir(&fixture.directory).unwrap().count(), 2);
            called = true;
        },
    )
    .unwrap();
    assert!(called);
    assert_eq!(
        load(&fixture.path, &KEY, CONTEXT).unwrap(),
        b"committed new state"
    );
}

#[test]
fn symbolic_links_and_non_regular_targets_are_rejected_without_touching_target() {
    let fixture = Fixture::new();
    let target = fixture.directory.join("target");
    fs::write(&target, b"untouched fixture").unwrap();
    symlink(&target, &fixture.path).unwrap();
    assert!(matches!(
        load(&fixture.path, &KEY, CONTEXT),
        Err(SnapshotError::Symlink)
    ));
    assert!(matches!(
        save(&fixture.path, &KEY, CONTEXT, ORIGINAL, Failpoint::None),
        Err(SnapshotError::Symlink)
    ));
    assert_eq!(fs::read(&target).unwrap(), b"untouched fixture");
    fs::remove_file(&fixture.path).unwrap();
    fs::create_dir(&fixture.path).unwrap();
    assert!(matches!(
        load(&fixture.path, &KEY, CONTEXT),
        Err(SnapshotError::NotRegularFile)
    ));
    assert!(matches!(
        save(&fixture.path, &KEY, CONTEXT, ORIGINAL, Failpoint::None),
        Err(SnapshotError::NotRegularFile)
    ));
    let linked_directory = fixture.directory.join("linked-directory");
    symlink(&fixture.path, &linked_directory).unwrap();
    assert!(matches!(
        save(
            &linked_directory.join("file"),
            &KEY,
            CONTEXT,
            ORIGINAL,
            Failpoint::None
        ),
        Err(SnapshotError::Symlink)
    ));
}

#[test]
fn oversized_save_preserves_old_snapshot_and_oversized_read_is_bounded() {
    let fixture = Fixture::new();
    fixture.save_original();
    let original_file = fs::read(&fixture.path).unwrap();
    fs::write(
        fixture.directory.join(".snapshot-preserved.tmp"),
        &original_file,
    )
    .unwrap();
    let original_files = fixture.files();
    let mut called = false;
    assert!(matches!(
        save_committed_with_hook(
            &fixture.path,
            &KEY,
            CONTEXT,
            &vec![0; MAX_PLAINTEXT_BYTES + 1],
            |_| called = true
        ),
        Err(SnapshotError::Oversize)
    ));
    assert!(!called);
    assert_eq!(fixture.files(), original_files);
    assert_eq!(load(&fixture.path, &KEY, CONTEXT).unwrap(), ORIGINAL);
    OpenOptions::new()
        .write(true)
        .open(&fixture.path)
        .unwrap()
        .set_len(MAX_FILE_BYTES as u64 + 1)
        .unwrap();
    assert!(matches!(
        load(&fixture.path, &KEY, CONTEXT),
        Err(SnapshotError::Oversize)
    ));
}

#[test]
fn exact_plaintext_limit_round_trips_and_file_limit_rejects_one_extra_byte() {
    let fixture = Fixture::new();
    let plaintext = vec![0xa5; 16 * 1024 * 1024];
    assert_eq!(MAX_PLAINTEXT_BYTES, plaintext.len());
    let commitment =
        save_committed_with_hook(&fixture.path, &KEY, CONTEXT, &plaintext, |_| {}).unwrap();
    assert_eq!(fs::metadata(&fixture.path).unwrap().len(), 16_777_253);
    assert_eq!(MAX_FILE_BYTES, plaintext.len() + 37);
    assert_eq!(load(&fixture.path, &KEY, CONTEXT).unwrap(), plaintext);
    assert_eq!(
        load_committed(&fixture.path, &KEY, CONTEXT, &commitment).unwrap(),
        plaintext
    );
    OpenOptions::new()
        .append(true)
        .open(&fixture.path)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    let oversized_digest = Sha256::digest(fs::read(&fixture.path).unwrap());
    // 两种加载入口均只能返回错误，不能返回前 16 MiB 的部分明文。
    assert!(matches!(
        load(&fixture.path, &KEY, CONTEXT),
        Err(SnapshotError::Oversize)
    ));
    assert!(matches!(
        load_committed(&fixture.path, &KEY, CONTEXT, &commitment),
        Err(SnapshotError::Oversize)
    ));
    assert_eq!(fs::metadata(&fixture.path).unwrap().len(), 16_777_254);
    assert_eq!(
        Sha256::digest(fs::read(&fixture.path).unwrap()),
        oversized_digest
    );
    assert_eq!(fs::read_dir(&fixture.directory).unwrap().count(), 1);
}

#[test]
fn exact_context_limit_is_authenticated_and_oversize_preserves_all_files() {
    let fixture = Fixture::new();
    let mut context = vec![b'c'; 4096];
    assert_eq!(MAX_CONTEXT_BYTES, context.len());
    let commitment =
        save_committed_with_hook(&fixture.path, &KEY, &context, ORIGINAL, |_| {}).unwrap();
    assert_eq!(load(&fixture.path, &KEY, &context).unwrap(), ORIGINAL);
    assert_eq!(
        load_committed(&fixture.path, &KEY, &context, &commitment).unwrap(),
        ORIGINAL
    );
    context[0] ^= 1;
    assert!(matches!(
        load(&fixture.path, &KEY, &context),
        Err(SnapshotError::AuthenticationFailed)
    ));
    context[0] ^= 1;
    fs::copy(
        &fixture.path,
        fixture.directory.join(".snapshot-preserved.tmp"),
    )
    .unwrap();
    let original_files = fixture.files();
    context.push(b'c');
    let mut called = false;
    assert!(matches!(
        save_committed_with_hook(&fixture.path, &KEY, &context, b"replacement", |_| {
            called = true
        }),
        Err(SnapshotError::Oversize)
    ));
    assert!(!called);
    assert!(matches!(
        load(&fixture.path, &KEY, &context),
        Err(SnapshotError::Oversize)
    ));
    assert!(matches!(
        load_committed(&fixture.path, &KEY, &context, &commitment),
        Err(SnapshotError::Oversize)
    ));
    assert_eq!(fixture.files(), original_files);
    context.pop();
    assert_eq!(
        load_committed(&fixture.path, &KEY, &context, &commitment).unwrap(),
        ORIGINAL
    );
}

#[test]
fn commitment_is_bound_to_written_bytes_and_rejects_later_replacement() {
    let fixture = Fixture::new();
    fixture.save_original();
    let old = fs::read(&fixture.path).unwrap();
    let expected = save_committed_with_hook(
        &fixture.path,
        &KEY,
        CONTEXT,
        b"advanced crypto state",
        |_| {},
    )
    .unwrap();
    assert_eq!(
        expected,
        <[u8; 32]>::from(Sha256::digest(fs::read(&fixture.path).unwrap()))
    );
    assert_eq!(
        load_committed(&fixture.path, &KEY, CONTEXT, &expected).unwrap(),
        b"advanced crypto state"
    );
    fs::write(&fixture.path, old).unwrap();
    assert!(matches!(
        load_committed(&fixture.path, &KEY, CONTEXT, &expected),
        Err(SnapshotError::CommitmentMismatch)
    ));
    assert_eq!(load(&fixture.path, &KEY, CONTEXT).unwrap(), ORIGINAL);
}
