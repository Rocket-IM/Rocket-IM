//! 使用实际SQLCipher文件验证生产读写路径；密钥为此测试新建的合成值。
use super::super::{data::Data, recovery_types::Meta};
use super::*;

#[test]
fn encrypted_backup_roundtrip_and_exact_file_extent() {
    let directory = std::env::temp_dir().join(format!(
        "rocket-backup-test-{}",
        files::random_id().unwrap()
    ));
    fs::create_dir(&directory).unwrap();
    let directory = fs::canonicalize(directory).unwrap();
    let scope = Scope {
        service: "test".into(),
        account: "alice".into(),
        device: "one".into(),
    };
    let saved = Saved {
        data: Data::empty(scope.clone()),
        crypto: vec![],
        meta: Meta {
            backup_guard: Some(files::random_id().unwrap()),
            ..Default::default()
        },
    };
    let database = directory.join("original.db");
    let path = directory.join("export.rimbackup");
    let manifest = Manifest {
        info: BackupInfo {
            format: 1,
            backup_id: files::random_id().unwrap(),
            scope: scope.clone(),
            revision: "0".into(),
            snapshot: store::digest(&saved).unwrap(),
        },
        database_path: database.clone(),
    };
    let key = files::random_id().unwrap();
    let temp = files::Temporary::new(&path, "test").unwrap();
    files::write_backup(&temp.0, &key, &saved, &manifest).unwrap();
    fs::rename(&temp.0, &path).unwrap();
    let result = files::read(&path, &key, &database, &scope);
    assert!(
        result.is_ok(),
        "real encrypted snapshot rejected: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().0.info, manifest.info);
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&[0; 4096])
        .unwrap();
    assert_eq!(
        files::read(&path, &key, &database, &scope)
            .err()
            .unwrap()
            .code,
        "backup_invalid"
    );
    let current = files::Temporary::new(&database, "current-format").unwrap();
    let mut connection = files::connection(&current.0, &key, false).unwrap();
    let tx = connection.transaction().unwrap();
    tx.execute_batch(store::SCHEMA).unwrap();
    tx.execute_batch("PRAGMA application_id=1380536369; PRAGMA user_version=4;")
        .unwrap();
    store::write(&tx, &saved).unwrap();
    tx.commit().unwrap();
    assert!(restore::read_current(&current.0, &key, &scope).is_ok());
    let tx = connection.transaction().unwrap();
    tx.execute_batch("PRAGMA user_version=9;").unwrap();
    tx.commit().unwrap();
    assert_eq!(
        restore::read_current(&current.0, &key, &scope)
            .err()
            .unwrap()
            .code,
        "store_format_unsupported"
    );
    let tx = connection.transaction().unwrap();
    tx.execute_batch("PRAGMA user_version=4; CREATE TABLE future_state(value BLOB);")
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        restore::read_current(&current.0, &key, &scope)
            .err()
            .unwrap()
            .code,
        "backup_current_conflict"
    );
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}
