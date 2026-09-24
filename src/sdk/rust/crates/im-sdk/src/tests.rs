use super::*;
use std::sync::Arc;

fn pair() -> (Arc<Device>, Device) {
    let a = Arc::new(Device::new("S1".into(), "A".into(), "A1".into()).unwrap());
    let b = Device::new("S1".into(), "B".into(), "B1".into()).unwrap();
    let welcome = a
        .create_group(
            "G1".into(),
            "B".into(),
            "B1".into(),
            b.identity_key().unwrap(),
            b.key_package().unwrap(),
        )
        .unwrap();
    b.join_group(
        "G1".into(),
        "A".into(),
        "A1".into(),
        a.identity_key().unwrap(),
        welcome,
    )
    .unwrap();
    (a, b)
}

#[test]
fn shared_device_serializes_concurrent_encryptions_without_reusing_sender_state() {
    let (a, b) = pair();
    let workers: Vec<_> = (0..4u8)
        .map(|value| {
            let a = a.clone();
            std::thread::spawn(move || (value, a.encrypt(vec![value + 1]).unwrap()))
        })
        .collect();
    for worker in workers {
        let (value, ciphertext) = worker.join().unwrap();
        assert_eq!(b.decrypt(ciphertext).unwrap(), vec![value + 1]);
    }
    assert_eq!(a.decrypt(b.encrypt(vec![9]).unwrap()).unwrap(), vec![9]);
}

#[test]
fn unexpected_panic_is_caught_and_invalidates_only_its_device() {
    let (a, b) = pair();
    let result: Result<()> = a.with(|_| panic!("synthetic boundary failure"));
    assert_eq!(result.unwrap_err(), Error::poisoned(ErrorCode::Poisoned));
    assert_eq!(a.identity_key().unwrap_err().code, ErrorCode::Closed);
    a.close().unwrap();
    assert!(b.identity_key().is_ok());
}

#[test]
fn stable_errors_and_close_are_forwarded_without_library_diagnostics() {
    let a = Device::new("S1".into(), "A".into(), "A1".into()).unwrap();
    let error = a.encrypt(vec![1]).unwrap_err();
    assert_eq!(error.code.as_str(), "group_required");
    assert_eq!(error.to_string(), "group_required; device_poisoned=false");
    a.close().unwrap();
    a.close().unwrap();
    assert_eq!(a.key_package().unwrap_err(), Error::new(ErrorCode::Closed));
}
