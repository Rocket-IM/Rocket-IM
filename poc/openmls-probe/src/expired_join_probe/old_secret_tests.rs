use super::*;
fn verify(name: &str) {
    let scenario = old_secrets::scenario(name).expect("synthetic scenario");
    let result = old_secret_cases::evaluate(&scenario).expect("raw AEAD controls and rejections");
    assert_eq!(result["target_count"], 12);
    assert_eq!(result["old_sender_aead_rejections"], 36);
    assert_eq!(result["old_body_aead_rejections"], 28);
    assert_eq!(result["not_retained"].as_array().unwrap().len(), 8);
    assert!(result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["gate_used"] == false
            && !row["legal_mls_receivers"].as_array().unwrap().is_empty()));
}
#[test]
fn removed_member_direct_old_secret_attack() {
    verify("remove_member");
}
#[test]
fn revoked_same_account_device_direct_old_secret_attack() {
    verify("revoke_device");
}
#[test]
fn replaced_same_signing_identity_direct_old_secret_attack() {
    verify("replace_same_identity");
}
#[test]
fn malformed_message_or_non_aead_error_never_counts_as_crypto_rejection() {
    assert!(raw_message::packet(&[0; 16]).is_err());
    assert!(raw_message::rejected(Ok(vec![0; 32])).is_err());
    assert!(
        raw_message::rejected(Err(openmls_traits::types::CryptoError::CryptoLibraryError)).is_err()
    );
}
