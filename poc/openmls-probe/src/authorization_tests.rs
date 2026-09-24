use super::*;
use openmls_basic_credential::SignatureKeyPair;

// 此处仅验证授权边界；集成装置负责用真实 MLS KeyPackage 替换该合成字节串。
const KEY_PACKAGE: &[u8] = b"synthetic-key-package-for-auth-boundary";
const NOW: u64 = 1_800_000_000;

struct Fixture {
    roster: TrustedRoster,
    signer: SignatureKeyPair,
    new_key: [u8; 32],
    request: AuthorizationRequest,
}

impl Fixture {
    fn new() -> Self {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let new_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let new_key = new_signer.to_public_vec().try_into().unwrap();
        let roster = TrustedRoster::new(
            "service-1".into(),
            "account-a".into(),
            "a1".into(),
            signer.to_public_vec().try_into().unwrap(),
        )
        .unwrap();
        let request = AuthorizationRequest {
            service: "service-1".into(),
            account: "account-a".into(),
            signer_device: "a1".into(),
            new_device: "a2".into(),
            new_signature_key: new_key,
            key_package_sha256: key_package_sha256(KEY_PACKAGE),
            expected_roster_version: 0,
            nonce: [42; 32],
            issued_at_unix_secs: NOW,
            expires_at_unix_secs: NOW + 300,
        };
        Self {
            roster,
            signer,
            new_key,
            request,
        }
    }

    fn authorization(&self) -> DeviceAuthorization {
        DeviceAuthorization::sign(self.request.clone(), &self.signer).unwrap()
    }

    fn rejects_unchanged(
        &mut self,
        authorization: &DeviceAuthorization,
        expected: AuthorizationError,
    ) {
        let before = self.roster.clone();
        assert_eq!(
            self.roster
                .apply(authorization, KEY_PACKAGE, &self.new_key, NOW),
            Err(expected)
        );
        assert_eq!(
            before, self.roster,
            "拒绝授权不能修改 nonce、版本或可信设备"
        );
    }
}

#[test]
fn valid_authorization_advances_once_and_survives_snapshot() {
    let mut fixture = Fixture::new();
    let authorization = fixture.authorization();
    let wire = serde_json::to_vec(&authorization).unwrap();
    let decoded = serde_json::from_slice(&wire).unwrap();
    fixture
        .roster
        .apply(&decoded, KEY_PACKAGE, &fixture.new_key, NOW)
        .unwrap();
    assert!(fixture.roster.is_trusted("a1") && fixture.roster.is_trusted("a2"));
    assert_eq!(fixture.roster.version(), 1);
    let snapshot = serde_json::to_vec(&fixture.roster).unwrap();
    fixture.roster = serde_json::from_slice(&snapshot).unwrap();
    fixture.rejects_unchanged(&decoded, AuthorizationError::NonceConsumed);
}

#[test]
fn forged_signature_and_service_token_cannot_authorize() {
    let mut fixture = Fixture::new();
    let mut authorization = fixture.authorization();
    authorization.signature[0] ^= 1;
    fixture.rejects_unchanged(&authorization, AuthorizationError::InvalidSignature);
    authorization.signature = b"synthetic-service-login-token".to_vec();
    fixture.rejects_unchanged(&authorization, AuthorizationError::InvalidSignature);
}

#[test]
fn legacy_project_domain_signature_is_rejected_without_consuming_authorization() {
    let mut fixture = Fixture::new();
    let mut legacy = fixture.authorization();
    // 保留改名前真实域作为兼容边界负例；正文和可信公钥均不变，仅签名域不同。
    let mut signed_bytes = b"Rockets-IM/POC/device-authorization/v1\0".to_vec();
    signed_bytes.extend(serde_json::to_vec(&legacy.request).unwrap());
    legacy.signature = fixture.signer.sign(&signed_bytes).unwrap();
    fixture.rejects_unchanged(&legacy, AuthorizationError::InvalidSignature);

    let current = fixture.authorization();
    fixture
        .roster
        .apply(&current, KEY_PACKAGE, &fixture.new_key, NOW)
        .unwrap();
    assert_eq!(fixture.roster.version(), 1);
    assert!(fixture.roster.is_trusted("a2"));
}

#[test]
fn directory_public_key_replacement_cannot_replace_pinned_key() {
    let mut fixture = Fixture::new();
    let attacker_signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let forged = DeviceAuthorization::sign(fixture.request.clone(), &attacker_signer).unwrap();
    fixture.rejects_unchanged(&forged, AuthorizationError::InvalidSignature);
    let mut forged = fixture.authorization();
    forged.request.new_signature_key = attacker_signer.to_public_vec().try_into().unwrap();
    fixture.rejects_unchanged(&forged, AuthorizationError::InvalidSignature);
}

#[test]
fn service_and_account_are_bound() {
    for change_service in [true, false] {
        let mut fixture = Fixture::new();
        if change_service {
            fixture.request.service = "service-2".into();
        } else {
            fixture.request.account = "account-b".into();
        }
        let authorization = fixture.authorization();
        fixture.rejects_unchanged(&authorization, AuthorizationError::WrongContext);
    }
}

#[test]
fn exact_expiry_and_future_authorization_are_rejected() {
    let mut fixture = Fixture::new();
    let authorization = fixture.authorization();
    for now in [NOW - 1, NOW + 300, NOW + 301] {
        let before = fixture.roster.clone();
        assert_eq!(
            fixture
                .roster
                .apply(&authorization, KEY_PACKAGE, &fixture.new_key, now),
            Err(AuthorizationError::OutsideValidity)
        );
        assert_eq!(fixture.roster, before);
    }
    fixture.request.expires_at_unix_secs += 1;
    assert_eq!(
        DeviceAuthorization::sign(fixture.request.clone(), &fixture.signer),
        Err(AuthorizationError::InvalidRequest)
    );
}

#[test]
fn key_package_bytes_and_actual_mls_key_must_match_authorization() {
    let mut fixture = Fixture::new();
    let authorization = fixture.authorization();
    let before = fixture.roster.clone();
    assert_eq!(
        fixture.roster.apply(
            &authorization,
            b"substituted-key-package",
            &fixture.new_key,
            NOW
        ),
        Err(AuthorizationError::KeyPackageMismatch)
    );
    assert_eq!(fixture.roster, before);
    assert_eq!(
        fixture.roster.apply(
            &authorization,
            KEY_PACKAGE,
            &fixture.signer.to_public_vec(),
            NOW
        ),
        Err(AuthorizationError::KeyPackageMismatch)
    );
    assert_eq!(fixture.roster, before);
}

#[test]
fn stale_and_future_roster_versions_are_rejected() {
    let mut fixture = Fixture::new();
    fixture.request.expected_roster_version = 1;
    let authorization = fixture.authorization();
    fixture.rejects_unchanged(&authorization, AuthorizationError::WrongVersion);
    fixture.request.expected_roster_version = 0;
    fixture
        .roster
        .apply(&fixture.authorization(), KEY_PACKAGE, &fixture.new_key, NOW)
        .unwrap();
    fixture.request.nonce = [43; 32];
    fixture.request.new_device = "a3".into();
    let stale = fixture.authorization();
    fixture.rejects_unchanged(&stale, AuthorizationError::WrongVersion);
}

#[test]
fn revoked_signer_cannot_create_new_authorization_after_snapshot_reload() {
    let mut fixture = Fixture::new();
    fixture.roster.revoke("a1", 0).unwrap();
    fixture.request.expected_roster_version = fixture.roster.version();
    let authorization = fixture.authorization();
    let snapshot = serde_json::to_vec(&fixture.roster).unwrap();
    fixture.roster = serde_json::from_slice(&snapshot).unwrap();
    assert!(!fixture.roster.is_trusted("a1"));
    fixture.rejects_unchanged(&authorization, AuthorizationError::SignerNotTrusted);
}

#[test]
fn known_device_id_and_reused_device_secret_cannot_be_enrolled() {
    let mut fixture = Fixture::new();
    fixture.request.new_device = "a1".into();
    let authorization = fixture.authorization();
    fixture.rejects_unchanged(&authorization, AuthorizationError::DeviceAlreadyKnown);
    fixture.request.new_device = "a2".into();
    fixture.new_key = fixture.signer.to_public_vec().try_into().unwrap();
    fixture.request.new_signature_key = fixture.new_key;
    let authorization = fixture.authorization();
    fixture.rejects_unchanged(&authorization, AuthorizationError::ReusedDeviceKey);
}

#[test]
fn signed_fields_cannot_be_mutated_or_extended() {
    let mut fixture = Fixture::new();
    let original = fixture.authorization();
    let mut changed = original.clone();
    changed.request.new_device = "attacker-device".into();
    fixture.rejects_unchanged(&changed, AuthorizationError::InvalidSignature);
    changed = original.clone();
    changed.request.nonce[0] ^= 1;
    fixture.rejects_unchanged(&changed, AuthorizationError::InvalidSignature);
    changed = original.clone();
    changed.request.expires_at_unix_secs -= 1;
    fixture.rejects_unchanged(&changed, AuthorizationError::InvalidSignature);
    let mut json = serde_json::to_value(original).unwrap();
    json["request"]["service_token"] = "synthetic-login-token".into();
    assert!(serde_json::from_value::<DeviceAuthorization>(json).is_err());
}
