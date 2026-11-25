use super::*;
fn scope() -> Scope {
    Scope {
        service: "test-service".into(),
        account: "alice".into(),
        device: "one".into(),
    }
}
fn auth() -> Authentication {
    Authentication::new(
        scope(),
        AuthenticationOptions {
            timeout_ms: 100,
            max_attempts: 3,
        },
    )
    .unwrap()
}
fn credential() -> DeviceCredential {
    DeviceCredential {
        scope: scope(),
        token: format!("rimd_{}_{}", "a".repeat(32), "b".repeat(64)),
        expires_at_unix_ms: (now_ms().unwrap() + 10_000).to_string(),
    }
}
fn request(a: &mut Authentication) -> String {
    assert!(!a.ready().unwrap());
    let events = a.take_events();
    assert_eq!(events.len(), 1);
    match &events[0] {
        AuthenticationEvent::CredentialRequest { request_id, .. } => request_id.clone(),
        _ => panic!("request"),
    }
}
#[test]
fn triggers_coalesce_and_generations_never_share_responses() {
    let mut a = auth();
    let mut b = auth();
    let aid = request(&mut a);
    let bid = request(&mut b);
    assert_ne!(aid, bid);
    for _ in 0..20 {
        assert!(!a.ready().unwrap());
        assert!(a.take_events().is_empty());
    }
    assert_eq!(
        b.complete(
            &aid,
            AuthenticationResult::Credential {
                credential: credential()
            }
        )
        .unwrap_err()
        .code,
        "stale_authentication"
    );
    assert_eq!(b.waiting.as_ref().unwrap().0, bid);
    assert!(a
        .complete(
            &aid,
            AuthenticationResult::Credential {
                credential: credential()
            }
        )
        .unwrap()
        .is_some());
    assert!(a.ready().unwrap());
    assert_eq!(
        a.complete(
            &aid,
            AuthenticationResult::Failure {
                code: AuthenticationFailure::Forbidden
            }
        )
        .unwrap_err()
        .code,
        "stale_authentication"
    );
    assert!(a.ready().unwrap());
}
#[test]
fn timeout_is_bounded_and_late_results_cannot_revive() {
    let mut a = auth();
    for attempt in 1..=3 {
        let id = request(&mut a);
        assert_eq!(a.attempt, attempt);
        a.waiting.as_mut().unwrap().1 = Instant::now();
        assert_eq!(
            a.complete(
                &id,
                AuthenticationResult::Credential {
                    credential: credential()
                }
            )
            .unwrap_err()
            .code,
            "stale_authentication"
        );
        assert!(
            matches!(&a.take_events()[0], AuthenticationEvent::CredentialCancel {request_id,..} if request_id == &id)
        );
        assert_eq!(a.blocked, attempt == 3);
        if attempt < 3 {
            a.retry_at = Instant::now();
        }
    }
    assert!(!a.ready().unwrap());
    assert!(a.take_events().is_empty());
    assert_eq!(a.error.unwrap().code, "credential_timeout");
}
#[test]
fn utc_or_monotonic_expiry_starts_one_new_cycle() {
    for wall_expiry in [true, false] {
        let mut a = auth();
        let id = request(&mut a);
        a.complete(
            &id,
            AuthenticationResult::Credential {
                credential: credential(),
            },
        )
        .unwrap();
        a.verified();
        if wall_expiry {
            a.expiry.as_mut().unwrap().0 = now_ms().unwrap();
        } else {
            a.expiry.as_mut().unwrap().1 = Instant::now();
        }
        let next = request(&mut a);
        assert_ne!(id, next);
        assert_eq!(a.attempt, 1);
        assert_eq!(a.reason, "expired");
        assert!(!a.ready().unwrap());
        assert!(a.take_events().is_empty());
    }
}

#[test]
fn expiring_before_verified_cannot_reset_retry_budget() {
    let mut a = auth();
    for attempt in 1..=3 {
        let id = request(&mut a);
        assert_eq!(a.attempt, attempt);
        a.complete(
            &id,
            AuthenticationResult::Credential {
                credential: credential(),
            },
        )
        .unwrap();
        a.expiry.as_mut().unwrap().1 = Instant::now();
        assert!(!a.ready().unwrap());
        assert_eq!(a.blocked, attempt == 3);
        assert!(a.take_events().is_empty());
        a.retry_at = Instant::now();
    }
    assert!(!a.ready().unwrap());
    assert_eq!(
        a.error.unwrap().code,
        "credential_expired_before_verification"
    );
}
#[test]
fn scope_purpose_expiry_and_malformed_secrets_block_without_retry() {
    for case in 0..8 {
        let mut a = auth();
        let id = request(&mut a);
        let mut c = credential();
        match case {
            0 => c.scope.service = "other".into(),
            1 => c.scope.account = "other".into(),
            2 => c.scope.device = "other".into(),
            3 => c.token = format!("rimb_{}", "a".repeat(64)),
            4 => c.expires_at_unix_ms = now_ms().unwrap().to_string(),
            5 => c.expires_at_unix_ms = "18446744073709551616".into(),
            6 => c.token = format!("rimd_{}a", "中".repeat(32)),
            _ => c.expires_at_unix_ms = (now_ms().unwrap() + 3_700_000).to_string(),
        }
        assert!(a
            .complete(&id, AuthenticationResult::Credential { credential: c })
            .unwrap()
            .is_none());
        assert!(a.blocked);
        assert!(!a.ready().unwrap());
        assert!(a.take_events().is_empty());
    }
}
#[test]
fn temporary_failure_recovers_without_accepting_prior_attempt() {
    let mut a = auth();
    let first = request(&mut a);
    a.complete(
        &first,
        AuthenticationResult::Failure {
            code: AuthenticationFailure::Unavailable,
        },
    )
    .unwrap();
    assert!(!a.blocked);
    assert!(!a.ready().unwrap());
    assert!(a.take_events().is_empty());
    a.retry_at = Instant::now();
    let second = request(&mut a);
    assert_eq!(a.attempt, 2);
    assert_eq!(
        a.complete(
            &first,
            AuthenticationResult::Failure {
                code: AuthenticationFailure::LoginRequired
            }
        )
        .unwrap_err()
        .code,
        "stale_authentication"
    );
    assert!(a
        .complete(
            &second,
            AuthenticationResult::Credential {
                credential: credential()
            }
        )
        .unwrap()
        .is_some());
    assert!(a.ready().unwrap());
    assert!(a.error.is_none());
}
