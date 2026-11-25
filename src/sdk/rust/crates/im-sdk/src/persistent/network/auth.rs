//! 单连接认证协调。每轮上限明确；没有后台线程、SQL或宿主回调等待。
use super::{super::types::*, auth_types::*};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
pub(super) struct Authentication {
    scope: Scope,
    options: AuthenticationOptions,
    generation: String,
    sequence: u64,
    attempt: u8,
    reason: String,
    waiting: Option<(String, Instant)>,
    expiry: Option<(u64, Instant)>,
    verified: bool,
    retry_at: Instant,
    pub error: Option<Error>,
    pub blocked: bool,
    events: Vec<AuthenticationEvent>,
}
fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| u64::try_from(v.as_millis()).ok())
        .ok_or_else(|| Error::new("clock_invalid"))
}
impl Authentication {
    pub fn new(scope: Scope, options: AuthenticationOptions) -> Result<Self> {
        if !(100..=30000).contains(&options.timeout_ms) || !(1..=3).contains(&options.max_attempts)
        {
            return Err(Error::new("invalid_authentication_options"));
        }
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::new("entropy_unavailable"))?;
        let generation = hex(&nonce);
        Ok(Self {
            scope,
            options,
            generation,
            sequence: 0,
            attempt: 0,
            reason: "initial".into(),
            waiting: None,
            expiry: None,
            verified: false,
            retry_at: Instant::now(),
            error: None,
            blocked: false,
            events: vec![],
        })
    }
    /// 同时使用绝对UTC期限与单调时钟，系统时钟回拨不能延长已取得的凭证。
    pub fn ready(&mut self) -> Result<bool> {
        if self.blocked {
            return Ok(false);
        }
        let now = Instant::now();
        if let Some((wall, mono)) = self.expiry {
            if now_ms()? < wall && now < mono {
                return Ok(true);
            }
            self.expiry = None;
            self.reason = "expired".into();
            if self.verified {
                self.attempt = 0;
                self.retry_at = now;
            } else {
                // 过短或持续无法核验的凭证不能靠重置轮次形成无限认证循环。
                self.fail("credential_expired_before_verification", true);
            }
        }
        if self
            .waiting
            .as_ref()
            .is_some_and(|(_, until)| now >= *until)
        {
            self.cancel_waiting();
            self.fail("credential_timeout", true);
        }
        if !self.blocked && self.waiting.is_none() && now >= self.retry_at {
            self.attempt += 1;
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or_else(|| Error::new("authentication_limit"))?;
            let id = format!("auth-{}-{}", self.generation, self.sequence);
            self.events.push(AuthenticationEvent::CredentialRequest {
                scope: self.scope.clone(),
                request_id: id.clone(),
                reason: self.reason.clone(),
                attempt: self.attempt,
                timeout_ms: self.options.timeout_ms,
            });
            self.waiting = Some((id, now + Duration::from_millis(self.options.timeout_ms)));
        }
        Ok(false)
    }
    fn cancel_waiting(&mut self) {
        if let Some((request_id, _)) = self.waiting.take() {
            self.events.push(AuthenticationEvent::CredentialCancel {
                scope: self.scope.clone(),
                request_id,
            });
        }
    }
    fn fail(&mut self, code: &str, transient: bool) {
        self.expiry = None;
        self.blocked = !transient || self.attempt >= self.options.max_attempts;
        self.error = Some(Error::new(code));
        self.retry_at =
            Instant::now() + Duration::from_millis(250 * u64::from(self.attempt.max(1)));
    }
    /// 只接受当前在途请求。超时、旧连接或已取消的结果不能改变状态。
    pub fn complete(&mut self, id: &str, result: AuthenticationResult) -> Result<Option<String>> {
        let Some((expected, until)) = &self.waiting else {
            return Err(Error::new("stale_authentication"));
        };
        if expected != id {
            return Err(Error::new("stale_authentication"));
        }
        if Instant::now() >= *until {
            self.cancel_waiting();
            self.fail("credential_timeout", true);
            return Err(Error::new("stale_authentication"));
        }
        self.waiting.take();
        match result {
            AuthenticationResult::Credential { mut credential } => {
                let valid = (|| {
                    if credential.scope != self.scope {
                        return Err(Error::new("credential_scope_mismatch"));
                    }
                    let token = &credential.token;
                    if token.len() != 102
                        || !token.is_ascii()
                        || !token.starts_with("rimd_")
                        || token.as_bytes()[37] != b'_'
                        || !token[5..37]
                            .bytes()
                            .chain(token[38..].bytes())
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err(Error::new("invalid_credential"));
                    }
                    let expires = number(&credential.expires_at_unix_ms)
                        .map_err(|_| Error::new("invalid_credential"))?;
                    let remaining = expires
                        .checked_sub(now_ms()?)
                        .filter(|v| *v > 0 && *v <= 3_600_000)
                        .ok_or_else(|| Error::new("credential_expired_or_invalid"))?;
                    Ok((expires, Instant::now() + Duration::from_millis(remaining)))
                })();
                match valid {
                    Ok(expiry) => {
                        self.expiry = Some(expiry);
                        self.verified = false;
                        self.error = None;
                        Ok(Some(std::mem::take(&mut credential.token)))
                    }
                    Err(e) => {
                        self.fail(&e.code, false);
                        Ok(None)
                    }
                }
            }
            AuthenticationResult::Failure { code } => {
                let (code, transient) = match code {
                    AuthenticationFailure::Unavailable => ("credential_unavailable", true),
                    AuthenticationFailure::LoginRequired => ("login_required", false),
                    AuthenticationFailure::Forbidden => ("credential_forbidden", false),
                    AuthenticationFailure::Cancelled => ("authentication_cancelled", false),
                    AuthenticationFailure::InvalidCredential => ("invalid_credential", false),
                    AuthenticationFailure::ProviderFailed => ("credential_provider_failed", false),
                };
                self.fail(code, transient);
                Ok(None)
            }
        }
    }
    pub fn take_events(&mut self) -> Vec<AuthenticationEvent> {
        std::mem::take(&mut self.events)
    }
    pub fn verified(&mut self) {
        self.verified = true;
    }
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
