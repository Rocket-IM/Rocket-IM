//! 旧记录只允许省略 W1 字段；新记录必须完整固定 profile/P，禁止混搭。
use super::*;
use witness::PolicyRef;

fn domain(
    version: &str,
    legacy: &str,
    current: &str,
    profile: &Option<String>,
    policy: &Option<PolicyRef>,
    old_domain: &'static [u8],
    new_domain: &'static [u8],
) -> Result<&'static [u8], PermissionError> {
    match (version, profile, policy) {
        (v, None, None) if v == legacy => Ok(old_domain),
        (v, Some(p), Some(reference)) if v == current && p == witness::PROFILE => {
            reference.validate()?;
            Ok(new_domain)
        }
        _ => Err(PermissionError::new(
            "recovery_invalid",
            "恢复版本与见证策略不匹配",
        )),
    }
}

impl Request {
    pub fn domain(&self) -> Result<&'static [u8], PermissionError> {
        let (v, p, r) = match self {
            Self::Intent(i) => (&i.protocol_version, &i.witness_profile, &i.policy_ref),
            Self::Control(c) => (&c.protocol_version, &c.witness_profile, &c.policy_ref),
        };
        domain(
            v,
            "rim-recovery-request-1",
            "rim-recovery-request-2",
            p,
            r,
            REQUEST_DOMAIN,
            REQUEST_W1_DOMAIN,
        )
    }
}
impl Statement {
    pub fn domain(&self) -> Result<&'static [u8], PermissionError> {
        domain(
            &self.protocol_version,
            "rim-permission-3",
            "rim-permission-4",
            &self.witness_profile,
            &self.policy_ref,
            CHANGE_DOMAIN,
            CHANGE_W1_DOMAIN,
        )
    }
}
impl Receipt {
    pub fn domain(&self) -> Result<&'static [u8], PermissionError> {
        domain(
            &self.protocol_version,
            "rim-recovery-receipt-1",
            "rim-recovery-receipt-2",
            &self.witness_profile,
            &self.policy_ref,
            RECEIPT_DOMAIN,
            RECEIPT_W1_DOMAIN,
        )
    }
}
