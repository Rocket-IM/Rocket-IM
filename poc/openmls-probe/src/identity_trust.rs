//! 首次核验的公开对象。渠道声明来自调用方，不证明人工核验或渠道独立性。
use crate::permission::{receipts, types, PermissionError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub protocol_version: String,
    pub service_id: String,
    pub account_id: String,
    pub device_id: String,
    pub signature_key: String,
}

impl DeviceIdentity {
    pub fn validate(&self) -> Result<(), PermissionError> {
        let invalid = |_| PermissionError::new("identity_invalid", "设备身份格式无效");
        if self.protocol_version != "rim-device-identity-1" {
            return Err(PermissionError::new(
                "identity_invalid",
                "设备身份版本不支持",
            ));
        }
        for id in [&self.service_id, &self.account_id, &self.device_id] {
            types::id(id).map_err(invalid)?;
        }
        receipts::validate_key(&self.signature_key).map_err(invalid)?;
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String, PermissionError> {
        self.validate()?;
        let raw = serde_json::to_vec(self)
            .map_err(|_| PermissionError::new("identity_invalid", "设备身份编码失败"))?;
        let mut hash = Sha256::new();
        hash.update(b"Rocket-IM/POC/device-identity/v1\0");
        hash.update(raw);
        Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Verify,
    Reset,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Display {
    pub protocol_version: String,
    pub observer: DeviceIdentity,
    pub identity: DeviceIdentity,
    #[serde(deserialize_with = "required_previous")]
    pub previous: Option<DeviceIdentity>,
    pub record_revision: String,
    pub session_nonce: String,
    pub display_nonce: String,
    pub purpose: Purpose,
}

fn required_previous<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<DeviceIdentity>, D::Error> {
    Option::<DeviceIdentity>::deserialize(deserializer)
}
