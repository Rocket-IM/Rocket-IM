//! 有限双设备开发接口：ID 和计数跨端无损，公开材料采用小写十六进制。
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Error {
    pub code: String,
    pub paused: bool,
}
impl Error {
    pub(crate) fn new(code: &str) -> Self {
        Self {
            code: code.into(),
            paused: false,
        }
    }
    pub(crate) fn paused(code: &str) -> Self {
        Self {
            code: code.into(),
            paused: true,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::new("storage_failure")
    }
}
impl From<rocket_crypto_core::Error> for Error {
    fn from(e: rocket_crypto_core::Error) -> Self {
        Self {
            code: e.code.as_str().into(),
            paused: e.device_poisoned,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub service: String,
    pub account: String,
    pub device: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub scope: Scope,
    pub identity_key: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoiningMaterial {
    pub identity: Identity,
    pub key_package: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub service: String,
    pub conversation: String,
    pub sender_account: String,
    pub sender_device: String,
    pub message_id: String,
    #[serde(default = "initial_context")]
    pub context: String,
    pub ciphertext: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub service: String,
    pub conversation: String,
    pub sender_account: String,
    pub sender_device: String,
    pub message_id: String,
    #[serde(default = "initial_context")]
    pub context: String,
    pub text: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Initialize,
    CreateGroup {
        conversation: String,
        peer: Identity,
        key_package: String,
    },
    JoinGroup {
        conversation: String,
        peer: Identity,
        welcome: String,
    },
    Send {
        message_id: String,
        text: String,
    },
    Receive {
        envelope: Envelope,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    Initialized { identity: Identity },
    Created { welcome: String },
    Joined,
    Sent { envelope: Envelope },
    Received { message: Message, position: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub revision: String,
    pub cached: bool,
    pub value: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub scope: Scope,
    pub revision: String,
    #[serde(default = "initial_context")]
    pub context: String,
    pub identity: Option<Identity>,
    pub conversation: Option<String>,
    pub peer: Option<Identity>,
    /// 本地成功接收计数，不是 Service 游标、送达或已读。
    pub received_count: String,
    pub pending_request: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestState {
    Missing,
    Pending,
    Retired { context: String },
    Failed { error: Error },
    Complete { outcome: Outcome },
}

pub(crate) fn id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(Error::new("invalid_id"));
    }
    Ok(())
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn unhex(value: &str, max: usize) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > max * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::new("invalid_encoding"));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok(digit(p[0]) * 16 + digit(p[1]))
        })
        .collect()
}
pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::new("invalid_encoding"))
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| Error::paused("store_invalid"))
}
pub(crate) fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub(crate) fn number(value: &str) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| Error::paused("store_invalid"))?;
    if n.to_string() != value {
        return Err(Error::paused("store_invalid"));
    }
    Ok(n)
}
impl Scope {
    pub(crate) fn validate(&self) -> Result<()> {
        id(&self.service)?;
        id(&self.account)?;
        id(&self.device)
    }
}
impl Identity {
    pub(crate) fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if unhex(&self.identity_key, 32)?.len() != 32 {
            return Err(Error::new("invalid_identity"));
        }
        Ok(())
    }
}
impl Action {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Initialize => Ok(()),
            Self::CreateGroup {
                conversation,
                peer,
                key_package,
            } => {
                id(conversation)?;
                peer.validate()?;
                unhex(key_package, 262144).map(|_| ())
            }
            Self::JoinGroup {
                conversation,
                peer,
                welcome,
            } => {
                id(conversation)?;
                peer.validate()?;
                unhex(welcome, 262144).map(|_| ())
            }
            Self::Send { message_id, text } => {
                id(message_id)?;
                if text.is_empty() || text.len() > 32768 {
                    return Err(Error::new("invalid_message"));
                }
                Ok(())
            }
            Self::Receive { envelope: e } => {
                for v in [
                    &e.service,
                    &e.conversation,
                    &e.sender_account,
                    &e.sender_device,
                    &e.message_id,
                ] {
                    id(v)?;
                }
                unhex(&e.ciphertext, 262144).map(|_| ())
            }
        }
    }
}

pub(super) fn initial_context() -> String {
    "initial".into()
}
