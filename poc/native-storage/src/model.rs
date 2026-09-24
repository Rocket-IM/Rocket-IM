use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub service: String,
    pub account: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub key: String,
    pub value: String,
    pub updated_revision: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub service: String,
    pub account: String,
    pub revision: String,
    pub schema_version: u32,
    pub records: Vec<Record>,
    pub sqlite_version: String,
    pub journal_mode: String,
    pub synchronous: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Error {
    pub code: String,
    pub sqlite_code: Option<i32>,
    pub paused: bool,
}

impl Error {
    pub fn new(code: &str, paused: bool) -> Self {
        Self {
            code: code.to_owned(),
            sqlite_code: None,
            paused,
        }
    }

    pub fn database(error: rusqlite::Error) -> Self {
        let sqlite_error = error.sqlite_error();
        let code = match sqlite_error.map(|value| value.code) {
            Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt) => {
                "database_corrupt"
            }
            _ => "database_error",
        };
        Self {
            code: code.to_owned(),
            sqlite_code: sqlite_error.map(|value| value.extended_code),
            paused: false,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} (sqlite_code={:?}, paused={})",
            self.code, self.sqlite_code, self.paused
        )
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    #[default]
    None,
    SqlAfterWrite,
    RefuseCommit,
    ReadAfterSnapshot,
    BeforeCommit,
    AfterCommit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Put {
    pub expected_revision: String,
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub fault: Fault,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OpenOptions {
    pub seed_v1: bool,
    pub fail_migration: bool,
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.contains('\0')
}

pub(crate) fn revision(value: &str) -> Result<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::new("invalid_revision", false));
    }
    value
        .parse()
        .map_err(|_| Error::new("invalid_revision", false))
}
