use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

pub const MAX_RECORDS: usize = 128;
pub const MAX_VALUE_BYTES: usize = 4096;

#[derive(Serialize)]
pub struct ApiError {
    pub code: &'static str,
    pub message: &'static str,
    pub paused: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<crate::diagnostics::Cause>,
}

impl ApiError {
    pub fn new(code: &'static str, message: &'static str, paused: bool) -> Self {
        Self {
            code,
            message,
            paused,
            cause: None,
        }
    }

    pub fn invalid() -> Self {
        Self::new("invalid_argument", "输入格式或范围不合法。", false)
    }

    pub fn test_only() -> Self {
        Self::new("test_mode_required", "故障注入仅限显式测试实例。", false)
    }

    pub fn closed() -> Self {
        Self::new("closed", "数据空间已关闭。", false)
    }

    pub fn database(error: rusqlite::Error) -> Self {
        // 不把 SQL、外部输入或 SQLite 原始错误文本交付给宿主。
        Self::new("storage_error", "SQLite 操作失败，请关闭后重新打开。", true).with_sqlite(error)
    }

    pub fn with_sqlite(mut self, error: rusqlite::Error) -> Self {
        self.cause = Some(crate::diagnostics::Cause::sqlite(error));
        self
    }

    pub fn with_opfs(mut self, error: sqlite_wasm_vfs::sahpool::OpfsSAHError) -> Self {
        self.cause = Some(crate::diagnostics::Cause::opfs(error));
        self
    }

    pub fn with_js(mut self, error: JsValue) -> Self {
        self.cause = Some(crate::diagnostics::Cause::browser(error));
        self
    }

    pub fn into_js(self) -> JsValue {
        JsValue::from_str(&encode(Err(self)))
    }
}

#[derive(Clone)]
pub struct Scope {
    pub service: String,
    pub account: String,
    pub device: String,
    pub namespace: Option<String>,
}

impl Scope {
    pub fn new(service: String, account: String) -> Result<Self, ApiError> {
        validate_id(&service)?;
        validate_id(&account)?;
        Ok(Self {
            service,
            account,
            device: "probe-device".into(),
            namespace: None,
        })
    }

    pub fn rebuilt(
        service: String,
        account: String,
        device: String,
        namespace: String,
    ) -> Result<Self, ApiError> {
        let mut scope = Self::new(service, account)?;
        validate_id(&device)?;
        if device == "probe-device"
            || namespace.len() != 64
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ApiError::invalid());
        }
        scope.device = device;
        scope.namespace = Some(namespace);
        Ok(scope)
    }

    pub fn storage_name(&self) -> String {
        // 长度与分段一并编码，避免含分隔符的服务/账号造成目录碰撞。
        let base = format!(
            "rim-storage-{}-{}-{}-{}",
            self.service.len(),
            self.service,
            self.account.len(),
            self.account
        );
        match &self.namespace {
            Some(namespace) => format!("{base}-rebuild-{namespace}"),
            None => base,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Snapshot,
    ReadFault,
    Put(Put),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Put {
    pub key: String,
    pub value: String,
    pub expected_revision: String,
    #[serde(default)]
    pub fault: Fault,
    #[serde(default)]
    pub checkpoint: Checkpoint,
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    #[default]
    None,
    WriteThenRollback,
    RefuseCommit,
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Checkpoint {
    #[default]
    None,
    BeforeCommit,
    AfterCommit,
}

impl Request {
    pub fn parse(json: &str, test_mode: bool, has_hook: bool) -> Result<Self, ApiError> {
        // 合法的 4096 字节正文可能逐字节编码为六字节 JSON 转义，另保留字段开销。
        if json.len() > 32 * 1024 {
            return Err(ApiError::invalid());
        }
        let request: Self = serde_json::from_str(json).map_err(|_| ApiError::invalid())?;
        if matches!(&request, Self::ReadFault) && !test_mode {
            return Err(ApiError::test_only());
        }
        if let Self::Put(put) = &request {
            validate_id(&put.key)?;
            parse_revision(&put.expected_revision)?;
            if put.value.len() > MAX_VALUE_BYTES {
                return Err(ApiError::invalid());
            }
            if (put.fault != Fault::None || put.checkpoint != Checkpoint::None) && !test_mode {
                return Err(ApiError::test_only());
            }
            if put.checkpoint != Checkpoint::None && (!has_hook || put.fault != Fault::None) {
                return Err(ApiError::invalid());
            }
        }
        Ok(request)
    }
}

pub fn validate_id(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ApiError::invalid());
    }
    Ok(())
}

pub fn parse_revision(value: &str) -> Result<u64, ApiError> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ApiError::invalid());
    }
    value.parse().map_err(|_| ApiError::invalid())
}

#[derive(Serialize)]
pub struct Record {
    pub key: String,
    pub value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub service: String,
    pub account: String,
    pub schema_version: u32,
    pub revision: String,
    pub records: Vec<Record>,
    pub sqlite_version: String,
}

pub fn encode(result: Result<Snapshot, ApiError>) -> String {
    let value = match result {
        Ok(snapshot) => serde_json::json!({ "ok": true, "result": snapshot }),
        Err(error) => serde_json::json!({ "ok": false, "error": error }),
    };
    value.to_string()
}
