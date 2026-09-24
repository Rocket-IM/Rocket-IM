use serde::Serialize;
use sqlite_wasm_vfs::sahpool::OpfsSAHError;
use wasm_bindgen::JsValue;

/// 只记录结构化数字与受控名称；从不保存 SQLite/JS 原始 message 或 SQL。
#[derive(Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Cause {
    Sqlite {
        code: i32,
        #[serde(rename = "extendedCode")]
        extended_code: i32,
    },
    SqliteBinding {
        name: &'static str,
    },
    Opfs {
        operation: &'static str,
        name: String,
    },
    Browser {
        name: String,
    },
}

impl Cause {
    pub fn sqlite(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(error, _) => Self::Sqlite {
                code: error.extended_code & 0xff,
                extended_code: error.extended_code,
            },
            rusqlite::Error::QueryReturnedNoRows => Self::SqliteBinding {
                name: "query_returned_no_rows",
            },
            rusqlite::Error::InvalidColumnType(..) => Self::SqliteBinding {
                name: "invalid_column_type",
            },
            rusqlite::Error::FromSqlConversionFailure(..) => Self::SqliteBinding {
                name: "value_conversion_failed",
            },
            _ => Self::SqliteBinding {
                name: "binding_error",
            },
        }
    }

    pub fn opfs(error: OpfsSAHError) -> Self {
        let (operation, error) = match error {
            OpfsSAHError::GetDirHandle(value) => ("get_directory", Some(value)),
            OpfsSAHError::GetFileHandle(value) => ("get_file", Some(value)),
            OpfsSAHError::CreateSyncAccessHandle(value) => {
                ("create_sync_access_handle", Some(value))
            }
            OpfsSAHError::IterHandle(value) => ("iterate_directory", Some(value)),
            OpfsSAHError::GetPath(value) => ("get_path", Some(value)),
            OpfsSAHError::RemoveEntity(value) => ("remove_entity", Some(value)),
            OpfsSAHError::GetSize(value) => ("get_size", Some(value)),
            OpfsSAHError::Read(value) => ("read", Some(value)),
            OpfsSAHError::Write(value) => ("write", Some(value)),
            OpfsSAHError::Flush(value) => ("flush", Some(value)),
            OpfsSAHError::Truncate(value) => ("truncate", Some(value)),
            OpfsSAHError::Reflect(value) => ("reflect", Some(value)),
            OpfsSAHError::NotSupported => ("dedicated_worker_required", None),
            OpfsSAHError::Vfs(_) => ("vfs_registration", None),
            OpfsSAHError::ImportDb(_) => ("import_database", None),
            OpfsSAHError::Generic(_) => ("pool_state", None),
        };
        Self::Opfs {
            operation,
            name: error
                .map(browser_error_name)
                .unwrap_or_else(|| "OpfsError".into()),
        }
    }

    pub fn browser(error: JsValue) -> Self {
        Self::Browser {
            name: browser_error_name(error),
        }
    }
}

fn browser_error_name(error: JsValue) -> String {
    let name = js_sys::Reflect::get(&error, &JsValue::from_str("name"))
        .ok()
        .and_then(|name| name.as_string());
    match name.as_deref() {
        Some(
            name @ ("QuotaExceededError"
            | "NotAllowedError"
            | "InvalidStateError"
            | "NotFoundError"
            | "NotSupportedError"
            | "NoModificationAllowedError"
            | "SecurityError"
            | "AbortError"
            | "DataError"
            | "InvalidModificationError"
            | "TypeMismatchError"
            | "UnknownError"
            | "TypeError"
            | "RangeError"),
        ) => name.into(),
        _ => "UnclassifiedBrowserError".into(),
    }
}
