//! 成熟 SQLCipher 页加密；密钥仅通过字节API注入，不进入SQL、argv或诊断。
use super::error;
use crate::model::Result;
use rusqlite::Connection;
use zeroize::Zeroizing;

pub(super) fn install(connection: &Connection, key: &str) -> Result<()> {
    let raw = Zeroizing::new(format!("x'{key}'"));
    // SAFETY: 连接由当前Rust数据库线程唯一持有；缓冲在同步调用内有效，SQLCipher复制key。
    let status = unsafe {
        rusqlite::ffi::sqlite3_key_v2(
            connection.handle(),
            c"main".as_ptr(),
            raw.as_ptr().cast(),
            raw.len() as i32,
        )
    };
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(error("protected_key_rejected"));
    }
    // 仅配置连接；不访问业务数据或结构。首次schema/key读取仍进入调用方显式事务。
    connection.execute_batch("PRAGMA cipher_log_level=NONE; PRAGMA cipher_memory_security=ON; PRAGMA temp_store=MEMORY;")
        .map_err(|_|error("protected_cipher_setup"))?;
    Ok(())
}
