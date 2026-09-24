//! 仅操作 Service 自有的回执签名钥；不接受用户设备目录或 E2EE 材料。
use crate::permission::{receipts::SignedRecord, PermissionError};
mod statement;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

fn error(message: &'static str) -> PermissionError {
    PermissionError::new("receipt_key", message)
}
fn load(path: &Path) -> Result<SigningKey, PermissionError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| error("无法安全读取回执钥"))?;
    let meta = file.metadata().map_err(|_| error("无法读取回执钥属性"))?;
    if !meta.is_file() || meta.permissions().mode() & 0o777 != 0o600 || meta.len() != 32 {
        return Err(error("回执钥必须是0600的32字节普通文件"));
    }
    let mut seed = [0u8; 32];
    file.read_exact(&mut seed)
        .map_err(|_| error("回执钥读取失败"))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn execute(input: &str) -> Result<Value, PermissionError> {
    if input.len() > 1024 * 1024 {
        return Err(error("请求超过1MiB"));
    }
    #[derive(Deserialize)]
    #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
    enum Request {
        Init {
            key_path: PathBuf,
        },
        PublicKey {
            key_path: PathBuf,
        },
        Sign {
            key_path: PathBuf,
            statement: statement::Statement,
            expected_signature_key: String,
        },
    }
    let request: Request = serde_json::from_str(input).map_err(|_| error("签名器请求字段无效"))?;
    let path = match &request {
        Request::Init { key_path }
        | Request::PublicKey { key_path }
        | Request::Sign { key_path, .. } => key_path,
    };
    if !path.is_absolute() {
        return Err(error("回执钥必须使用绝对路径"));
    }
    if matches!(request, Request::Init { .. }) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| error("安全随机源失败"))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| error("回执钥已存在或不能安全创建"))?;
        file.write_all(&seed)
            .and_then(|_| file.sync_all())
            .map_err(|_| error("回执钥持久化失败"))?;
        File::open(path.parent().ok_or_else(|| error("缺少父目录"))?)
            .and_then(|f| f.sync_all())
            .map_err(|_| error("回执钥目录持久化失败"))?;
    }
    let key = load(path)?;
    let signature_key = STANDARD.encode(key.verifying_key().as_bytes());
    let result = if let Request::Sign {
        statement,
        expected_signature_key,
        ..
    } = request
    {
        if expected_signature_key != signature_key {
            return Err(PermissionError::new(
                "receipt_key_mismatch",
                "当前回执钥与固定公钥不同",
            ));
        }
        let domain = statement.domain()?;
        let raw = serde_json::to_vec(&statement).map_err(|_| error("回执编码失败"))?;
        let mut signed = domain.to_vec();
        signed.extend(&raw);
        let receipt = SignedRecord {
            statement_bytes: STANDARD.encode(&raw),
            signature_bytes: STANDARD.encode(key.sign(&signed).to_bytes()),
        };
        json!({"receipt":receipt})
    } else {
        json!({"signature_key":signature_key})
    };
    Ok(json!({"ok":true,"result":result}))
}

#[cfg(test)]
mod tests;
