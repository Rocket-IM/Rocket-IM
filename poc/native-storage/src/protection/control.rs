//! 仅供合成实验的故障控制装置；不向调用方返回钥匙串内容或已处理正文。
#[path = "audit.rs"]
mod audit;

use super::{error, keychain, record::checked_path, Guard, Locator, SERVICE};
use crate::model::Result;
use serde_json::{json, Value};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

/// 二进制必须先验证 --test-mode；本入口不属于正式 SDK 能力。
pub fn run(mut input: Value) -> Result<Value> {
    let result = dispatch(&mut input);
    wipe(&mut input);
    result
}

fn dispatch(input: &mut Value) -> Result<Value> {
    let op = text(input, "op")?;
    match op.as_str() {
        "keychain_create" | "keychain_unlock" | "keychain_lock" => {
            let path = PathBuf::from(text(input, "path")?);
            lab_keychain(&path)?;
            if op == "keychain_lock" {
                keychain::lock(&path)?;
            } else {
                let password = Zeroizing::new(take_text(input, "password")?);
                if op == "keychain_create" {
                    keychain::create(&path, password.as_bytes())?;
                } else {
                    keychain::unlock(&path, password.as_bytes())?;
                }
            }
        }
        "key_delete" => {
            let (_, location, _) = location(input, "db", "locator")?;
            let item = target_item(&location, boolean(input, "trust")?);
            keychain::remove(&location.keychain, SERVICE, &item)?;
        }
        "key_tamper" => tamper(input)?,
        "key_copy" => {
            let (_, source, _) = location(input, "source_db", "source_locator")?;
            let (_, target, _) = location(input, "db", "locator")?;
            let trust = boolean(input, "trust")?;
            let bytes = Zeroizing::new(keychain::read(
                &source.keychain,
                SERVICE,
                &target_item(&source, trust),
            )?);
            if source.keychain == target.keychain
                && target_item(&source, trust) == target_item(&target, trust)
            {
                return Err(error("protected_control_same_item"));
            }
            let target_item = target_item(&target, trust);
            keychain::remove(&target.keychain, SERVICE, &target_item)?;
            keychain::add(&target.keychain, SERVICE, &target_item, &bytes)?;
        }
        "key_reserve" => {
            let (database, location, locator) = location(input, "db", "locator")?;
            let guard = Guard::create(
                &database,
                &location.scope(),
                &locator,
                optional_text(input, "purpose")?,
            )?;
            guard.check()?;
            checkpoint()?;
        }
        "audit" => {
            let (database, _, locator) = location(input, "db", "locator")?;
            let paths = input
                .get("paths")
                .and_then(Value::as_array)
                .filter(|paths| !paths.is_empty() && paths.len() <= 256)
                .ok_or_else(|| error("protected_audit_paths"))?
                .iter()
                .map(|path| {
                    path.as_str()
                        .map(PathBuf::from)
                        .ok_or_else(|| error("protected_audit_paths"))
                })
                .collect::<Result<Vec<_>>>()?;
            return audit::run(database, locator, optional_text(input, "purpose")?, paths);
        }
        _ => return Err(error("protected_control_operation")),
    }
    Ok(json!({"completed":true}))
}

fn tamper(input: &mut Value) -> Result<()> {
    let (_, location, _) = location(input, "db", "locator")?;
    let target = text(input, "target")?;
    let trust = match target.as_str() {
        "key" => false,
        "trust" => true,
        _ => return Err(error("protected_control_target")),
    };
    let field = text(input, "field")?;
    let permitted = if trust {
        matches!(
            field.as_str(),
            "database"
                | "key_id"
                | "program_sha256"
                | "config.anchor_public_key"
                | "config.client_seed"
                | "config.program"
                | "config.directory"
                | "config.scope.service"
                | "config.scope.account"
                | "config.scope.device"
                | "config.scope.identity_key"
                | "config.scope.store_id"
        )
    } else {
        matches!(
            field.as_str(),
            "key"
                | "database"
                | "purpose"
                | "locator.service"
                | "locator.account"
                | "locator.device"
                | "locator.item"
                | "locator.keychain"
        )
    };
    if !permitted {
        return Err(error("protected_control_field"));
    }
    let item = target_item(&location, trust);
    let bytes = Zeroizing::new(keychain::read(&location.keychain, SERVICE, &item)?);
    let mut record = SensitiveJson(
        serde_json::from_slice(&bytes).map_err(|_| error("protected_record_invalid"))?,
    );
    let replacement = input
        .get_mut("value")
        .ok_or_else(|| error("protected_control_value"))?
        .take();
    let pointer = format!("/{}", field.replace('.', "/"));
    let destination = record
        .0
        .pointer_mut(&pointer)
        .ok_or_else(|| error("protected_control_field"))?;
    wipe(destination);
    *destination = replacement;
    let encoded =
        Zeroizing::new(serde_json::to_vec(&record.0).map_err(|_| error("protected_encoding"))?);
    if encoded.len() > 32768 {
        return Err(error("protected_control_value"));
    }
    // 故障装置刻意分开删除/新增；失败会留下不可用状态，不宣称跨系统原子。
    keychain::remove(&location.keychain, SERVICE, &item)?;
    keychain::add(&location.keychain, SERVICE, &item, &encoded)
}

fn target_item(location: &Locator, trust: bool) -> String {
    if trust {
        location.trust_item()
    } else {
        location.item.clone()
    }
}

fn location(
    input: &Value,
    database_name: &str,
    locator_name: &str,
) -> Result<(PathBuf, Locator, String)> {
    let database = PathBuf::from(text(input, database_name)?);
    let value = input
        .get(locator_name)
        .ok_or_else(|| error("protected_control_locator"))?;
    let json = if let Some(value) = value.as_str() {
        value.to_owned()
    } else {
        serde_json::to_string(value).map_err(|_| error("protected_control_locator"))?
    };
    let location = Locator::parse(&database, &json)?;
    lab_keychain(&location.keychain)?;
    Ok((database, location, json))
}

fn lab_keychain(path: &Path) -> Result<()> {
    checked_path(path)?;
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("lab-") && name.ends_with(".keychain-db"))
    {
        return Err(error("protected_lab_keychain_required"));
    }
    Ok(())
}
fn text(input: &Value, name: &str) -> Result<String> {
    input
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 16384)
        .map(str::to_owned)
        .ok_or_else(|| error("protected_control_input"))
}
fn take_text(input: &mut Value, name: &str) -> Result<String> {
    let value = input
        .get_mut(name)
        .ok_or_else(|| error("protected_control_input"))?
        .take();
    match value {
        Value::String(value) => Ok(value),
        _ => Err(error("protected_control_input")),
    }
}
fn optional_text(input: &Value, name: &str) -> Result<Option<String>> {
    match input.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => text(input, name).map(Some),
    }
}
fn boolean(input: &Value, name: &str) -> Result<bool> {
    match input.get(name) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(error("protected_control_input")),
    }
}
fn checkpoint() -> Result<()> {
    let mut output = std::io::stderr().lock();
    writeln!(
        output,
        "{}",
        json!({"checkpoint":"protected_key_saved","pid":std::process::id()})
    )
    .and_then(|()| output.flush())
    .map_err(|_| error("checkpoint_output_failed"))?;
    drop(output);
    std::thread::sleep(Duration::from_secs(10));
    Err(error("checkpoint_timeout"))
}

pub(super) struct SensitiveJson(pub Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe),
        Value::Object(values) => values.values_mut().for_each(wipe),
        _ => {}
    }
}
