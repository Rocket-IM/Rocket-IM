//! 在实验 JSON 命令边界保留签名封装的准确原字节；不接触设备或 MLS。
use super::{require, witness::*};
use crate::permission::PermissionError;
use serde_json::Value;

fn invalid() -> PermissionError {
    PermissionError::new("recovery_invalid", "缺少准确原始签名封装")
}
fn envelope(raw: &[u8], limit: usize) -> Result<(), PermissionError> {
    parse_signed_wire(raw, limit).map(|_| ()).map_err(|error| {
        if error.code == "resource_exhausted" {
            PermissionError::new("w1_resource_exhausted", "见证签名原始封装超过 wire 预算")
        } else {
            error
        }
    })
}
fn whitespace(raw: &[u8], mut i: usize) -> usize {
    while raw.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}
// 此扫描器只定位已经由 serde 验证的 JSON；不替代语法或类型校验。
fn string_end(raw: &[u8], start: usize) -> Result<usize, PermissionError> {
    let mut i = start + 1;
    while let Some(byte) = raw.get(i) {
        match byte {
            b'\\' => i += 2,
            b'"' => return Ok(i + 1),
            _ => i += 1,
        }
    }
    Err(invalid())
}
fn value_end(raw: &[u8], start: usize) -> Result<usize, PermissionError> {
    match raw.get(start) {
        Some(b'"') => string_end(raw, start),
        Some(b'{' | b'[') => {
            let mut depth = 1;
            let mut i = start + 1;
            while let Some(byte) = raw.get(i) {
                match byte {
                    b'"' => {
                        i = string_end(raw, i)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Err(invalid())
        }
        Some(_) => Ok((start..raw.len())
            .find(|&i| raw[i].is_ascii_whitespace() || matches!(raw[i], b',' | b'}' | b']'))
            .unwrap_or(raw.len())),
        None => Err(invalid()),
    }
}
fn field<'a>(raw: &'a [u8], name: &str) -> Result<&'a [u8], PermissionError> {
    let mut i = whitespace(raw, 0);
    require(raw.get(i) == Some(&b'{'), "recovery_invalid")?;
    i = whitespace(raw, i + 1);
    while raw.get(i) == Some(&b'"') {
        let end = string_end(raw, i)?;
        let key: String = serde_json::from_slice(&raw[i..end]).map_err(|_| invalid())?;
        i = whitespace(raw, end);
        require(raw.get(i) == Some(&b':'), "recovery_invalid")?;
        let start = whitespace(raw, i + 1);
        let end = value_end(raw, start)?;
        if key == name {
            return Ok(&raw[start..end]);
        }
        i = whitespace(raw, end);
        if raw.get(i) != Some(&b',') {
            break;
        }
        i = whitespace(raw, i + 1);
    }
    Err(invalid())
}
/// 在加载任何设备状态前调用。整份输入禁止重键；仅 W1 接收操作要求签名封装准确 wire 格式。
pub fn validate_lab_envelopes(input: &str) -> Result<(), PermissionError> {
    let value: Value = parse_bytes(input.as_bytes(), 1024 * 1024)?;
    if value["operation"] != "join_recovery" {
        return Ok(());
    }
    let kind = value["command"]["kind"].as_str().unwrap_or("");
    let request = matches!(kind, "witness_respond" | "witness_apply");
    let response = matches!(kind, "witness_apply" | "witness_observe");
    if !request && !response {
        return Ok(());
    }
    let command = field(input.as_bytes(), "command")?;
    if request {
        envelope(field(command, "request")?, REQUEST_WIRE_LIMIT)?;
    }
    if response {
        envelope(
            field(field(command, "delivery")?, "response")?,
            RESPONSE_WIRE_LIMIT,
        )?;
    }
    Ok(())
}
