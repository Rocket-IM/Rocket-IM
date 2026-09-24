//! 合成秘密保护控制器：命令与密码仅从标准输入读取，输出不包含输入原文。
use rocket_native_storage_probe::model::{Error, Result};
use serde_json::{json, Value};
use std::io::{self, Write};

fn main() {
    let reply = match run() {
        Ok(value) => json!({"ok":true,"result":value,"error":null}),
        Err(error) => json!({"ok":false,"result":null,"error":error}),
    };
    let success = reply["ok"] == true;
    let mut output = io::stdout().lock();
    if serde_json::to_writer(&mut output, &reply).is_err()
        || writeln!(output).and_then(|()| output.flush()).is_err()
        || !success
    {
        std::process::exit(1);
    }
}

#[cfg(feature = "protected-storage")]
fn run() -> Result<Value> {
    use std::io::Read;
    use zeroize::Zeroizing;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 || args[0] != "--test-mode" {
        return Err(Error::new("test_mode_required", true));
    }
    let mut input = Zeroizing::new(Vec::new());
    io::stdin()
        .lock()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut input)
        .map_err(|_| Error::new("protected_control_io", true))?;
    if input.len() > 1024 * 1024 {
        return Err(Error::new("protected_control_input_limit", true));
    }
    let value =
        serde_json::from_slice(&input).map_err(|_| Error::new("protected_control_input", true))?;
    rocket_native_storage_probe::protection::control::run(value)
}

#[cfg(not(feature = "protected-storage"))]
fn run() -> Result<Value> {
    Err(Error::new("protected_storage_unavailable", true))
}
