//! 默认关闭的本机秘密观测装置；不属于 state-lab 或公开 SDK/API。
#[cfg(unix)]
#[path = "../secret_surface_probe.rs"]
mod probe;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::io::Read;
    let mut input = Vec::new();
    let result = std::io::stdin()
        .take(probe::MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| "input_read")
        .and_then(|_| probe::run(&input));
    match result {
        Ok(result) => {
            println!("{}", serde_json::json!({"ok":true,"result":result}));
            std::process::ExitCode::SUCCESS
        }
        Err(code) => {
            // 错误不附带请求、路径、JSON 片段或底层错误中的秘密值。
            println!("{}", serde_json::json!({"ok":false,"error":{"code":code}}));
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
