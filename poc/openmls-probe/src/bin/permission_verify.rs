//! 只读公共权限证明校验器；不接收目录参数、不加载设备状态。
#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::io::Read;
    let mut input = String::new();
    if std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_string(&mut input)
        .is_err()
    {
        println!(
            "{}",
            serde_json::json!({"ok":false,"error":{"code":"invalid_permission","message":"输入不是有界 UTF-8"}})
        );
        return std::process::ExitCode::FAILURE;
    }
    match openmls_probe::permission::execute(&input) {
        Ok(response) => {
            println!("{response}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            println!("{}", error.response());
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(1);
}
