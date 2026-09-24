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
            serde_json::json!({"ok":false,"error":{"code":"invalid_request","message":"请求不是有效UTF8"}})
        );
        return std::process::ExitCode::FAILURE;
    }
    match openmls_probe::relay_receipt::execute(&input) {
        Ok(result) => {
            println!("{result}");
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
