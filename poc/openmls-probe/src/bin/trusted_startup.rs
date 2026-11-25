#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::io::Read;
    let mut input = String::new();
    let result = std::io::stdin()
        .take(openmls_probe::trusted_startup::LIMIT as u64 + 1)
        .read_to_string(&mut input)
        .map_err(|_| openmls_probe::trusted_startup::error())
        .and_then(|_| openmls_probe::trusted_startup::authority::execute(&input));
    match result {
        Ok(value) => {
            println!("{value}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            println!(
                "{}",
                serde_json::json!({"ok":false,"error":{"code":e.code,"message":e.to_string()}})
            );
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(1);
}
