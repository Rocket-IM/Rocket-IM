#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use openmls_probe::rollback_anchor::{authority, AnchorError, INPUT_LIMIT};
    use std::io::Read;
    let mut input = String::new();
    let result = std::io::stdin()
        .take(INPUT_LIMIT as u64 + 1)
        .read_to_string(&mut input)
        .map_err(|_| AnchorError::new("anchor_invalid", "锚请求不是有效 UTF8"))
        .and_then(|_| authority::execute(&input));
    match result {
        Ok(value) => {
            println!("{value}");
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
