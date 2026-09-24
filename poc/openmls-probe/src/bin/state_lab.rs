#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::io::Read;
    let mut input = String::new();
    let read = std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_string(&mut input);
    if let Err(error) = read {
        println!(
            "{}",
            serde_json::json!({"ok":false,"error":{"code":"stdin","message":error.to_string()}})
        );
        return std::process::ExitCode::FAILURE;
    }
    #[cfg(feature = "wire-send-probe")]
    openmls_probe::lab::wire_send_probe::reset();
    let result = openmls_probe::lab::execute(&input);
    #[cfg(feature = "wire-send-probe")]
    eprintln!(
        "{}",
        serde_json::json!({"probe":"wire_send_create_message","version":1,
            "calls":openmls_probe::lab::wire_send_probe::calls().to_string()})
    );
    match result {
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
fn main() {}
