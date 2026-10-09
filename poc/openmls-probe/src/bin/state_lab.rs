#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::io::Read;
    if std::env::args().nth(1).as_deref() == Some("--session") {
        return session();
    }
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

#[cfg(unix)]
fn session() -> std::process::ExitCode {
    use std::io::{BufRead, Read, Write};
    let mut session = match openmls_probe::lab::Session::new() {
        Ok(session) => session,
        Err(error) => {
            println!("{}", error.response());
            return std::process::ExitCode::FAILURE;
        }
    };
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut raw = Vec::new();
        let read = (&mut input)
            .take(1024 * 1024 + 1)
            .read_until(b'\n', &mut raw);
        match read {
            Ok(0) => return std::process::ExitCode::SUCCESS,
            Ok(_) if raw.len() <= 1024 * 1024 => {}
            _ => {
                println!(
                    "{}",
                    serde_json::json!({"ok":false,"error":{"code":"input_limit","message":"会话单请求读取失败或超过1MiB"}})
                );
                return std::process::ExitCode::FAILURE;
            }
        }
        #[cfg(feature = "wire-send-probe")]
        openmls_probe::lab::wire_send_probe::reset();
        let response = match std::str::from_utf8(&raw) {
            Ok(text) => match session.execute(text) {
                Ok(result) => result,
                Err(error) => error.response(),
            },
            Err(_) => {
                serde_json::json!({"ok":false,"error":{"code":"invalid_request","message":"请求不是UTF-8"}})
            }
        };
        println!("{response}");
        if std::io::stdout().flush().is_err() {
            return std::process::ExitCode::FAILURE;
        }
        #[cfg(feature = "wire-send-probe")]
        eprintln!(
            "{}",
            serde_json::json!({"probe":"wire_send_create_message","version":1,"calls":openmls_probe::lab::wire_send_probe::calls().to_string()})
        );
    }
}
