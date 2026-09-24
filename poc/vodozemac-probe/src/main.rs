fn main() -> std::process::ExitCode {
    match rockets_vodozemac_probe::run_smoke() {
        Ok(summary) => {
            println!("{summary}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("FAIL vodozemac: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
