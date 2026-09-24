fn main() -> std::process::ExitCode {
    match openmls_probe::run_smoke() {
        Ok(summary) => {
            println!("{summary}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("OpenMLS 最小验证失败：{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
