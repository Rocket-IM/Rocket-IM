//! 默认关闭的本机机制探针；不接入业务 CLI 或 Relay。
#[path = "../expired_join_probe/mod.rs"]
mod probe;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let result = match args.as_slice() {
        [_, phase, directory] => probe::run(phase, std::path::Path::new(directory)),
        _ => Err("usage: openmls-expired-join-probe init|recover|late|old-secrets-init|old-secrets-attack DIRECTORY".into()),
    };
    match result {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
