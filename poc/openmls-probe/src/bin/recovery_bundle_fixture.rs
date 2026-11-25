//! 仅合成私有 bundle 损坏夹具；正常 CLI 不包含此操作。
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin().take(16385).read_to_string(&mut input)?;
    match openmls_probe::lab::recovery_bundle_probe::seed(&input) {
        Ok(value) => println!("{value}"),
        Err(error) => {
            println!("{}", error.response());
            std::process::exit(1);
        }
    }
    Ok(())
}
