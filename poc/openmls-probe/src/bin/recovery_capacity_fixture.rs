//! 仅合成容量夹具；不属于正常 CLI，必须显式启用测试特性。
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin().take(16385).read_to_string(&mut input)?;
    match openmls_probe::lab::recovery_capacity_probe::seed(&input) {
        Ok(value) => println!("{value}"),
        Err(error) => {
            println!("{}", error.response());
            std::process::exit(1);
        }
    }
    Ok(())
}
