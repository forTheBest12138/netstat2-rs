use netstat2::port_to_pid;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let pid = port_to_pid(true, true, &[127, 0, 0, 1], 2333)?;
    println!("{}", pid);
    Ok(())
}
