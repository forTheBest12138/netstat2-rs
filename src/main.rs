use std::error::Error;
use netstat2::port_to_pid;

fn main() -> core::result::Result<(), Box<dyn Error>> {
    let pid = port_to_pid(true, true, &[127,0,0, 1], 2333)?;
    println!("{}", pid);
    Ok(())
}