use netstat2::port_to_pid;

fn main() {
    if let Ok(pid) = port_to_pid(true, true, &[127, 0, 0, 1], 2333) {
        println!("{pid}");
    }
}