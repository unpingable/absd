#![no_std]
#![no_main]

use absd_user::{MultiStart, Pipe};
absd_user::multi_entry!(main);

fn main(start: MultiStart<'_>) -> i32 {
    let [read, acknowledgement] = start.handles else { return 70; };
    let ack = Pipe::from_raw(*acknowledgement);
    // This one-byte write cannot fill the fresh pipe. A later read is allowed
    // only after observed data or EOF, so a spurious wake cannot hide in it.
    if ack.write_timeout(b"A", 1000) != Ok(1) { return 71; }
    if readable_native_probe::wait(&[*read], 0) != 1 { return 72; }
    let pipe = Pipe::from_raw(*read);
    match pipe.info() {
        Ok(info) if info.available >= 1 || info.writers == 0 => (),
        _ => return 75,
    }
    let mut byte = [0];
    let reply = match pipe.read_timeout(&mut byte, 1000) {
        Ok(0) => b"E",
        Ok(1) if byte == *b"X" => b"D",
        _ => return 73,
    };
    if ack.write_timeout(reply, 1000) != Ok(1) { return 74; }
    0
}
