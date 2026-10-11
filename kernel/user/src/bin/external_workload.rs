//! Default generic external-workload fixture: echo input to captured output.
#![no_std]
#![no_main]

use absd_user::{MultiStart, Pipe};

absd_user::multi_entry!(main);

fn main(start: MultiStart<'_>) -> i32 {
    let [input_raw, console_raw] = start.handles else {
        return 90;
    };
    if *console_raw != start.console.raw() {
        return 90;
    }
    let input = Pipe::from_raw(*input_raw);
    let mut collected = [0u8; 768];
    let mut length = 0usize;
    loop {
        let mut bytes = [0u8; 128];
        let Ok(count) = input.read_once(&mut bytes) else {
            return 91;
        };
        if count == 0 {
            break;
        }
        if length + count > collected.len() {
            return 92;
        }
        collected[length..length + count].copy_from_slice(&bytes[..count]);
        length += count;
    }
    // Deliberately hand the wrapper a slice larger than one syscall. The
    // wrapper must split it into MAX_WRITE-sized writes without data loss.
    if length <= absd_user::MAX_WRITE || start.console.write_all(&collected[..length]).is_err() {
        return 93;
    }
    0
}
