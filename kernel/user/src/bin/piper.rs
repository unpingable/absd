//! Writes numbered lines into the pipe end handed over at spawn and exits;
//! its exit drops the last writer, which is how the reader sees the end.
#![no_std]
#![no_main]

use absd_user::{Pipe, Start};

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let pipe = Pipe::from_raw(start.handle);
    let lines = start.arg;
    for number in 0..lines {
        let mut line = *b"piper: line 000\n";
        line[12] = b'0' + (number / 100 % 10) as u8;
        line[13] = b'0' + (number / 10 % 10) as u8;
        line[14] = b'0' + (number % 10) as u8;
        if pipe.write_all(&line).is_err() {
            return 87;
        }
    }
    0
}
