//! Direct init substitution through the existing ABSD_PORTABILITY_ELF path.
//! Never use as an external child: its timed supervisor masks boot liveness.
#![no_std]
#![no_main]

use absd_user::{Pipe, Start};
absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let Ok(pipe) = Pipe::create() else { return 70; };
    // Keep our writer open so this empty Pipe is not at EOF. The process owns
    // a Console handle but the captured wait set contains only the Pipe.
    if start.console.write_all(b"READABLE PIPE ONLY WAIT\n").is_err() {
        return 71;
    }
    let _ = absd_user::wait_readable(&[pipe.raw()], 0);
    let _ = start.console.write_all(b"READABLE WAIT RETURNED\n");
    72
}
