//! Sleeps for the number of ticks given as its argument and checks that at
//! least that much time passed on the kernel clock.
#![no_std]
#![no_main]

use absd_user::{Start, sleep, time};

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let before = time();
    sleep(start.arg);
    let after = time();
    if after < before + start.arg {
        let _ = console.write_str("user-sleeper: woke early\n");
        return 86;
    }
    let _ = console.write_str("user-sleeper: slept for the requested ticks\n");
    0
}
