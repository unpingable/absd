//! Kernel-configured bounded-class qualification workloads; no admission API.
#![no_std]
#![no_main]
use absd_user::{Start, rt_next, sleep, time};
absd_user::entry!(main);
fn work() {
    let began = time();
    while time() == began {
        core::hint::spin_loop();
    }
}
fn main(start: Start) -> i32 {
    match start.arg {
        0 | 2 | 8 | 9 | 10 | 11 | 13 => loop {
            core::hint::spin_loop();
        },
        3 => {
            work();
            sleep(3);
            loop {
                core::hint::spin_loop();
            }
        }
        4 => loop {
            work();
            sleep(25);
            work();
            if rt_next().is_err() {
                return 90;
            }
        },
        5 | 6 => {
            work();
            sleep(if start.arg == 5 { 25 } else { 65 });
            if rt_next().is_err() {
                return 90;
            }
            loop {
                work();
                if rt_next().is_err() {
                    return 90;
                }
            }
        }
        12 => unsafe {
            core::arch::asm!("ud2", options(noreturn));
        },
        _ => loop {
            work();
            if rt_next().is_err() {
                return 90;
            }
        },
    }
}
