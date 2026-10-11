#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! `sshtest`: session-side helper for the SSH matrix (installed as
//! /bin/sshtest on ABSD). One mode per run:
//!
//!   stderr        "out\n" on stdout, "err\n" on stderr
//!   zeros N       N zero bytes on stdout
//!   sleep MS      waits MS milliseconds, prints "slept\n"
//!   drip          a line every 10 ms, forever
//!   after MS      copies stdin to stdout, waits MS ms, prints "after\n"
//!   fault         executes an invalid instruction
//!   exit N        exits with status N
//!   ticks         the kernel's tick count since boot (ABSD)
//!   stop          tries to stop the machine without the right (ABSD): the
//!                 runtime's `stop`, the retired `stop` syscall, and
//!                 `machine_stop` through every small handle value; prints
//!                 each refusal, exits 0 only if all were refused

use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn wait(ms: u64) {
    let end = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < end {
        #[cfg(target_os = "absd")]
        absd_runtime::sleep_ticks(1);
        #[cfg(not(target_os = "absd"))]
        std::thread::sleep(Duration::from_millis(1).min(end - Instant::now()));
    }
}

fn main() {
    #[cfg(target_os = "absd")]
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let number = |i: usize| args.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let mut out = std::io::stdout();
    match args.first().map(String::as_str) {
        Some("stderr") => {
            out.write_all(b"out\n").unwrap();
            out.flush().unwrap();
            std::io::stderr().write_all(b"err\n").unwrap();
        }
        Some("zeros") => {
            let block = [0u8; 4096];
            let mut left = number(1) as usize;
            while left > 0 {
                let n = left.min(block.len());
                out.write_all(&block[..n]).unwrap();
                left -= n;
            }
            out.flush().unwrap();
        }
        Some("drip") => loop {
            // A line every 10 ms until killed or its reader is gone.
            if out.write_all(b"drip drip drip drip drip drip drip drip\n").and_then(|()| out.flush()).is_err() {
                std::process::exit(0);
            }
            wait(10);
        },
        Some("sleep") => {
            wait(number(1));
            out.write_all(b"slept\n").unwrap();
        }
        Some("after") => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            out.write_all(&input).unwrap();
            out.flush().unwrap();
            wait(number(1));
            out.write_all(b"after\n").unwrap();
        }
        #[cfg(target_arch = "x86_64")]
        Some("fault") => unsafe { core::arch::asm!("ud2", options(nomem, nostack)) },
        Some("exit") => std::process::exit(number(1) as i32),
        #[cfg(target_os = "absd")]
        Some("ticks") => writeln!(out, "ticks {}", absd_runtime::ticks()).unwrap(),
        #[cfg(target_os = "absd")]
        Some("stop") => {
            let raw = |number: u64, a0: u64, a1: u64| -> i64 {
                let result: i64;
                unsafe {
                    core::arch::asm!("int 0x80", inout("rax") number => result, in("rdi") a0,
                        in("rsi") a1, in("rdx") 0u64, options(nostack));
                }
                result
            };
            let runtime = absd_runtime::stop(16);
            let retired = raw(28, 16, 0);
            let guessed: Vec<i64> = (0..256u64).map(|handle| raw(37, handle, 16)).collect();
            let refused = guessed.iter().filter(|&&code| code == -9).count();
            writeln!(out, "stop refused runtime={runtime} retired={retired} guessed={refused}/256").unwrap();
            out.flush().unwrap();
            std::process::exit(if runtime == -9 && retired == -38 && refused == 256 { 0 } else { 1 });
        }
        _ => {
            eprintln!("sshtest: stderr | zeros N | drip | sleep MS | after MS | fault | exit N | ticks | stop");
            std::process::exit(2);
        }
    }
    out.flush().unwrap();
}
