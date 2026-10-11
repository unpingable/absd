#![feature(restricted_std)]
//! A brokered child for `broker_requester`: reports its runtime arguments on
//! stderr, copies stdin to stdout, and exits with the status its first
//! argument names. `fault` executes an invalid instruction instead; `flood`
//! writes 8 KiB to each of stdout and stderr, alternating, so a parent that
//! reads only one of them would deadlock. A policy-given environment is
//! reported on stderr after the arguments.

use std::io::{Read, Write};

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stderr = std::io::stderr();
    let mut stdout = std::io::stdout();
    let _ = writeln!(stderr, "broker-echo args={}", args.join(","));
    // Only when init's policy gave it one, so the requester's checks hold
    // without an environment.
    let env: Vec<String> = std::env::vars().map(|(key, value)| format!("{key}={value}")).collect();
    if !env.is_empty() {
        let _ = writeln!(stderr, "broker-echo env={}", env.join(","));
    }
    let mode = args.first().map(String::as_str).unwrap_or("0");
    match mode {
        "fault" => unsafe { core::arch::asm!("ud2", options(nomem, nostack)) },
        "flood" => {
            let block = [b'o'; 256];
            let other = [b'e'; 256];
            for _ in 0..32 {
                stdout.write_all(&block).unwrap();
                stdout.flush().unwrap();
                stderr.write_all(&other).unwrap();
            }
        }
        _ => {}
    }
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    stdout.write_all(&input).unwrap();
    stdout.flush().unwrap();
    std::process::exit(if mode == "flood" { 0 } else { mode.parse().unwrap_or(99) });
}
