#![feature(restricted_std)]
//! `/bin/sh-probe`: small deterministic commands for the shell matrix.
//!
//! * `flood N` writes N pattern bytes (`i % 251`) to stdout; a failed write
//!   is reported with its `io::ErrorKind` on stderr and the program goes on
//!   to exit 3 (a broken pipe is an error value, not a signal).
//! * `count` reads stdin to end-of-file and prints `COUNT bytes=N sum=S`
//!   (S the byte sum modulo 2^32).
//! * `head N` reads N bytes of stdin (fewer at end-of-file), prints them
//!   and exits without reading more.
//! * `escape PATH TARGET` tries to reach files beyond its streams: create
//!   PATH, open TARGET (the file its own stdout may be redirected to) for
//!   appending, and write the block device through its filesystem view;
//!   it prints what each attempt got.

use std::io::{Read, Write};

fn flood(count: usize) -> i32 {
    let pattern: Vec<u8> = (0..count).map(|i| (i % 251) as u8).collect();
    let mut out = std::io::stdout().lock();
    match out.write_all(&pattern).and_then(|()| out.flush()) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("sh-probe flood: write failed: {:?}; still running, exiting 3", error.kind());
            3
        }
    }
}

fn count() -> i32 {
    let mut bytes = Vec::new();
    if let Err(error) = std::io::stdin().lock().read_to_end(&mut bytes) {
        eprintln!("sh-probe count: read failed: {:?}", error.kind());
        return 1;
    }
    let sum = bytes.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)));
    println!("COUNT bytes={} sum={sum}", bytes.len());
    0
}

fn head(wanted: usize) -> i32 {
    let mut bytes = vec![0u8; wanted];
    let mut have = 0;
    let mut input = std::io::stdin().lock();
    while have < wanted {
        match input.read(&mut bytes[have..]) {
            Ok(0) => break,
            Ok(count) => have += count,
            Err(error) => {
                eprintln!("sh-probe head: read failed: {:?}", error.kind());
                return 1;
            }
        }
    }
    println!("HEAD {have} bytes={:?}", &bytes[..have]);
    0
}

fn escape(path: &str, target: &str) -> i32 {
    let kind = |result: std::io::Result<()>| match result {
        Ok(()) => "succeeded".to_owned(),
        Err(error) => format!("{:?}", error.kind()),
    };
    let create = kind(std::fs::write(path, b"escaped\n"));
    let target = kind(
        std::fs::OpenOptions::new()
            .append(true)
            .open(target)
            .and_then(|mut file| file.write_all(b"escaped\n")),
    );
    let sector = [0u8; 512];
    let raw = match absd_runtime::layout::write_raw(absd_runtime::block_handle(), 0, &sector) {
        Ok(()) => 0,
        Err(code) => code,
    };
    println!("ESCAPE create={create} target={target} raw-block={raw}");
    0
}

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let number = |text: &str| text.parse::<usize>().ok();
    let status = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["flood", n] if number(n).is_some() => flood(number(n).unwrap()),
        ["count"] => count(),
        ["head", n] if number(n).is_some() => head(number(n).unwrap()),
        ["escape", path, target] => escape(path, target),
        _ => {
            eprintln!("usage: sh-probe flood N | count | head N | escape PATH TARGET");
            2
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(status);
}
