#![feature(restricted_std)]
//! `sha256sum [FILE...]`: the SHA-256 of each file (standard input, named
//! `-`, when none is given) as `HEX  NAME`, the line format of GNU
//! coreutils. `sha256sum -c LIST` reads such lines from LIST and reports
//! `NAME: OK` or `NAME: FAILED` for each, exit 1 if any failed or could
//! not be read. The digest is the `sha2` crate's.

use sha2::{Digest, Sha256};
use std::io::Read;

fn digest(mut input: impl Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn check(list: &str) -> i32 {
    let text = match std::fs::read_to_string(list) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("sha256sum: {list}: {error}");
            return 1;
        }
    };
    let mut status = 0;
    for line in text.lines().filter(|l| !l.is_empty()) {
        let Some((expected, name)) = line.split_once("  ").filter(|(h, _)| h.len() == 64) else {
            eprintln!("sha256sum: {list}: improperly formatted line: {line}");
            status = 1;
            continue;
        };
        match std::fs::File::open(name).and_then(digest) {
            Ok(actual) if actual == expected.to_ascii_lowercase() => println!("{name}: OK"),
            Ok(_) => {
                println!("{name}: FAILED");
                status = 1;
            }
            Err(error) => {
                println!("{name}: FAILED open or read");
                eprintln!("sha256sum: {name}: {error}");
                status = 1;
            }
        }
    }
    status
}

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "-c") {
        let [_, list] = args.as_slice() else {
            eprintln!("sha256sum: usage: sha256sum -c LIST");
            std::process::exit(2);
        };
        std::process::exit(check(list));
    }
    if args.iter().any(|a| a.starts_with('-') && a != "-") {
        eprintln!("sha256sum: usage: sha256sum [FILE...] | sha256sum -c LIST");
        std::process::exit(2);
    }
    let mut status = 0;
    if args.is_empty() {
        match digest(std::io::stdin().lock()) {
            Ok(hex) => println!("{hex}  -"),
            Err(error) => {
                eprintln!("sha256sum: -: {error}");
                status = 1;
            }
        }
    }
    for path in &args {
        let result = if path == "-" { digest(std::io::stdin().lock()) } else { std::fs::File::open(path).and_then(digest) };
        match result {
            Ok(hex) => println!("{hex}  {path}"),
            Err(error) => {
                eprintln!("sha256sum: {path}: {error}");
                status = 1;
            }
        }
    }
    std::process::exit(status);
}
