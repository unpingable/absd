#![feature(restricted_std)]
//! `head [-n LINES | -c BYTES] [FILE...]`: the first 10 lines (or the
//! given count of lines or bytes) of each file, or of standard input when
//! none is given. With several files each gets a `==> FILE <==` header. It
//! stops reading once it has enough. Exit 1 if a file cannot be read.

use std::io::{BufRead, BufReader, Read, Write};

enum Count {
    Lines(u64),
    Bytes(u64),
}

fn head(input: impl Read, count: &Count, out: &mut impl Write) -> std::io::Result<()> {
    let mut input = BufReader::with_capacity(4096, input);
    match *count {
        Count::Bytes(n) => {
            std::io::copy(&mut input.take(n), out)?;
        }
        Count::Lines(n) => {
            let mut line = Vec::new();
            for _ in 0..n {
                line.clear();
                if input.read_until(b'\n', &mut line)? == 0 {
                    break;
                }
                out.write_all(&line)?;
            }
        }
    }
    Ok(())
}

fn parse(args: &mut Vec<String>) -> Option<Count> {
    let mut count = Count::Lines(10);
    while let Some(flag) = args.first().cloned() {
        let make: fn(u64) -> Count = match flag.as_str() {
            "-n" => Count::Lines,
            "-c" => Count::Bytes,
            _ if flag.starts_with('-') && flag.len() > 1 => return None,
            _ => break,
        };
        let value = args.get(1)?.parse().ok()?;
        count = make(value);
        args.drain(..2);
    }
    Some(count)
}

fn main() {
    absd_runtime::link_anchor();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let Some(count) = parse(&mut args) else {
        eprintln!("head: usage: head [-n LINES | -c BYTES] [FILE...]");
        std::process::exit(2);
    };
    let mut out = std::io::stdout().lock();
    let mut status = 0;
    if args.is_empty() {
        if head(std::io::stdin().lock(), &count, &mut out).is_err() {
            status = 1;
        }
    }
    let headers = args.len() > 1;
    for (i, path) in args.iter().enumerate() {
        let result = std::fs::File::open(path).and_then(|file| {
            if headers {
                write!(out, "{}==> {path} <==\n", if i > 0 { "\n" } else { "" })?;
            }
            head(file, &count, &mut out)
        });
        if let Err(error) = result {
            let _ = out.flush();
            eprintln!("head: {path}: {error}");
            status = 1;
        }
    }
    let _ = out.flush();
    std::process::exit(status);
}
