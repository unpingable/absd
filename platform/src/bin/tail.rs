#![feature(restricted_std)]
//! `tail [-n LINES | -c BYTES] [FILE...]`: the last 10 lines (or the given
//! count of lines or bytes) of each file, or of standard input when none
//! is given. A file is read backwards from its end, so only its tail
//! crosses the file server; standard input is read to its end. With
//! several files each gets a `==> FILE <==` header. No `-f`: nothing
//! reports that a file grew except reading it again. Exit 1 if a file
//! cannot be read.

use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom, Write};

enum Count {
    Lines(u64),
    Bytes(u64),
}

const CHUNK: u64 = 4096;

/// Where the last `n` lines of `file` (of `length` bytes) begin.
fn lines_start(file: &mut std::fs::File, length: u64, n: u64) -> std::io::Result<u64> {
    if n == 0 {
        return Ok(length);
    }
    let mut end = length;
    let mut newlines = 0;
    let mut buffer = vec![0u8; CHUNK as usize];
    // A final newline ends the last line; it does not start another.
    let mut skip_final = true;
    while end > 0 {
        let start = end.saturating_sub(CHUNK);
        let chunk = &mut buffer[..(end - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(chunk)?;
        for (i, byte) in chunk.iter().enumerate().rev() {
            if *byte == b'\n' {
                if skip_final && start + i as u64 == length - 1 {
                    continue;
                }
                newlines += 1;
                if newlines == n {
                    return Ok(start + i as u64 + 1);
                }
            }
        }
        skip_final = false;
        end = start;
    }
    Ok(0)
}

fn tail_file(path: &str, count: &Count, out: &mut impl Write) -> std::io::Result<()> {
    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    let start = match *count {
        Count::Bytes(n) => length.saturating_sub(n),
        Count::Lines(n) => lines_start(&mut file, length, n)?,
    };
    file.seek(SeekFrom::Start(start))?;
    std::io::copy(&mut file, out)?;
    Ok(())
}

fn tail_stream(mut input: impl Read, count: &Count, out: &mut impl Write) -> std::io::Result<()> {
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;
    let start = match *count {
        Count::Bytes(n) => data.len().saturating_sub(n as usize),
        Count::Lines(n) => {
            let mut starts: VecDeque<usize> = VecDeque::new();
            let mut at = 0;
            while at < data.len() {
                starts.push_back(at);
                if starts.len() as u64 > n {
                    starts.pop_front();
                }
                at = data[at..].iter().position(|b| *b == b'\n').map_or(data.len(), |i| at + i + 1);
            }
            if n == 0 { data.len() } else { starts.front().copied().unwrap_or(data.len()) }
        }
    };
    out.write_all(&data[start..])
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
        eprintln!("tail: usage: tail [-n LINES | -c BYTES] [FILE...]");
        std::process::exit(2);
    };
    let mut out = std::io::stdout().lock();
    let mut status = 0;
    if args.is_empty() {
        if tail_stream(std::io::stdin().lock(), &count, &mut out).is_err() {
            status = 1;
        }
    }
    let headers = args.len() > 1;
    for (i, path) in args.iter().enumerate() {
        if headers {
            let _ = write!(out, "{}==> {path} <==\n", if i > 0 { "\n" } else { "" });
        }
        if let Err(error) = tail_file(path, &count, &mut out) {
            let _ = out.flush();
            eprintln!("tail: {path}: {error}");
            status = 1;
        }
    }
    let _ = out.flush();
    std::process::exit(status);
}
