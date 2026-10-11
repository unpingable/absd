#![feature(restricted_std)]
//! `wc [-l] [-w] [-c] [FILE...]`: newline, word, and byte counts of each
//! file (standard input when none is given), in that order, with a `total`
//! line for several files. With flags, only the counts asked for. Words
//! are runs of bytes other than ASCII whitespace. Columns are right-aligned
//! to the widest number printed. Exit 1 if a file cannot be read.

use std::io::Read;

#[derive(Default, Clone, Copy)]
struct Counts {
    lines: u64,
    words: u64,
    bytes: u64,
}

fn count(mut input: impl Read) -> std::io::Result<Counts> {
    let mut counts = Counts::default();
    let mut in_word = false;
    let mut buffer = [0u8; 4096];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            return Ok(counts);
        }
        counts.bytes += n as u64;
        for &byte in &buffer[..n] {
            if byte == b'\n' {
                counts.lines += 1;
            }
            if byte.is_ascii_whitespace() {
                in_word = false;
            } else if !in_word {
                in_word = true;
                counts.words += 1;
            }
        }
    }
}

fn main() {
    absd_runtime::link_anchor();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let (mut lines, mut words, mut bytes) = (false, false, false);
    while let Some(flag) = args.first().filter(|a| a.starts_with('-') && a.len() > 1).cloned() {
        for letter in flag[1..].chars() {
            match letter {
                'l' => lines = true,
                'w' => words = true,
                'c' => bytes = true,
                _ => {
                    eprintln!("wc: usage: wc [-l] [-w] [-c] [FILE...]");
                    std::process::exit(2);
                }
            }
        }
        args.remove(0);
    }
    if !(lines || words || bytes) {
        (lines, words, bytes) = (true, true, true);
    }
    let mut rows: Vec<(Counts, Option<String>)> = Vec::new();
    let mut status = 0;
    if args.is_empty() {
        match count(std::io::stdin().lock()) {
            Ok(counts) => rows.push((counts, None)),
            Err(error) => {
                eprintln!("wc: standard input: {error}");
                status = 1;
            }
        }
    }
    for path in &args {
        match std::fs::File::open(path).and_then(count) {
            Ok(counts) => rows.push((counts, Some(path.clone()))),
            Err(error) => {
                eprintln!("wc: {path}: {error}");
                status = 1;
            }
        }
    }
    if args.len() > 1 {
        let mut total = Counts::default();
        for (counts, _) in &rows {
            total.lines += counts.lines;
            total.words += counts.words;
            total.bytes += counts.bytes;
        }
        rows.push((total, Some("total".to_owned())));
    }
    let fields = |c: &Counts| {
        let mut v = Vec::new();
        if lines {
            v.push(c.lines);
        }
        if words {
            v.push(c.words);
        }
        if bytes {
            v.push(c.bytes);
        }
        v
    };
    let width = rows.iter().flat_map(|(c, _)| fields(c)).map(|n| n.to_string().len()).max().unwrap_or(1);
    for (counts, name) in &rows {
        let mut line: Vec<String> = fields(counts).iter().map(|n| format!("{n:>width$}")).collect();
        if let Some(name) = name {
            line.push(name.clone());
        }
        println!("{}", line.join(" "));
    }
    std::process::exit(status);
}
