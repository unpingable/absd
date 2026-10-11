#![feature(restricted_std)]
//! `man [SECTION] NAME` prints a manual page; `man -k WORD` lists the pages
//! whose name or one-line description contains WORD (ASCII case ignored).
//!
//! Pages are plain text, rendered from mdoc(7) sources on the build host
//! (scripts/render-man.sh) and installed as `/share/man/catS/NAME.0`; the
//! index `man -k` reads is `/share/man/whatis`. There is no roff on ABSD
//! and no pager: the page is copied to standard output as it is.
//! Without SECTION the sections are searched in the order 1, 8, 6, 2, 3,
//! 5, 7, 4, 9 and the first page found is printed. Exit 0 when a page (or
//! a `-k` match) was printed, 1 when there was none or it could not be
//! read, 2 for a usage error.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};

const ROOT: &str = "/share/man";
const ORDER: [char; 9] = ['1', '8', '6', '2', '3', '5', '7', '4', '9'];

fn usage() -> ! {
    eprintln!("man: usage: man [SECTION] NAME | man -k WORD");
    std::process::exit(2);
}

/// A page name: letters, digits, `.`, `_`, `-`, not starting with `.`.
/// Anything else (a path, `..`) is not a page name.
fn page_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn fail(message: String) -> ! {
    eprintln!("man: {message}");
    std::process::exit(1);
}

/// Refuses with a clear reason when this process sees no manual at all
/// (for example under `nofs`), rather than reporting every page missing.
fn require_manual() {
    if let Err(error) = std::fs::metadata(ROOT) {
        fail(format!("{ROOT}: {error}: no manual is visible to this process"));
    }
}

fn apropos(word: &str) {
    require_manual();
    let index = format!("{ROOT}/whatis");
    let file = std::fs::File::open(&index).unwrap_or_else(|e| fail(format!("{index}: {e}")));
    let needle = word.to_ascii_lowercase();
    let mut out = std::io::stdout().lock();
    let mut found = false;
    for line in BufReader::new(file).lines() {
        let line = line.unwrap_or_else(|e| fail(format!("{index}: {e}")));
        if line.to_ascii_lowercase().contains(&needle) {
            let _ = writeln!(out, "{line}");
            found = true;
        }
    }
    let _ = out.flush();
    if !found {
        fail(format!("{word}: nothing appropriate"));
    }
}

/// Copies the page to standard output. A reader that has gone (`man X |
/// head`) ends `man` quietly with status 1: there is no SIGPIPE to do it.
fn print(mut file: std::fs::File, path: &str) {
    let mut out = std::io::stdout().lock();
    let mut buffer = [0u8; 4096];
    loop {
        let count = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) => fail(format!("{path}: {error}")),
        };
        if let Err(error) = out.write_all(&buffer[..count]) {
            if error.kind() == ErrorKind::BrokenPipe {
                std::process::exit(1);
            }
            fail(format!("standard output: {error}"));
        }
    }
    match out.flush() {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::BrokenPipe => std::process::exit(1),
        Err(error) => fail(format!("standard output: {error}")),
    }
}

fn show(section: Option<char>, name: &str) {
    if !page_name(name) {
        eprintln!("man: {name}: not a page name");
        std::process::exit(2);
    }
    require_manual();
    let sections: Vec<char> = match section {
        Some(s) => vec![s],
        None => ORDER.to_vec(),
    };
    for s in sections {
        let path = format!("{ROOT}/cat{s}/{name}.0");
        match std::fs::File::open(&path) {
            Ok(file) => return print(file, &path),
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => fail(format!("{path}: {error}")),
        }
    }
    match section {
        Some(s) => fail(format!("no entry for {name} in section {s} of the manual")),
        None => fail(format!("no entry for {name} in the manual")),
    }
}

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let section = |s: &str| {
        let mut chars = s.chars();
        match (chars.next(), chars.next()) {
            (Some(c @ '1'..='9'), None) => Some(c),
            _ => None,
        }
    };
    match args.as_slice() {
        ["-k", word] if !word.is_empty() => apropos(word),
        [flag, ..] if flag.starts_with('-') => usage(),
        [name] => show(None, name),
        [s, name] => match section(s) {
            Some(c) => show(Some(c), name),
            None => usage(),
        },
        _ => usage(),
    }
}
