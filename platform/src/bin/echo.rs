#![feature(restricted_std)]
//! `echo [-n] ARG...`: the arguments separated by single spaces, then a
//! newline unless `-n` comes first.

use std::io::Write;

fn main() {
    absd_runtime::link_anchor();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let newline = args.first().map(String::as_str) != Some("-n");
    if !newline {
        args.remove(0);
    }
    let mut out = std::io::stdout().lock();
    let mut line = args.join(" ");
    if newline {
        line.push('\n');
    }
    if out.write_all(line.as_bytes()).and_then(|()| out.flush()).is_err() {
        std::process::exit(1);
    }
}
