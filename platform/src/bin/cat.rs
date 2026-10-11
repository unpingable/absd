#![feature(restricted_std)]
//! `cat [FILE...]`: each file's bytes in order (paths relative to the
//! working directory), or standard input when none is given or where a
//! file is `-`. A file that cannot be read is reported and makes the exit
//! status 1. A reader that has gone (`cat f | head`) ends cat quietly with
//! status 1, there being no SIGPIPE to do it; any other output failure is
//! reported once and ends it too.

#[path = "../cmd_flags.rs"]
mod cmd_flags;

use std::io::{ErrorKind, Read, Write};

enum Failed {
    Input(std::io::Error),
    Output(std::io::Error),
}

fn copy(input: &mut impl Read, out: &mut impl Write) -> Result<(), Failed> {
    let mut buffer = [0u8; 4096];
    loop {
        let count = input.read(&mut buffer).map_err(Failed::Input)?;
        if count == 0 {
            return Ok(());
        }
        out.write_all(&buffer[..count]).map_err(Failed::Output)?;
    }
}

fn output_failed(error: std::io::Error) -> ! {
    if error.kind() != ErrorKind::BrokenPipe {
        eprintln!("cat: standard output: {error}");
    }
    std::process::exit(1);
}

fn main() {
    absd_runtime::link_anchor();
    let mut paths: Vec<String> = std::env::args().skip(1).collect();
    cmd_flags::take("cat", &mut paths, &[]);
    if paths.is_empty() {
        paths.push("-".to_owned());
    }
    let mut out = std::io::stdout().lock();
    let mut status = 0;
    for path in &paths {
        let result = if path == "-" {
            copy(&mut std::io::stdin().lock(), &mut out)
        } else {
            match std::fs::File::open(path) {
                Ok(mut file) => copy(&mut file, &mut out),
                Err(error) => Err(Failed::Input(error)),
            }
        };
        match result {
            Ok(()) => {}
            Err(Failed::Input(error)) => {
                let _ = out.flush();
                let name = if path == "-" { "standard input" } else { path.as_str() };
                eprintln!("cat: {name}: {error}");
                status = 1;
            }
            Err(Failed::Output(error)) => output_failed(error),
        }
    }
    if let Err(error) = out.flush() {
        output_failed(error);
    }
    std::process::exit(status);
}
