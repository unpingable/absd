#![feature(restricted_std)]
//! The compatibility probe's durable worker (scripts/compat-matrix.py). It
//! mounts the filesystem read-only and runs each case of the script on its
//! standard input through `std::process::Command`: one case per line,
//! tab-separated, `STDIN PROGRAM ARG...`. `STDIN` is `-` for a null stdin,
//! else a file under `/data` whose bytes are written to the child's piped
//! stdin before its output is read (the inputs are small). Every child runs
//! in `/data` with piped stdout and stderr. Each case is reported in the
//! framing the host reproduces for the Linux reference run:
//!
//! ```text
//! == PROGRAM ARG...
//! <stdout bytes>
//! -- stderr
//! <stderr bytes>
//! -- status N
//! ```

use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn run(fields: &[&str], out: &mut impl Write) -> std::io::Result<()> {
    let (stdin, program, args) = (fields[0], fields[1], &fields[2..]);
    writeln!(out, "== {}", fields[1..].join(" "))?;
    let input = if stdin == "-" { None } else { Some(std::fs::read(format!("/data/{stdin}"))?) };
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir("/data")
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let result = match command.spawn() {
        Ok(mut child) => {
            if let Some(bytes) = input {
                // A child may exit without reading its input; as on Linux
                // (Python's `communicate`), that is not the case's failure.
                let mut pipe = child.stdin.take().expect("piped stdin");
                let _ = pipe.write_all(&bytes);
            }
            child.wait_with_output()
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(output) => {
            out.write_all(&output.stdout)?;
            writeln!(out, "-- stderr")?;
            out.write_all(&output.stderr)?;
            let status = output.status.code().map_or("none".to_string(), |c| c.to_string());
            writeln!(out, "-- status {status}")
        }
        Err(error) => writeln!(out, "-- spawn refused {:?}", error.kind()),
    }
}

fn main() {
    absd_runtime::link_anchor();
    if let Err(error) = absd_runtime::storage::mount(false, false) {
        println!("COMPAT LAUNCH FAILED mount {error:?}");
        std::process::exit(1);
    }
    let mut script = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut script) {
        println!("COMPAT LAUNCH FAILED script {error}");
        std::process::exit(1);
    }
    let mut out = std::io::stdout().lock();
    let mut cases = 0;
    for line in script.lines().filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 2 {
            let _ = writeln!(out, "COMPAT LAUNCH FAILED malformed case {line:?}");
            std::process::exit(1);
        }
        if let Err(error) = run(&fields, &mut out) {
            let _ = writeln!(out, "COMPAT LAUNCH FAILED {line:?}: {error}");
            std::process::exit(1);
        }
        cases += 1;
    }
    let _ = writeln!(out, "COMPAT LAUNCH DONE cases={cases}");
    let _ = out.flush();
}
