#![feature(restricted_std)]
//! `mkdir [-p] DIR...`: creates each directory (with `-p`, its missing
//! parents too, and an existing directory is not an error). A directory
//! that cannot be created is reported and makes the exit status 1.

#[path = "../cmd_flags.rs"]
mod cmd_flags;

fn main() {
    absd_runtime::link_anchor();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let parents = cmd_flags::take("mkdir", &mut args, &["-p"]).iter().any(|flag| flag == "-p");
    if args.is_empty() {
        eprintln!("mkdir: usage: mkdir [-p] DIR...");
        std::process::exit(2);
    }
    let mut status = 0;
    for path in &args {
        let result = if parents { std::fs::create_dir_all(path) } else { std::fs::create_dir(path) };
        if let Err(error) = result {
            eprintln!("mkdir: {path}: {error}");
            status = 1;
        }
    }
    std::process::exit(status);
}
