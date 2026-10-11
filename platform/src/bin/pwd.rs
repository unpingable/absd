#![feature(restricted_std)]
//! `pwd`: the working directory the process started with (its startup
//! record's, else `/`).

fn main() {
    absd_runtime::link_anchor();
    match std::env::current_dir() {
        Ok(directory) => println!("{}", directory.display()),
        Err(error) => {
            eprintln!("pwd: {error}");
            std::process::exit(1);
        }
    }
}
