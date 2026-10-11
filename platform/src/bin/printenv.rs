#![feature(restricted_std)]
//! `printenv [NAME...]`: every `KEY=VALUE` of the environment, sorted, or
//! the value of each name given (exit 1 if one is unset).

fn main() {
    absd_runtime::link_anchor();
    let names: Vec<String> = std::env::args().skip(1).collect();
    if names.is_empty() {
        let mut vars: Vec<(String, String)> = std::env::vars().collect();
        vars.sort();
        for (key, value) in vars {
            println!("{key}={value}");
        }
        return;
    }
    let mut status = 0;
    for name in &names {
        match std::env::var(name) {
            Ok(value) => println!("{value}"),
            Err(_) => status = 1,
        }
    }
    std::process::exit(status);
}
