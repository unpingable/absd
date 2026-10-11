#![feature(restricted_std)]

fn main() {
    absd_runtime::link_anchor();
    println!("ABSD STD EXIT OK code=0");
    std::process::exit(0);
}
