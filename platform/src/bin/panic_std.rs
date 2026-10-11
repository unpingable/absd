#![feature(restricted_std)]

fn main() {
    absd_runtime::link_anchor();
    panic!("ABSD deliberate panic probe");
}
