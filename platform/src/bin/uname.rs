#![feature(restricted_std)]
//! `uname [-a | -r | -s]`: the system name; with `-r`, the release id this
//! program was built as (`docs/RELEASE.md`; the commands of `/bin` are the
//! selected release's, so it is the release being served; release(1) asks
//! the file server itself); with `-a`, the name, the release id, the
//! machine, the Rust target this program was built for, and the kernel's
//! PID for it. ABSD has no host name to report.

fn main() {
    absd_runtime::link_anchor();
    match std::env::args().nth(1).as_deref() {
        None | Some("-s") => println!("ABSD"),
        Some("-r") => println!("{}", absd_release::RELEASE_ID),
        Some("-a") => println!(
            "ABSD {} {} x86_64-unknown-absd pid={}",
            absd_release::RELEASE_ID,
            std::env::consts::ARCH,
            std::process::id()
        ),
        Some(other) => {
            eprintln!("uname: unknown option {other}");
            std::process::exit(2);
        }
    }
}
