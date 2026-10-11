#![feature(restricted_std)]
//! `release`: which ABSD release this machine is serving, as one line of
//! `key=value` fields in the release record's order (`docs/RELEASE.md`
//! section 2): `release`, `fsd_protocol`, and `fs_format` are the file
//! server's own answer (`op::VERSION`), so they name what the server was
//! built as; `kernel_abi` and `app_abi` are the generations this command
//! was built for, which the runtime has already found the kernel to match
//! (it refuses to start otherwise, status 103). Exit 1 when no file server
//! answers this process or its answer is refused.

fn main() {
    absd_runtime::link_anchor();
    if std::env::args().len() > 1 {
        eprintln!("release: usage: release");
        std::process::exit(2);
    }
    if !absd_runtime::fsd::active() {
        eprintln!("release: no file server serves this process; the release is the file server's to name");
        std::process::exit(1);
    }
    match absd_runtime::fsd::check_server(0, false) {
        Ok(server) => println!(
            "release={} kernel_abi={} fsd_protocol={} fs_format={} app_abi={}",
            String::from_utf8_lossy(&server.release),
            absd_release::KERNEL_ABI,
            server.fsd_protocol,
            server.fs_format,
            absd_release::APP_ABI
        ),
        Err(refusal) => {
            eprintln!("release: {}", refusal.line());
            std::process::exit(1);
        }
    }
}
