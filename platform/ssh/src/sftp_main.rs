#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! Stdio worker of the SSH sftp subsystem, never a network listener.
use std::path::PathBuf;

fn main() {
    #[cfg(target_os = "absd")]
    absd_runtime::link_anchor();
    if std::env::args().len() != 1 {
        eprintln!("usage: absd-sftp (stdio subsystem; no arguments)");
        std::process::exit(2);
    }
    let home = if cfg!(target_os = "absd") {
        PathBuf::from("/home/operator")
    } else {
        match std::env::current_dir() {
            Ok(path) => path,
            Err(error) => {
                eprintln!("absd-sftp: {error}");
                std::process::exit(1);
            }
        }
    };
    if let Err(error) = absd_sshd::sftp::serve(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &home,
    ) {
        eprintln!("absd-sftp: {error}");
        std::process::exit(1);
    }
}
