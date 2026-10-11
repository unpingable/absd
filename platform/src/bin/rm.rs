#![feature(restricted_std)]
//! `rm [-r] PATH...`: removes each file (with `-r`, a directory and
//! everything below it). A directory without `-r` is refused. A mount
//! point of this session, and with `-r` a directory holding one, are
//! refused before anything is touched: the file server keeps mount points,
//! and `-r` would otherwise empty the mount before the refusal. A path that
//! cannot be removed is reported and makes the exit status 1.

#[path = "../cmd_flags.rs"]
mod cmd_flags;
#[path = "../cmd_mounts.rs"]
mod cmd_mounts;

use std::io::{Error, ErrorKind};

/// Why `path` is refused before the filesystem is asked, if it is.
fn refused(path: &str, recursive: bool) -> Option<&'static str> {
    let last = path.trim_end_matches('/').rsplit('/').next().unwrap_or(path);
    if last == "." || last == ".." {
        return Some("refusing to remove `.` or `..`");
    }
    if cmd_mounts::is_mount_point(path) {
        return Some("a mount point of this session; the file server keeps it");
    }
    if recursive {
        return match cmd_mounts::holds_mount(path) {
            Some(false) => None,
            Some(true) => Some("holds a mount point of this session; the file server keeps it"),
            None => Some("whether a mount point of this session lies below cannot be told; refused"),
        };
    }
    None
}

fn main() {
    absd_runtime::link_anchor();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let recursive = cmd_flags::take("rm", &mut args, &["-r"]).iter().any(|flag| flag == "-r");
    if args.is_empty() {
        eprintln!("rm: usage: rm [-r] PATH...");
        std::process::exit(2);
    }
    let mut status = 0;
    for path in &args {
        if let Some(reason) = refused(path, recursive) {
            eprintln!("rm: {path}: {reason}");
            status = 1;
            continue;
        }
        let result = match std::fs::metadata(path) {
            Ok(meta) if meta.is_dir() && recursive => std::fs::remove_dir_all(path),
            Ok(meta) if meta.is_dir() => Err(Error::new(ErrorKind::IsADirectory, "is a directory (use -r)")),
            Ok(_) => std::fs::remove_file(path),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            eprintln!("rm: {path}: {error}");
            status = 1;
        }
    }
    std::process::exit(status);
}
