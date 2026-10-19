#![feature(restricted_std, absd_fs_ext)]
//! `stat PATH...`: what the filesystem records for each object: its kind,
//! size, read-only flag, identity (filesystem id and object serial, never
//! reused), and link count, and, when this process reaches the filesystem
//! through the file server, the mount of this session's binding that holds
//! it and whether that mount is writable here. ABSD files have no owner,
//! or mode. Modification time is shown in UTC, or unknown when absent.
//! Exit 1 if a path cannot be examined.

use std::os::absd::fs::MetadataExt;

#[path = "../cmd_mtime.rs"]
mod cmd_mtime;

#[path = "../cmd_mounts.rs"]
mod cmd_mounts;

fn mount_line(path: &str) -> Option<String> {
    if !absd_runtime::fsd::active() {
        return None;
    }
    Some(match cmd_mounts::mount_of(path) {
        Some(m) => format!(
            "mount: {} ({})",
            String::from_utf8_lossy(&m.path),
            if m.writable { "read-write" } else { "read-only" }
        ),
        // A directory leading to mounts (such as `/` or `/home`).
        None => "mount: none (a directory on the way to this session's mounts; read-only)".to_owned(),
    })
}

fn main() {
    absd_runtime::link_anchor();
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("stat: usage: stat PATH...");
        std::process::exit(2);
    }
    let mut status = 0;
    for path in &paths {
        match std::fs::metadata(path) {
            Ok(meta) => {
                println!("path: {path}");
                println!("type: {}", if meta.is_dir() { "directory" } else { "file" });
                println!("size: {}", meta.len());
                println!("read-only flag: {}", if meta.permissions().readonly() { "yes" } else { "no" });
                println!("object: filesystem={:016x} serial={}", meta.filesystem_id(), meta.object_serial());
                println!("links: {}", meta.links());
                match cmd_mtime::display(&meta, true) {
                    Ok(time) => println!("modified: {time}"),
                    Err(error) => { eprintln!("stat: {path}: {error}"); status = 1; }
                }
                if let Some(line) = mount_line(path) {
                    println!("{line}");
                }
            }
            Err(error) => {
                eprintln!("stat: {path}: {error}");
                status = 1;
            }
        }
    }
    std::process::exit(status);
}
