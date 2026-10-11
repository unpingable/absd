#![feature(restricted_std, absd_fs_ext)]
//! `mv FROM TO`: renames FROM to TO in one filesystem commit, replacing a
//! file at TO; when TO is an existing directory, FROM moves into it under
//! its own name. Nothing is copied: both names must be where this process
//! may write.

#[path = "../cmd_flags.rs"]
mod cmd_flags;
#[path = "../cmd_mounts.rs"]
mod cmd_mounts;

use std::os::absd::fs::MetadataExt;
use std::path::Path;

fn fail(from: &str, to: &str, reason: impl std::fmt::Display) -> ! {
    eprintln!("mv: {from} -> {to}: {reason}");
    std::process::exit(1);
}

fn main() {
    absd_runtime::link_anchor();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    cmd_flags::take("mv", &mut args, &[]);
    let [from, to] = args.as_slice() else {
        eprintln!("mv: usage: mv FROM TO");
        std::process::exit(2);
    };
    let source = std::fs::metadata(from).unwrap_or_else(|error| fail(from, to, error));
    let mut target = to.clone();
    if std::fs::metadata(to).is_ok_and(|m| m.is_dir()) {
        let Some(name) = Path::new(from).file_name() else {
            fail(from, to, "has no name to move into a directory");
        };
        target = format!("{}/{}", to.trim_end_matches('/'), name.to_string_lossy());
    }
    if let Ok(existing) = std::fs::metadata(&target) {
        if existing.filesystem_id() == source.filesystem_id() && existing.object_serial() == source.object_serial() {
            fail(from, &target, "source and destination are the same object");
        }
    }
    if cmd_mounts::is_mount_point(from) || cmd_mounts::is_mount_point(&target) {
        fail(from, &target, "a mount point of this session; the file server keeps it");
    }
    if source.is_dir() {
        // Refused by the file server too, with a message that says less.
        let origin = std::fs::canonicalize(from).unwrap_or_else(|error| fail(from, &target, error));
        let path = Path::new(&target);
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let resolved = std::fs::canonicalize(parent)
            .unwrap_or_else(|error| fail(from, &target, error))
            .join(path.file_name().unwrap_or_default());
        if resolved.starts_with(&origin) {
            fail(from, &target, "cannot move a directory into itself");
        }
    }
    if let Err(error) = std::fs::rename(from, &target) {
        fail(from, &target, error);
    }
}
