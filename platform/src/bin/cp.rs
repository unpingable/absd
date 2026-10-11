#![feature(restricted_std, absd_fs_ext)]
//! `cp [-r] SOURCE DEST` or `cp [-r] SOURCE... DIRECTORY`: copies each
//! file's bytes (with `-r`, a directory and everything below it) through
//! this process's own filesystem view, so it writes only where that view
//! is writable. Nothing but bytes is copied: ABSD files carry no owner,
//! mode, or times, and the read-only flag is not carried over. An object
//! that cannot be copied is reported, the rest of a tree is still copied,
//! and the exit status is 1. A file copy that fails part way removes the
//! new destination it had created, or reports it (and a destination that
//! already existed, whose old bytes are gone) as left incomplete.

#[path = "../cmd_flags.rs"]
mod cmd_flags;

use std::io;
use std::os::absd::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn same_object(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.filesystem_id() == b.filesystem_id() && a.object_serial() == b.object_serial()
}

fn report(from: &Path, to: &Path, error: io::Error) {
    eprintln!("cp: {} -> {}: {error}", from.display(), to.display());
}

fn copy_file(from: &Path, to: &Path) -> io::Result<()> {
    let source = std::fs::metadata(from)?;
    let existed = match std::fs::metadata(to) {
        Ok(target) if same_object(&source, &target) => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "source and destination are the same file"));
        }
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    let mut input = std::fs::File::open(from)?;
    let mut output = std::fs::File::create(to)?;
    if let Err(error) = io::copy(&mut input, &mut output) {
        drop(output);
        if !existed && std::fs::remove_file(to).is_ok() {
            return Err(error);
        }
        return Err(io::Error::new(error.kind(), format!("{error}; {} is left incomplete", to.display())));
    }
    Ok(())
}

/// Copies the directory `from` and everything below it; each object that
/// cannot be copied is reported and the rest goes on. Whether all of it
/// was copied.
fn copy_tree(from: &Path, to: &Path) -> bool {
    let prepared = (|| {
        // Refuse to copy a directory into itself (the copy would never end).
        let origin = std::fs::canonicalize(from)?;
        let parent = to.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let target = std::fs::canonicalize(parent)?.join(to.file_name().unwrap_or_default());
        if target.starts_with(&origin) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot copy a directory into itself"));
        }
        match std::fs::create_dir(to) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && std::fs::metadata(to)?.is_dir() => {}
            other => other?,
        }
        let mut names: Vec<_> =
            std::fs::read_dir(from)?.map(|e| e.map(|e| e.file_name())).collect::<Result<_, _>>()?;
        names.sort();
        Ok(names)
    })();
    let names: Vec<std::ffi::OsString> = match prepared {
        Ok(names) => names,
        Err(error) => {
            report(from, to, error);
            return false;
        }
    };
    let mut all = true;
    for name in names {
        let (from, to) = (from.join(&name), to.join(&name));
        let copied = match std::fs::metadata(&from) {
            Ok(meta) if meta.is_dir() => copy_tree(&from, &to),
            Ok(_) => copy_file(&from, &to).map_err(|error| report(&from, &to, error)).is_ok(),
            Err(error) => {
                report(&from, &to, error);
                false
            }
        };
        all &= copied;
    }
    all
}

fn main() {
    absd_runtime::link_anchor();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let recursive = cmd_flags::take("cp", &mut args, &["-r"]).iter().any(|flag| flag == "-r");
    if args.len() < 2 {
        eprintln!("cp: usage: cp [-r] SOURCE DEST | cp [-r] SOURCE... DIRECTORY");
        std::process::exit(2);
    }
    let dest = PathBuf::from(args.pop().unwrap());
    let into = std::fs::metadata(&dest).is_ok_and(|m| m.is_dir());
    if args.len() > 1 && !into {
        eprintln!("cp: {}: not a directory", dest.display());
        std::process::exit(1);
    }
    let mut status = 0;
    for source in &args {
        let from = Path::new(source);
        let to = match (into, from.file_name()) {
            (true, Some(name)) => dest.join(name),
            (true, None) => {
                eprintln!("cp: {source}: has no name to copy under {}", dest.display());
                status = 1;
                continue;
            }
            (false, _) => dest.clone(),
        };
        let result = match std::fs::metadata(from) {
            Ok(meta) if meta.is_dir() && !recursive => {
                Err(io::Error::new(io::ErrorKind::IsADirectory, "is a directory (use -r)"))
            }
            Ok(meta) if meta.is_dir() => {
                if !copy_tree(from, &to) {
                    status = 1;
                }
                continue;
            }
            Ok(_) => copy_file(from, &to),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            report(from, &to, error);
            status = 1;
        }
    }
    std::process::exit(status);
}
