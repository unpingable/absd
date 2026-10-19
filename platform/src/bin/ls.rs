#![feature(restricted_std, absd_fs_ext)]
//! `ls [-l] [PATH...]`: the names in each directory (the working directory
//! when none is given), sorted, a directory's with a trailing `/`; a file
//! path lists itself. With several paths each directory gets a `PATH:`
//! header. Exit 1 if any path cannot be listed. A reader that has gone
//! (`ls | head`) ends ls quietly with status 1.
//!
//! `-l` adds what the filesystem records and nothing else: the kind (`d`
//! directory, `-` file), the read-only flag (`ro`, or `--` when clear),
//! the link count, the size in bytes and modification time in UTC to the
//! minute (`-` if unknown). ABSD files have no owner, group, or mode.

#[path = "../cmd_flags.rs"]
mod cmd_flags;
#[path = "../cmd_mtime.rs"]
mod cmd_mtime;

use std::io::{ErrorKind, StdoutLock, Write};
use std::os::absd::fs::MetadataExt;

fn long(meta: &std::fs::Metadata, name: &str, width: usize) -> std::io::Result<String> {
    Ok(format!(
        "{} {} {} {:>width$} {} {name}",
        if meta.is_dir() { "d" } else { "-" },
        if meta.permissions().readonly() { "ro" } else { "--" },
        meta.links(),
        meta.len(),
        cmd_mtime::display(meta, false)?
    ))
}

/// A line of output; when the output has failed there is nothing more to
/// do (a gone reader is not an error of ls's own).
fn emit(out: &mut StdoutLock, line: &str) {
    if let Err(error) = out.write_all(line.as_bytes()).and_then(|()| out.write_all(b"\n")) {
        if error.kind() != ErrorKind::BrokenPipe {
            eprintln!("ls: standard output: {error}");
        }
        std::process::exit(1);
    }
}

/// Names, each with its metadata under `-l`.
fn print(out: &mut StdoutLock, rows: Vec<(String, Option<std::fs::Metadata>)>) -> std::io::Result<()> {
    let width = rows.iter().filter_map(|(_, m)| m.as_ref()).map(|m| m.len().to_string().len()).max().unwrap_or(1);
    for (name, meta) in rows {
        match meta {
            Some(meta) => emit(out, &long(&meta, &name, width)?),
            None => emit(out, &name),
        }
    }
    Ok(())
}

fn list(out: &mut StdoutLock, path: &str, header: bool, detail: bool) -> Result<(), std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_dir() {
        print(out, vec![(path.to_owned(), detail.then_some(metadata))])?;
        return Ok(());
    }
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let mut name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type()?.is_dir() {
            name.push('/');
        }
        let meta = if detail { Some(entry.metadata()?) } else { None };
        rows.push((name, meta));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    if header {
        emit(out, &format!("{path}:"));
    }
    print(out, rows)
}

fn main() {
    absd_runtime::link_anchor();
    let mut paths: Vec<String> = std::env::args().skip(1).collect();
    let detail = cmd_flags::take("ls", &mut paths, &["-l"]).iter().any(|flag| flag == "-l");
    if paths.is_empty() {
        paths.push(".".to_owned());
    }
    let header = paths.len() > 1;
    let mut out = std::io::stdout().lock();
    let mut status = 0;
    for path in &paths {
        if let Err(error) = list(&mut out, path, header, detail) {
            let _ = out.flush();
            eprintln!("ls: {path}: {error}");
            status = 1;
        }
    }
    if let Err(error) = out.flush() {
        if error.kind() != ErrorKind::BrokenPipe {
            eprintln!("ls: standard output: {error}");
        }
        status = 1;
    }
    std::process::exit(status);
}
