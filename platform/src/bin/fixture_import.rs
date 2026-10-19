#![feature(restricted_std)]
//! Carries opaque files from the host into the ABSD filesystem.
//!
//! Input (stdin): `ABSDFIX1`, then per file a `u16` path length, the
//! absolute path, a `u64` byte length, the file's SHA-256, and its bytes; a
//! zero path length ends the stream. Every file is created new, written,
//! synced, read back, and checked against its digest through `std::fs` on
//! the real filesystem. A path ending in `/` with zero bytes is a
//! directory, created (with its parents) and left empty. The importer knows
//! paths and bytes only; it interprets no file format.
//!
//! Step word: 1 imports into a fresh device (formatting it); 2 adds files to
//! the filesystem already on the device (each still created new, so nothing
//! present is replaced); 3 appends each entry's bytes to the existing file
//! at its path, and the digest checked is that of the appended bytes, read
//! back from where they landed. Steps 2 and 3 carry a fixture too large for
//! one boot's worker deadline across boots; the host checks whole files.
//! 4 replaces each file whole, as one commit: the bytes go to `PATH.new`
//! (created new, after removing a stale one), are synced and checked, and
//! `PATH.new` is renamed over `PATH`, so a stop at any point leaves the old
//! file or the new one (the operator image's reconfiguration of `/etc`).
//! 5 removes trees: every entry is a directory entry (`PATH/`, zero bytes),
//! and the directory at `PATH`, with everything below it, is removed in one
//! commit, so a stop at any point leaves the whole tree or none of it (the
//! host tool's release removal, `scripts/release.py remove`); `/` is
//! refused, and so is a path that is absent or not a directory.
//! 0 does nothing, so a durable boot can run only its reader.

use std::io::{Read, Seek as _, SeekFrom, Write as _};

use absd_runtime::storage;
use sha2::{Digest as _, Sha256};

const CHUNK: usize = 64 * 1024;

fn exact(input: &mut impl Read, buffer: &mut [u8]) -> Result<(), String> {
    input.read_exact(buffer).map_err(|_| "truncated fixture stream".to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Streams each file straight to the filesystem in bounded chunks: no
/// allocation grows with the fixture (ABSD maps at most 256 KiB at once).
fn import(step: u64) -> Result<usize, String> {
    let (format, append, replace, remove) = (step == 1, step == 3, step == 4, step == 5);
    let mut input = std::io::stdin().lock();
    let mut magic = [0u8; 8];
    exact(&mut input, &mut magic)?;
    if &magic != b"ABSDFIX1" {
        return Err("not a fixture stream".to_owned());
    }
    let mounted = storage::mount(format, true).map_err(|e| format!("{e:?}"))?;
    if !format && mounted.formatted {
        return Err("step 2 needs a filesystem already on the device".to_owned());
    }
    println!("FS MOUNT OK formatted={} seq={}", mounted.formatted, mounted.sequence);
    let mut chunk = vec![0u8; CHUNK];
    let mut files = 0;
    loop {
        let mut length = [0u8; 2];
        exact(&mut input, &mut length)?;
        let length = u16::from_le_bytes(length) as usize;
        if length == 0 {
            break;
        }
        let mut name = vec![0u8; length];
        exact(&mut input, &mut name)?;
        let path = String::from_utf8(name).map_err(|e| e.to_string())?;
        let mut size = [0u8; 8];
        exact(&mut input, &mut size)?;
        let size = u64::from_le_bytes(size);
        let mut digest = [0u8; 32];
        exact(&mut input, &mut digest)?;
        if remove {
            let Some(directory) = path.strip_suffix('/') else {
                return Err(format!("{path}: step 5 removes directories only"));
            };
            if size != 0 || digest != <[u8; 32]>::from(Sha256::digest([])) {
                return Err(format!("{path}: a directory carries no bytes"));
            }
            if directory.is_empty() || !directory.starts_with('/') {
                return Err(format!("{path}: not a removable directory"));
            }
            if !std::fs::metadata(directory).map_err(|e| format!("{path}: {e}"))?.is_dir() {
                return Err(format!("{path}: not a directory"));
            }
            let removed = storage::with_fs(|fs| fs.remove_tree(directory.as_bytes(), true))
                .ok_or_else(|| "no filesystem mounted".to_owned())?
                .map_err(|e| format!("{path}: {e:?}"))?;
            match std::fs::metadata(directory) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(format!("{path}: still present after its removal")),
            }
            println!("FIXTURE REMOVED path={directory} objects={removed}");
            files += 1;
            continue;
        }
        if let Some(directory) = path.strip_suffix('/') {
            if size != 0 || digest != <[u8; 32]>::from(Sha256::digest([])) {
                return Err(format!("{path}: a directory carries no bytes"));
            }
            std::fs::create_dir_all(directory).map_err(|e| format!("{path}: {e}"))?;
            if !std::fs::metadata(directory).map_err(|e| format!("{path}: {e}"))?.is_dir() {
                return Err(format!("{path}: not a directory after creation"));
            }
            println!("FIXTURE DIRECTORY path={directory}");
            files += 1;
            continue;
        }
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
        }
        let target = if replace { format!("{path}.new") } else { path.clone() };
        if replace {
            match std::fs::remove_file(&target) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{target}: {e}")),
                _ => {}
            }
        }
        let mut file = if append {
            std::fs::OpenOptions::new().append(true).open(&target)
        } else {
            std::fs::OpenOptions::new().write(true).create_new(true).open(&target)
        }
        .map_err(|e| format!("{target}: {e}"))?;
        let start = file.metadata().map_err(|e| format!("{path}: {e}"))?.len();
        let mut remaining = size;
        while remaining > 0 {
            let take = remaining.min(CHUNK as u64) as usize;
            exact(&mut input, &mut chunk[..take])?;
            file.write_all(&chunk[..take]).map_err(|e| format!("{path}: {e}"))?;
            remaining -= take as u64;
        }
        file.sync_all().map_err(|e| format!("{path}: {e}"))?;
        drop(file);
        let mut back = std::fs::File::open(&target).map_err(|e| format!("{target}: {e}"))?;
        back.seek(SeekFrom::Start(start)).map_err(|e| format!("{path}: {e}"))?;
        let mut hasher = Sha256::new();
        let mut read_back = 0u64;
        loop {
            let count = back.read(&mut chunk).map_err(|e| format!("{path}: {e}"))?;
            if count == 0 {
                break;
            }
            hasher.update(&chunk[..count]);
            read_back += count as u64;
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != digest || read_back != size {
            return Err(format!("{path}: read back {read_back} bytes with a different digest"));
        }
        drop(back);
        if replace {
            std::fs::rename(&target, &path).map_err(|e| format!("{path}: {e}"))?;
        }
        println!("FIXTURE FILE path={path} offset={start} bytes={size} sha256={}", hex(&actual));
        files += 1;
    }
    let mut trailing = [0u8; 1];
    if input.read(&mut trailing).map_err(|e| e.to_string())? != 0 {
        return Err("bytes after the fixture stream".to_owned());
    }
    Ok(files)
}

fn main() {
    absd_runtime::link_anchor();
    match absd_runtime::step() {
        0 => println!("FIXTURE IMPORT SKIPPED"),
        step @ (1..=5) => match import(step) {
            Ok(files) => println!("FIXTURE IMPORT OK files={files}"),
            Err(error) => {
                println!("FIXTURE IMPORT FAILED {error}");
                std::process::exit(95);
            }
        },
        other => {
            println!("FIXTURE IMPORT FAILED unknown step {other}");
            std::process::exit(95);
        }
    }
}
