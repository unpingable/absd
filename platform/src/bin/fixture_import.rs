#![feature(restricted_std)]
//! Carries opaque files from the host into the ABSD filesystem.
//!
//! Input (stdin): `ABSDFIX1`, then per file a `u16` path length, the
//! absolute path, a `u64` byte length, the file's SHA-256, and its bytes; a
//! zero path length ends the stream. Every file is constructed in a new
//! temporary object, synced, read back and verified before atomic rename
//! on the real filesystem. A path ending in `/` with zero bytes is a
//! directory, created (with its parents) and left empty. The importer knows
//! paths and bytes only; it interprets no file format.
//!
//! Step word: 1 imports into a blank device (permitting formatting it);
//! 2 adds files to an existing filesystem. Both commit with rename-no-replace.
//! 3 copies an existing writable file's committed prefix, adds the entry's
//! bytes and replaces the final name only after prefix and suffix readback.
//! Steps 2/3 carry large fixtures across boots: each final path is a verified
//! prefix until the host checks the whole file. Replaying an uncertain step 3
//! requires host reconciliation to avoid appending twice.
//! 4 replaces a file whole with the same verified-temp construction.
//! 5 removes trees: every entry is a directory entry (`PATH/`, zero bytes),
//! and the directory at `PATH`, with everything below it, is removed in one
//! commit, so a stop at any point leaves the whole tree or none of it (the
//! host tool's release removal, `scripts/release.py remove`); `/` is
//! refused, and so is a path that is absent or not a directory.
//! 0 does nothing, so a durable boot can run only its reader.

use std::io::Read;

#[path = "../fixture_import_file.rs"]
mod file;
use file::Boundary;

use absd_runtime::storage;
use sha2::{Digest as _, Sha256};

const CHUNK: usize = file::CHUNK;

fn exact(input: &mut impl Read, buffer: &mut [u8]) -> Result<(), String> {
    input
        .read_exact(buffer)
        .map_err(|_| "truncated fixture stream".to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Streams each file straight to the filesystem in bounded chunks: no
/// allocation grows with the fixture (ABSD maps at most 256 KiB at once).
fn import(step: u64) -> Result<usize, String> {
    let (format, remove) = (step == 1, step == 5);
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
    println!(
        "FS MOUNT OK formatted={} seq={}",
        mounted.formatted, mounted.sequence
    );
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
        if file::reserved_path(&path) && !remove {
            return Err(format!("{path}: reserved importer temporary component"));
        }
        let mut size = [0u8; 8];
        exact(&mut input, &mut size)?;
        let size = u64::from_le_bytes(size);
        let mut digest = [0u8; 32];
        exact(&mut input, &mut digest)?;
        println!(
            "FIXTURE ENTRY index={} path_hex={} step={step}",
            files + 1,
            hex(path.as_bytes())
        );
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
            if !std::fs::metadata(directory)
                .map_err(|e| format!("{path}: {e}"))?
                .is_dir()
            {
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
            if !std::fs::metadata(directory)
                .map_err(|e| format!("{path}: {e}"))?
                .is_dir()
            {
                return Err(format!("{path}: not a directory after creation"));
            }
            println!("FIXTURE DIRECTORY path={directory}");
            files += 1;
            continue;
        }
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
        }
        let start = storage::with_fs(|fs| {
            file::import_file(
                fs,
                &mut input,
                step,
                &path,
                size,
                digest,
                &mut chunk,
                |point, fs, temp| {
                    if matches!(point, Boundary::DirectoryCreated | Boundary::Created) {
                        let attr = fs
                            .stat(temp.as_bytes())
                            .map_err(|error| format!("{error:?}"))?;
                        println!(
                            "FIXTURE TEMP path_hex={} final_hex={} fs_id={} serial={} kind={:?}",
                            hex(temp.as_bytes()),
                            hex(path.as_bytes()),
                            attr.fs_id,
                            attr.serial,
                            attr.kind
                        );
                    }
                    // Qualification build only. Cargo tracks the setting in the
                    // executable's inputs; normal builds select no boundary.
                    if option_env!("ABSD_FIXTURE_IMPORT_STOP") == Some(point.name()) {
                        println!("FIXTURE IMPORT STOP boundary={} final={path}", point.name());
                        std::process::exit(96);
                    }
                    Ok(())
                },
            )
        })
        .ok_or_else(|| "no filesystem mounted".to_owned())?
        .map_err(|error| format!("{path}: {error}"))?;
        println!(
            "FIXTURE FILE path={path} offset={start} bytes={size} sha256={}",
            hex(&digest)
        );
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
    if let Some(stop) = option_env!("ABSD_FIXTURE_IMPORT_STOP") {
        let valid = [
            Boundary::DirectoryCreated,
            Boundary::Created,
            Boundary::PrefixCopied,
            Boundary::InputWritten,
            Boundary::Synced,
            Boundary::Verified,
            Boundary::Renamed,
        ];
        if !valid.iter().any(|point| point.name() == stop) {
            println!("FIXTURE IMPORT FAILED invalid qualification stop");
            std::process::exit(95);
        }
    }
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
