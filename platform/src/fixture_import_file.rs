//! One verified file commit for the fixture importer. No stream framing here.
//! The caller owns the sole writable mount of a halted image.

use absd_fs::{BLOCK, Device, Error, Fs, Kind, OpenFlags};
use sha2::{Digest as _, Sha256};
use std::io::Read;

pub const CHUNK: usize = 64 * 1024;
const TEMP_CANDIDATES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    DirectoryCreated,
    Created,
    PrefixCopied,
    InputWritten,
    Synced,
    Verified,
    Renamed,
}

impl Boundary {
    pub fn name(self) -> &'static str {
        match self {
            Self::DirectoryCreated => "directory-created",
            Self::Created => "created",
            Self::PrefixCopied => "prefix-copied",
            Self::InputWritten => "input-written",
            Self::Synced => "synced",
            Self::Verified => "verified",
            Self::Renamed => "renamed",
        }
    }
}

pub fn reserved_path(path: &str) -> bool {
    path.split('/').any(|part| {
        part.strip_prefix(".absd-import-").is_some_and(|suffix| {
            suffix.len() == 4 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
        })
    })
}

fn fs_error(error: Error) -> String {
    format!("{error:?}")
}

fn write<D: Device>(fs: &mut Fs<D>, handle: u64, offset: u64, data: &[u8]) -> Result<(), String> {
    let count = fs.write_at(handle, offset, data).map_err(fs_error)?;
    if count != data.len() {
        return Err("short filesystem write".to_owned());
    }
    Ok(())
}

fn hash_range<D: Device>(
    fs: &mut Fs<D>,
    handle: u64,
    start: u64,
    length: u64,
    chunk: &mut [u8],
) -> Result<[u8; 32], String> {
    let mut hash = Sha256::new();
    let mut done = 0;
    while done < length {
        let take = (length - done).min(chunk.len() as u64) as usize;
        let count = fs
            .read_at(handle, start + done, &mut chunk[..take])
            .map_err(fs_error)?;
        if count != take {
            return Err("short filesystem readback".to_owned());
        }
        hash.update(&chunk[..count]);
        done += count as u64;
    }
    Ok(hash.finalize().into())
}

/// Returns the prior prefix length. New files use rename-no-replace; appends
/// replace only after both copied prefix and supplied suffix pass readback.
/// `boundary` is an observation/test hook, not a grant to another process.
pub fn import_file<D: Device>(
    fs: &mut Fs<D>,
    input: &mut impl Read,
    step: u64,
    path: &str,
    size: u64,
    digest: [u8; 32],
    chunk: &mut [u8],
    mut boundary: impl FnMut(Boundary, &mut Fs<D>, &str) -> Result<(), String>,
) -> Result<u64, String> {
    if !(1..=4).contains(&step) || chunk.is_empty() {
        return Err("invalid file import operation".to_owned());
    }
    if reserved_path(path) {
        return Err("reserved importer temporary component".to_owned());
    }
    let append = step == 3;
    let replace = append || step == 4;
    let previous = match fs.stat(path.as_bytes()) {
        Ok(attr) => Some(attr),
        Err(Error::NotFound) => None,
        Err(error) => return Err(fs_error(error)),
    };
    if !replace && previous.is_some() {
        return Err("Exists".to_owned());
    }
    if let Some(attr) = previous {
        if replace && attr.kind != Kind::File {
            return Err("IsDir".to_owned());
        }
        if replace && attr.readonly {
            return Err("Denied".to_owned());
        }
    }
    let start = if append {
        let attr = previous.ok_or_else(|| "NotFound".to_owned())?;
        if attr.kind != Kind::File {
            return Err("IsDir".to_owned());
        }
        if attr.readonly {
            return Err("Denied".to_owned());
        }
        attr.size
    } else {
        0
    };
    // Old blocks remain live until commit. Never borrow them for the temp.
    let total = start
        .checked_add(size)
        .ok_or_else(|| "file size overflow".to_owned())?;
    let blocks = total.div_ceil(BLOCK as u64);
    if blocks > fs.free_blocks() as u64 {
        return Err(format!(
            "NoSpace temporary_blocks={blocks} free_blocks={}",
            fs.free_blocks()
        ));
    }
    let parent = std::path::Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .ok_or_else(|| "invalid file path".to_owned())?;
    let mut chosen = None;
    for index in 0..TEMP_CANDIDATES {
        let candidate = format!("{}/.absd-import-{index:04x}", parent.trim_end_matches('/'));
        match fs.mkdir(candidate.as_bytes()) {
            Ok(()) => {
                chosen = Some(candidate);
                break;
            }
            Err(Error::Exists) => continue,
            Err(error) => return Err(fs_error(error)),
        }
    }
    let directory = chosen.ok_or_else(|| "temporary name collision limit".to_owned())?;
    let temp = format!("{directory}/file");
    let mut opened = None;
    let mut source = None;
    let mut temp_created = false;
    let mut committed = false;
    let result = (|| {
        boundary(Boundary::DirectoryCreated, fs, &directory)?;
        let handle = fs
            .open(
                temp.as_bytes(),
                OpenFlags {
                    read: true,
                    write: true,
                    create_new: true,
                    ..OpenFlags::default()
                },
            )
            .map_err(fs_error)?;
        opened = Some(handle);
        temp_created = true;
        boundary(Boundary::Created, fs, &temp)?;
        let mut prefix = Sha256::new();
        if append {
            let original = fs
                .open(
                    path.as_bytes(),
                    OpenFlags {
                        read: true,
                        ..OpenFlags::default()
                    },
                )
                .map_err(fs_error)?;
            source = Some(original);
            let mut copied = 0;
            while copied < start {
                let take = (start - copied).min(chunk.len() as u64) as usize;
                let count = fs
                    .read_at(original, copied, &mut chunk[..take])
                    .map_err(fs_error)?;
                if count != take {
                    return Err("short prefix read".to_owned());
                }
                prefix.update(&chunk[..take]);
                write(fs, handle, copied, &chunk[..take])?;
                copied += take as u64;
            }
        }
        let prefix: [u8; 32] = prefix.finalize().into();
        boundary(Boundary::PrefixCopied, fs, &temp)?;
        let mut received = 0;
        while received < size {
            let take = (size - received).min(chunk.len() as u64) as usize;
            input
                .read_exact(&mut chunk[..take])
                .map_err(|_| "truncated fixture stream".to_owned())?;
            write(fs, handle, start + received, &chunk[..take])?;
            received += take as u64;
        }
        boundary(Boundary::InputWritten, fs, &temp)?;
        fs.sync().map_err(fs_error)?;
        boundary(Boundary::Synced, fs, &temp)?;
        if fs.fstat(handle).map_err(fs_error)?.size != total
            || hash_range(fs, handle, 0, start, chunk)? != prefix
            || hash_range(fs, handle, start, size, chunk)? != digest
        {
            return Err("readback size or digest mismatch".to_owned());
        }
        boundary(Boundary::Verified, fs, &temp)?;
        if let Some(handle) = source.take() {
            fs.close(handle).map_err(fs_error)?;
        }
        fs.close(opened.take().unwrap()).map_err(fs_error)?;
        // Rename may fail after an uncertain device effect. Never attempt to
        // repair a poisoned filesystem or infer success from its memory view.
        fs.rename(temp.as_bytes(), path.as_bytes(), !replace)
            .map_err(fs_error)?;
        committed = true;
        boundary(Boundary::Renamed, fs, &temp)?;
        fs.rmdir(directory.as_bytes()).map_err(fs_error)?;
        Ok(start)
    })();
    if let Some(handle) = source.take() {
        let _ = fs.close(handle);
    }
    if let Some(handle) = opened.take() {
        let _ = fs.close(handle);
    }
    match result {
        Err(error) if !committed && !fs.poisoned() => {
            let cleanup = if temp_created {
                fs.unlink(temp.as_bytes())
            } else {
                Ok(())
            };
            if let Err(cleanup) = cleanup {
                return Err(format!("{error}; temporary cleanup {temp}: {cleanup:?}"));
            }
            match fs.rmdir(directory.as_bytes()) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!(
                    "{error}; temporary cleanup {directory}: {cleanup:?}"
                )),
            }
        }
        result => result,
    }
}
