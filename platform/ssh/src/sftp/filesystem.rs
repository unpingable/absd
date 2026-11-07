//! Target adaptation; every native operation uses the child's restricted FSD slot.
use super::wire;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};

pub(super) const MAX_PATH: usize = 4096;
pub(super) const MAX_FILE: u64 = 64 * 1024 * 1024;

pub(super) fn path(home: &Path, bytes: &[u8]) -> Result<PathBuf, u32> {
    if bytes.len() > MAX_PATH || bytes.contains(&0) {
        return Err(5);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| 5u32)?;
    let given = Path::new(text);
    let path = if given.is_absolute() {
        given.to_path_buf()
    } else {
        home.join(given)
    };
    if path.as_os_str().len() > MAX_PATH {
        return Err(5);
    }
    Ok(path)
}
pub(super) fn range(offset: u64, size: usize) -> Result<(), u32> {
    if offset
        .checked_add(size as u64)
        .is_none_or(|end| end > MAX_FILE)
    {
        Err(4)
    } else {
        Ok(())
    }
}
pub(super) fn error(error: io::Error) -> u32 {
    match error.kind() {
        io::ErrorKind::NotFound => 2,
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => 3,
        io::ErrorKind::Unsupported => 8,
        _ => 4,
    }
}
pub(super) fn canonical(path: &Path) -> io::Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let Some(name) = path.file_name() else {
                return Err(error);
            };
            let parent = fs::canonicalize(path.parent().unwrap_or(Path::new("/")))?;
            if !fs::metadata(&parent)?.is_dir() {
                return Err(io::ErrorKind::NotADirectory.into());
            }
            Ok(parent.join(name))
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "absd")]
pub(super) fn rename(from: &Path, to: &Path) -> io::Result<()> {
    std::os::absd::fs::rename_noreplace(from, to)
}
#[cfg(target_os = "linux")]
pub(super) fn rename(from: &Path, to: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let from =
        CString::new(from.as_os_str().as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let to = CString::new(to.as_os_str().as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
    // Atomic reference operation, never an existence check followed by replacement.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(not(any(target_os = "absd", target_os = "linux")))]
pub(super) fn rename(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

pub(super) fn attributes(out: &mut Vec<u8>, metadata: &Metadata) {
    wire::encode(out, &5u32); // SIZE|PERMISSIONS; no invented ownership/timestamps.
    wire::encode(out, &metadata.len());
    let kind = if metadata.is_dir() {
        0o040000u32
    } else if metadata.file_type().is_symlink() {
        0o120000
    } else {
        0o100000
    };
    // Synthetic object-state bits, not effective mount rights or chmod support.
    let access = if metadata.permissions().readonly() {
        0o400
    } else {
        0o600
    };
    wire::encode(
        out,
        &(kind | access | if metadata.is_dir() { 0o100 } else { 0 }),
    );
}
pub(super) fn name(out: &mut Vec<u8>, name: &Path, metadata: &Metadata) -> Result<(), u32> {
    let name = name.to_str().ok_or(4u32)?;
    if name.len() > MAX_PATH {
        return Err(4);
    }
    wire::string(out, name.as_bytes());
    wire::string(out, name.as_bytes());
    attributes(out, metadata);
    Ok(())
}
