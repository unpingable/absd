//! The working directory: process memory only, set from the startup
//! record's working-directory section (else `/`) and by
//! `std::env::set_current_dir`. The filesystem itself knows only absolute
//! paths; relative ones are resolved here, lexically, before any storage
//! hook sees them. ABSD has no symbolic links, so lexical `..` is exact.

use alloc::vec::Vec;
use core::cell::UnsafeCell;

struct Global(UnsafeCell<Option<Vec<u8>>>);
// SAFETY: ABSD processes are single-threaded; the hooks never re-enter.
unsafe impl Sync for Global {}
static CWD: Global = Global(UnsafeCell::new(None));

fn slot() -> &'static mut Option<Vec<u8>> {
    // SAFETY: see `Global`; no reference outlives one call.
    unsafe { &mut *CWD.0.get() }
}

/// The current working directory (absolute, normalized).
pub fn get() -> &'static [u8] {
    slot().as_deref().unwrap_or(b"/")
}

/// Replaces the working directory. The caller has resolved and checked it.
pub(crate) fn set(directory: Vec<u8>) {
    *slot() = Some(directory);
}

/// `path` as an absolute path: unchanged when already absolute (the
/// filesystem then judges it exactly as before), else joined to the working
/// directory with empty and `.` components dropped and `..` taken lexically
/// (never above `/`). An empty path stays empty (it names nothing).
pub fn resolve(path: &[u8]) -> Vec<u8> {
    if path.is_empty() || path[0] == b'/' {
        return path.to_vec();
    }
    lexical(get(), path)
}

/// `path` resolved as `resolve` does, but an absolute path is normalized
/// the same way too (a working directory is always in normal form).
pub fn normalize(path: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        return Vec::new();
    }
    lexical(if path[0] == b'/' { b"/" } else { get() }, path)
}

fn lexical(base: &[u8], path: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> =
        base.split(|&byte| byte == b'/').filter(|part| !part.is_empty()).collect();
    for part in path.split(|&byte| byte == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    let mut resolved = Vec::with_capacity(base.len() + path.len() + 1);
    for part in &parts {
        resolved.push(b'/');
        resolved.extend_from_slice(part);
    }
    if resolved.is_empty() {
        resolved.push(b'/');
    }
    resolved
}

/// `std::env::current_dir`: copies the working directory into `out` and
/// returns its length, or `-22` when `capacity` is too small.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_getcwd(out: *mut u8, capacity: usize) -> isize {
    let cwd = get();
    if cwd.len() > capacity {
        return -22;
    }
    unsafe { core::ptr::copy_nonoverlapping(cwd.as_ptr(), out, cwd.len()) };
    cwd.len() as isize
}

/// `std::env::set_current_dir`: resolves `path`, requires an existing
/// directory on the mounted filesystem (only `/` without one), and makes it
/// the working directory. The result names the directory the filesystem
/// holds under that path, so `set_current_dir("..")` works as on Unix.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_chdir(path: *const u8, length: usize) -> i64 {
    let path = if length == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(path, length) } };
    let resolved = normalize(path);
    if resolved.is_empty() {
        return -2;
    }
    let checked = crate::storage::stat_kind(&resolved).map(|kind| match kind {
        Ok(absd_fs::Kind::Dir) => 0,
        Ok(_) => -20,
        Err(code) => code,
    });
    let result = match checked {
        Some(result) => result,
        None if resolved == b"/" => 0,
        None => -2,
    };
    if result != 0 {
        return result;
    }
    if !absd_broker::valid_cwd(&resolved) {
        return -22;
    }
    set(resolved);
    0
}
