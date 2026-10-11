//! The `absd` SQLite VFS.
//!
//! Files: SQLite's paths are the filesystem's absolute paths. Durability:
//! `xSync` is a filesystem sync, which commits the whole namespace and every
//! pending file length; namespace changes (create, delete) are already
//! durable when they return, so SQLite's directory syncs have nothing left
//! to do. Temporary files without a name live in process memory.
//!
//! Locks and WAL shared memory: one process at a time mounts the
//! filesystem (init hands the block handle to one holder), so the lock
//! tables and the wal-index live in this process's memory, keyed by the
//! database object's serial. They vanish with the process, which is exactly
//! the lifetime SQLite gives them: a wal-index with no live connection is
//! rebuilt from the WAL. Nothing volatile is written to the device.

use std::collections::{BTreeMap, BTreeSet};
use std::cell::UnsafeCell;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr;

use absd_fs::{Error, OpenFlags};
use absd_runtime::storage::with_fs;
use libsqlite3_sys as ffi;

pub const VFS_NAME: &CStr = c"absd";
const SECTOR_SIZE: c_int = 512;
const SHM_SLOTS: usize = ffi::SQLITE_SHM_NLOCK as usize;

#[derive(Default)]
struct FileLock {
    shared: BTreeSet<u64>,
    reserved: Option<u64>,
    pending: Option<u64>,
    exclusive: Option<u64>,
}

struct ShmNode {
    region_size: usize,
    regions: Vec<Box<[u8]>>,
    users: BTreeSet<u64>,
    exclusive: [Option<u64>; SHM_SLOTS],
    shared: [BTreeSet<u64>; SHM_SLOTS],
}

#[derive(Default)]
struct Tables {
    next_id: u64,
    locks: BTreeMap<u64, FileLock>,
    shm: BTreeMap<u64, ShmNode>,
}

struct Global(UnsafeCell<Option<Tables>>);
// ABSD processes are single-threaded; SQLite is built with no-op mutexes.
unsafe impl Sync for Global {}
static TABLES: Global = Global(UnsafeCell::new(None));

fn tables() -> &'static mut Tables {
    unsafe { (*TABLES.0.get()).get_or_insert_with(Tables::default) }
}

/// Connections holding any file lock on `serial` (for tests).
pub fn lock_holders(serial: u64) -> usize {
    tables().locks.get(&serial).map_or(0, |lock| lock.shared.len())
}

#[repr(C)]
struct AbsdFile {
    base: ffi::sqlite3_file,
    id: u64,
    handle: u64,
    serial: u64,
    level: c_int,
    shm: bool,
    delete_on_close: *mut Vec<u8>,
    memory: *mut Vec<u8>,
}

unsafe fn file<'a>(raw: *mut ffi::sqlite3_file) -> &'a mut AbsdFile {
    unsafe { &mut *(raw as *mut AbsdFile) }
}

fn io_error(error: Error, fallback: c_int) -> c_int {
    match error {
        Error::NoSpace => ffi::SQLITE_FULL,
        Error::ReadOnlyFs | Error::Denied => ffi::SQLITE_READONLY,
        Error::Corrupt(_) => ffi::SQLITE_CORRUPT,
        _ => fallback,
    }
}

fn mounted<R>(f: impl FnOnce(&mut absd_fs::Fs<absd_runtime::storage::RegionDevice>) -> R) -> Option<R> {
    with_fs(f)
}

unsafe extern "C" fn x_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    raw: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    unsafe { (*raw).pMethods = ptr::null() };
    let id = {
        let tables = tables();
        tables.next_id += 1;
        tables.next_id
    };
    let mut record = AbsdFile {
        base: ffi::sqlite3_file { pMethods: ptr::null() },
        id,
        handle: 0,
        serial: 0,
        level: ffi::SQLITE_LOCK_NONE,
        shm: false,
        delete_on_close: ptr::null_mut(),
        memory: ptr::null_mut(),
    };
    let mut granted = flags;
    if name.is_null() {
        record.memory = Box::into_raw(Box::new(Vec::new()));
        record.base.pMethods = &MEMORY_METHODS;
    } else {
        let path = unsafe { CStr::from_ptr(name) }.to_bytes();
        let readonly = flags & ffi::SQLITE_OPEN_READONLY != 0;
        let create = flags & ffi::SQLITE_OPEN_CREATE != 0;
        let exclusive = flags & ffi::SQLITE_OPEN_EXCLUSIVE != 0;
        let request = |write: bool| OpenFlags {
            read: true,
            write,
            create: create && write && !exclusive,
            create_new: create && write && exclusive,
            truncate: false,
        };
        let opened = mounted(|fs| {
            let handle = match fs.open(path, request(!readonly)) {
                Err(Error::ReadOnlyFs | Error::Denied) if !readonly => {
                    granted = (flags & !(ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE))
                        | ffi::SQLITE_OPEN_READONLY;
                    fs.open(path, OpenFlags { read: true, ..OpenFlags::default() })?
                }
                other => other?,
            };
            let attr = fs.fstat(handle)?;
            Ok::<_, Error>((handle, attr.serial))
        });
        let opened = match opened {
            // A read-only mount cannot create a WAL. An absent WAL is an empty
            // one (SQLite deletes it after a complete checkpoint and recreates
            // it empty), so a reader gets an empty, volatile, read-only WAL:
            // nothing is written to the device, and the wal-index already
            // lives in process memory.
            Some(Err(Error::ReadOnlyFs | Error::NotFound))
                if flags & ffi::SQLITE_OPEN_WAL != 0 && mounted(|fs| !fs.writable()) == Some(true) =>
            {
                record.memory = Box::into_raw(Box::new(Vec::new()));
                record.base.pMethods = &MEMORY_METHODS;
                unsafe { ptr::write(raw as *mut AbsdFile, record) };
                if !out_flags.is_null() {
                    unsafe {
                        *out_flags = (flags & !(ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE))
                            | ffi::SQLITE_OPEN_READONLY
                    };
                }
                return ffi::SQLITE_OK;
            }
            other => other,
        };
        let Some(Ok((handle, serial))) = opened else { return ffi::SQLITE_CANTOPEN };
        record.handle = handle;
        record.serial = serial;
        if flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0 {
            record.delete_on_close = Box::into_raw(Box::new(path.to_vec()));
        }
        record.base.pMethods = &FILE_METHODS;
    }
    unsafe { ptr::write(raw as *mut AbsdFile, record) };
    if !out_flags.is_null() {
        unsafe { *out_flags = granted };
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn x_delete(_vfs: *mut ffi::sqlite3_vfs, name: *const c_char, _sync_dir: c_int) -> c_int {
    let path = unsafe { CStr::from_ptr(name) }.to_bytes();
    match mounted(|fs| fs.unlink(path)) {
        Some(Ok(())) => ffi::SQLITE_OK,
        Some(Err(Error::NotFound)) => ffi::SQLITE_IOERR_DELETE_NOENT,
        _ => ffi::SQLITE_IOERR_DELETE,
    }
}

unsafe extern "C" fn x_access(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    let path = unsafe { CStr::from_ptr(name) }.to_bytes();
    let answer = mounted(|fs| match fs.stat(path) {
        // As the Unix VFS: an empty regular file does not "exist", so a
        // zero-length journal or WAL is never treated as hot.
        Ok(attr) if flags == ffi::SQLITE_ACCESS_EXISTS => {
            Ok(attr.kind == absd_fs::Kind::Dir || attr.size > 0)
        }
        Ok(attr) => Ok(!attr.readonly && fs.writable()),
        Err(Error::NotFound) => Ok(false),
        Err(error) => Err(error),
    });
    match answer {
        Some(Ok(value)) => {
            unsafe { *out = c_int::from(value) };
            ffi::SQLITE_OK
        }
        _ => ffi::SQLITE_IOERR_ACCESS,
    }
}

unsafe extern "C" fn x_full_pathname(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    size: c_int,
    out: *mut c_char,
) -> c_int {
    let path = unsafe { CStr::from_ptr(name) }.to_bytes_with_nul();
    // There is no current directory: only absolute paths name anything.
    if path.first() != Some(&b'/') || path.len() > size as usize {
        return ffi::SQLITE_CANTOPEN;
    }
    unsafe { ptr::copy_nonoverlapping(path.as_ptr() as *const c_char, out, path.len()) };
    ffi::SQLITE_OK
}

unsafe extern "C" fn x_randomness(_vfs: *mut ffi::sqlite3_vfs, count: c_int, out: *mut c_char) -> c_int {
    let out = unsafe { std::slice::from_raw_parts_mut(out as *mut u8, count as usize) };
    for chunk in out.chunks_mut(8) {
        let mut value = 0u64;
        while unsafe { core::arch::x86_64::_rdrand64_step(&mut value) } != 1 {}
        chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
    }
    count
}

unsafe extern "C" fn x_sleep(_vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    // Nothing else runs in this process that could release a lock.
    microseconds
}

/// ABSD has no wall clock; SQLite's date functions fail rather than invent
/// a time.
unsafe extern "C" fn x_current_time(_vfs: *mut ffi::sqlite3_vfs, _out: *mut f64) -> c_int {
    ffi::SQLITE_ERROR
}

unsafe extern "C" fn x_current_time_int64(_vfs: *mut ffi::sqlite3_vfs, _out: *mut ffi::sqlite3_int64) -> c_int {
    ffi::SQLITE_ERROR
}

unsafe extern "C" fn x_get_last_error(_vfs: *mut ffi::sqlite3_vfs, _size: c_int, _out: *mut c_char) -> c_int {
    0
}

unsafe extern "C" fn f_close(raw: *mut ffi::sqlite3_file) -> c_int {
    unsafe {
        f_unlock(raw, ffi::SQLITE_LOCK_NONE);
        f_shm_unmap(raw, 0);
    }
    let file = unsafe { file(raw) };
    let mut status = ffi::SQLITE_OK;
    let handle = file.handle;
    if mounted(|fs| fs.close(handle)).is_none_or(|result| result.is_err()) {
        status = ffi::SQLITE_IOERR_CLOSE;
    }
    if !file.delete_on_close.is_null() {
        let path = unsafe { Box::from_raw(file.delete_on_close) };
        file.delete_on_close = ptr::null_mut();
        match mounted(|fs| fs.unlink(&path)) {
            Some(Ok(())) | Some(Err(Error::NotFound)) => {}
            _ => status = ffi::SQLITE_IOERR_DELETE,
        }
    }
    status
}

unsafe extern "C" fn f_read(raw: *mut ffi::sqlite3_file, out: *mut c_void, amount: c_int, offset: ffi::sqlite3_int64) -> c_int {
    let file = unsafe { file(raw) };
    let buffer = unsafe { std::slice::from_raw_parts_mut(out as *mut u8, amount as usize) };
    let handle = file.handle;
    match mounted(|fs| fs.read_at(handle, offset as u64, buffer)) {
        Some(Ok(count)) if count == buffer.len() => ffi::SQLITE_OK,
        Some(Ok(count)) => {
            buffer[count..].fill(0);
            ffi::SQLITE_IOERR_SHORT_READ
        }
        Some(Err(error)) => io_error(error, ffi::SQLITE_IOERR_READ),
        None => ffi::SQLITE_IOERR_READ,
    }
}

unsafe extern "C" fn f_write(raw: *mut ffi::sqlite3_file, data: *const c_void, amount: c_int, offset: ffi::sqlite3_int64) -> c_int {
    let file = unsafe { file(raw) };
    let data = unsafe { std::slice::from_raw_parts(data as *const u8, amount as usize) };
    let handle = file.handle;
    match mounted(|fs| fs.write_at(handle, offset as u64, data)) {
        Some(Ok(_)) => ffi::SQLITE_OK,
        Some(Err(error)) => io_error(error, ffi::SQLITE_IOERR_WRITE),
        None => ffi::SQLITE_IOERR_WRITE,
    }
}

unsafe extern "C" fn f_truncate(raw: *mut ffi::sqlite3_file, size: ffi::sqlite3_int64) -> c_int {
    let handle = unsafe { file(raw) }.handle;
    match mounted(|fs| fs.set_len(handle, size as u64)) {
        Some(Ok(())) => ffi::SQLITE_OK,
        Some(Err(error)) => io_error(error, ffi::SQLITE_IOERR_TRUNCATE),
        None => ffi::SQLITE_IOERR_TRUNCATE,
    }
}

unsafe extern "C" fn f_sync(_raw: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    match mounted(|fs| fs.sync()) {
        Some(Ok(())) => ffi::SQLITE_OK,
        Some(Err(error)) => io_error(error, ffi::SQLITE_IOERR_FSYNC),
        None => ffi::SQLITE_IOERR_FSYNC,
    }
}

unsafe extern "C" fn f_file_size(raw: *mut ffi::sqlite3_file, out: *mut ffi::sqlite3_int64) -> c_int {
    let handle = unsafe { file(raw) }.handle;
    match mounted(|fs| fs.fstat(handle)) {
        Some(Ok(attr)) => {
            unsafe { *out = attr.size as ffi::sqlite3_int64 };
            ffi::SQLITE_OK
        }
        _ => ffi::SQLITE_IOERR_FSTAT,
    }
}

/// SQLite's five-level file lock among this process's connections, with
/// the same rules as the Unix VFS's per-inode table.
unsafe extern "C" fn f_lock(raw: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    let file = unsafe { file(raw) };
    if file.level >= level {
        return ffi::SQLITE_OK;
    }
    let id = file.id;
    let lock = tables().locks.entry(file.serial).or_default();
    let other = |holder: Option<u64>| holder.is_some_and(|holder| holder != id);
    match level {
        ffi::SQLITE_LOCK_SHARED => {
            if other(lock.pending) || other(lock.exclusive) {
                return ffi::SQLITE_BUSY;
            }
            lock.shared.insert(id);
            file.level = ffi::SQLITE_LOCK_SHARED;
        }
        ffi::SQLITE_LOCK_RESERVED => {
            if other(lock.reserved) || other(lock.pending) || other(lock.exclusive) {
                return ffi::SQLITE_BUSY;
            }
            lock.reserved = Some(id);
            file.level = ffi::SQLITE_LOCK_RESERVED;
        }
        ffi::SQLITE_LOCK_EXCLUSIVE => {
            if other(lock.pending) || other(lock.exclusive) || (other(lock.reserved) && file.level < ffi::SQLITE_LOCK_RESERVED) {
                return ffi::SQLITE_BUSY;
            }
            lock.pending = Some(id);
            file.level = ffi::SQLITE_LOCK_PENDING;
            if lock.shared.iter().any(|holder| *holder != id) {
                return ffi::SQLITE_BUSY;
            }
            lock.exclusive = Some(id);
            file.level = ffi::SQLITE_LOCK_EXCLUSIVE;
        }
        _ => return ffi::SQLITE_MISUSE,
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn f_unlock(raw: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    let file = unsafe { file(raw) };
    if file.level <= level {
        return ffi::SQLITE_OK;
    }
    let id = file.id;
    let tables = tables();
    if let Some(lock) = tables.locks.get_mut(&file.serial) {
        for holder in [&mut lock.reserved, &mut lock.pending, &mut lock.exclusive] {
            if *holder == Some(id) {
                *holder = None;
            }
        }
        if level == ffi::SQLITE_LOCK_NONE {
            lock.shared.remove(&id);
        }
        if lock.shared.is_empty() && lock.reserved.is_none() && lock.pending.is_none() && lock.exclusive.is_none() {
            tables.locks.remove(&file.serial);
        }
    }
    file.level = level;
    ffi::SQLITE_OK
}

unsafe extern "C" fn f_check_reserved(raw: *mut ffi::sqlite3_file, out: *mut c_int) -> c_int {
    let file = unsafe { file(raw) };
    let reserved = tables()
        .locks
        .get(&file.serial)
        .is_some_and(|lock| lock.reserved.is_some() || lock.pending.is_some() || lock.exclusive.is_some());
    unsafe { *out = c_int::from(reserved) };
    ffi::SQLITE_OK
}

unsafe extern "C" fn f_file_control(raw: *mut ffi::sqlite3_file, op: c_int, arg: *mut c_void) -> c_int {
    if op == ffi::SQLITE_FCNTL_HAS_MOVED {
        let handle = unsafe { file(raw) }.handle;
        return match mounted(|fs| fs.fstat(handle)) {
            Some(Ok(attr)) => {
                unsafe { *(arg as *mut c_int) = c_int::from(attr.links == 0) };
                ffi::SQLITE_OK
            }
            _ => ffi::SQLITE_IOERR_FSTAT,
        };
    }
    ffi::SQLITE_NOTFOUND
}

unsafe extern "C" fn f_sector_size(_raw: *mut ffi::sqlite3_file) -> c_int {
    SECTOR_SIZE
}

/// Writes never disturb bytes outside their range (sector-atomic device,
/// read-modify-write of partial sectors); no other property is claimed.
unsafe extern "C" fn f_device_characteristics(_raw: *mut ffi::sqlite3_file) -> c_int {
    ffi::SQLITE_IOCAP_POWERSAFE_OVERWRITE
}

unsafe extern "C" fn f_shm_map(
    raw: *mut ffi::sqlite3_file,
    region: c_int,
    size: c_int,
    extend: c_int,
    out: *mut *mut c_void,
) -> c_int {
    let file = unsafe { file(raw) };
    let node = tables().shm.entry(file.serial).or_insert_with(|| ShmNode {
        region_size: size as usize,
        regions: Vec::new(),
        users: BTreeSet::new(),
        exclusive: [None; SHM_SLOTS],
        shared: Default::default(),
    });
    if node.region_size != size as usize {
        return ffi::SQLITE_IOERR_SHMSIZE;
    }
    node.users.insert(file.id);
    file.shm = true;
    let region = region as usize;
    while node.regions.len() <= region {
        if extend == 0 {
            unsafe { *out = ptr::null_mut() };
            return ffi::SQLITE_OK;
        }
        node.regions.push(vec![0u8; node.region_size].into_boxed_slice());
    }
    unsafe { *out = node.regions[region].as_mut_ptr() as *mut c_void };
    ffi::SQLITE_OK
}

unsafe extern "C" fn f_shm_lock(raw: *mut ffi::sqlite3_file, offset: c_int, count: c_int, flags: c_int) -> c_int {
    let file = unsafe { file(raw) };
    let id = file.id;
    let Some(node) = tables().shm.get_mut(&file.serial) else { return ffi::SQLITE_IOERR_SHMLOCK };
    let slots = offset as usize..(offset + count) as usize;
    if slots.end > SHM_SLOTS {
        return ffi::SQLITE_IOERR_SHMLOCK;
    }
    if flags & ffi::SQLITE_SHM_UNLOCK != 0 {
        for slot in slots {
            node.shared[slot].remove(&id);
            if node.exclusive[slot] == Some(id) {
                node.exclusive[slot] = None;
            }
        }
        return ffi::SQLITE_OK;
    }
    let exclusive = flags & ffi::SQLITE_SHM_EXCLUSIVE != 0;
    for slot in slots.clone() {
        if node.exclusive[slot].is_some_and(|holder| holder != id) {
            return ffi::SQLITE_BUSY;
        }
        if exclusive && node.shared[slot].iter().any(|holder| *holder != id) {
            return ffi::SQLITE_BUSY;
        }
    }
    for slot in slots {
        if exclusive {
            node.shared[slot].remove(&id);
            node.exclusive[slot] = Some(id);
        } else {
            node.shared[slot].insert(id);
        }
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn f_shm_barrier(_raw: *mut ffi::sqlite3_file) {
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

unsafe extern "C" fn f_shm_unmap(raw: *mut ffi::sqlite3_file, _delete: c_int) -> c_int {
    let file = unsafe { file(raw) };
    if !file.shm {
        return ffi::SQLITE_OK;
    }
    file.shm = false;
    let id = file.id;
    let tables = tables();
    if let Some(node) = tables.shm.get_mut(&file.serial) {
        node.users.remove(&id);
        for slot in 0..SHM_SLOTS {
            node.shared[slot].remove(&id);
            if node.exclusive[slot] == Some(id) {
                node.exclusive[slot] = None;
            }
        }
        // The last connection gone: the wal-index is rebuilt from the WAL
        // by the next one, as after any crash.
        if node.users.is_empty() {
            tables.shm.remove(&file.serial);
        }
    }
    ffi::SQLITE_OK
}

unsafe fn memory<'a>(raw: *mut ffi::sqlite3_file) -> &'a mut Vec<u8> {
    unsafe { &mut *file(raw).memory }
}

unsafe extern "C" fn m_close(raw: *mut ffi::sqlite3_file) -> c_int {
    let file = unsafe { file(raw) };
    drop(unsafe { Box::from_raw(file.memory) });
    file.memory = ptr::null_mut();
    ffi::SQLITE_OK
}

unsafe extern "C" fn m_read(raw: *mut ffi::sqlite3_file, out: *mut c_void, amount: c_int, offset: ffi::sqlite3_int64) -> c_int {
    let bytes = unsafe { memory(raw) };
    let out = unsafe { std::slice::from_raw_parts_mut(out as *mut u8, amount as usize) };
    let start = (offset as usize).min(bytes.len());
    let count = (bytes.len() - start).min(out.len());
    out[..count].copy_from_slice(&bytes[start..start + count]);
    if count < out.len() {
        out[count..].fill(0);
        return ffi::SQLITE_IOERR_SHORT_READ;
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn m_write(raw: *mut ffi::sqlite3_file, data: *const c_void, amount: c_int, offset: ffi::sqlite3_int64) -> c_int {
    let bytes = unsafe { memory(raw) };
    let data = unsafe { std::slice::from_raw_parts(data as *const u8, amount as usize) };
    let end = offset as usize + data.len();
    if bytes.len() < end {
        bytes.resize(end, 0);
    }
    bytes[offset as usize..end].copy_from_slice(data);
    ffi::SQLITE_OK
}

unsafe extern "C" fn m_truncate(raw: *mut ffi::sqlite3_file, size: ffi::sqlite3_int64) -> c_int {
    unsafe { memory(raw) }.truncate(size as usize);
    ffi::SQLITE_OK
}

unsafe extern "C" fn m_sync(_raw: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn m_file_size(raw: *mut ffi::sqlite3_file, out: *mut ffi::sqlite3_int64) -> c_int {
    unsafe { *out = memory(raw).len() as ffi::sqlite3_int64 };
    ffi::SQLITE_OK
}

unsafe extern "C" fn m_lock(_raw: *mut ffi::sqlite3_file, _level: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn m_check_reserved(_raw: *mut ffi::sqlite3_file, out: *mut c_int) -> c_int {
    unsafe { *out = 0 };
    ffi::SQLITE_OK
}

unsafe extern "C" fn m_file_control(_raw: *mut ffi::sqlite3_file, _op: c_int, _arg: *mut c_void) -> c_int {
    ffi::SQLITE_NOTFOUND
}

unsafe extern "C" fn m_device_characteristics(_raw: *mut ffi::sqlite3_file) -> c_int {
    0
}

static FILE_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 2,
    xClose: Some(f_close),
    xRead: Some(f_read),
    xWrite: Some(f_write),
    xTruncate: Some(f_truncate),
    xSync: Some(f_sync),
    xFileSize: Some(f_file_size),
    xLock: Some(f_lock),
    xUnlock: Some(f_unlock),
    xCheckReservedLock: Some(f_check_reserved),
    xFileControl: Some(f_file_control),
    xSectorSize: Some(f_sector_size),
    xDeviceCharacteristics: Some(f_device_characteristics),
    xShmMap: Some(f_shm_map),
    xShmLock: Some(f_shm_lock),
    xShmBarrier: Some(f_shm_barrier),
    xShmUnmap: Some(f_shm_unmap),
    xFetch: None,
    xUnfetch: None,
};

static MEMORY_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(m_close),
    xRead: Some(m_read),
    xWrite: Some(m_write),
    xTruncate: Some(m_truncate),
    xSync: Some(m_sync),
    xFileSize: Some(m_file_size),
    xLock: Some(m_lock),
    xUnlock: Some(m_lock),
    xCheckReservedLock: Some(m_check_reserved),
    xFileControl: Some(m_file_control),
    xSectorSize: Some(f_sector_size),
    xDeviceCharacteristics: Some(m_device_characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

struct VfsCell(UnsafeCell<ffi::sqlite3_vfs>);
unsafe impl Sync for VfsCell {}

static VFS: VfsCell = VfsCell(UnsafeCell::new(ffi::sqlite3_vfs {
    iVersion: 2,
    szOsFile: size_of::<AbsdFile>() as c_int,
    mxPathname: 512,
    pNext: ptr::null_mut(),
    zName: VFS_NAME.as_ptr(),
    pAppData: ptr::null_mut(),
    xOpen: Some(x_open),
    xDelete: Some(x_delete),
    xAccess: Some(x_access),
    xFullPathname: Some(x_full_pathname),
    xDlOpen: None,
    xDlError: None,
    xDlSym: None,
    xDlClose: None,
    xRandomness: Some(x_randomness),
    xSleep: Some(x_sleep),
    xCurrentTime: Some(x_current_time),
    xGetLastError: Some(x_get_last_error),
    xCurrentTimeInt64: Some(x_current_time_int64),
    xSetSystemCall: None,
    xGetSystemCall: None,
    xNextSystemCall: None,
}));

/// Called by `sqlite3_initialize` in a `SQLITE_OS_OTHER` build.
#[unsafe(no_mangle)]
pub extern "C" fn sqlite3_os_init() -> c_int {
    unsafe { ffi::sqlite3_vfs_register(VFS.0.get(), 1) }
}

#[unsafe(no_mangle)]
pub extern "C" fn sqlite3_os_end() -> c_int {
    ffi::SQLITE_OK
}
