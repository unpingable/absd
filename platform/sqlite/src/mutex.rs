//! SQLite mutexes for a one-thread process.
//!
//! `SQLITE_OS_OTHER` would give SQLite its no-op mutexes, which rusqlite
//! rightly refuses (they make the connection unsound to share between
//! threads). ABSD processes have exactly one thread, so a mutex here is an
//! ownership counter: entering a held non-recursive mutex could only be a
//! self-deadlock, and aborts instead of hanging.

use std::ffi::c_int;

use libsqlite3_sys as ffi;

#[repr(C)]
struct Mutex {
    recursive: bool,
    count: u32,
}

const STATIC_COUNT: usize = 16;
static mut STATICS: [Mutex; STATIC_COUNT] = [const { Mutex { recursive: false, count: 0 } }; STATIC_COUNT];

unsafe extern "C" fn init() -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn end() -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn alloc(id: c_int) -> *mut ffi::sqlite3_mutex {
    match id {
        ffi::SQLITE_MUTEX_FAST | ffi::SQLITE_MUTEX_RECURSIVE => {
            Box::into_raw(Box::new(Mutex { recursive: id == ffi::SQLITE_MUTEX_RECURSIVE, count: 0 }))
                as *mut ffi::sqlite3_mutex
        }
        _ if (id as usize) < STATIC_COUNT => unsafe {
            (&raw mut STATICS[id as usize]) as *mut ffi::sqlite3_mutex
        },
        _ => std::ptr::null_mut(),
    }
}

fn is_static(mutex: *mut ffi::sqlite3_mutex) -> bool {
    let first = (&raw const STATICS) as usize;
    let address = mutex as usize;
    address >= first && address < first + size_of::<[Mutex; STATIC_COUNT]>()
}

unsafe extern "C" fn free(mutex: *mut ffi::sqlite3_mutex) {
    if !mutex.is_null() && !is_static(mutex) {
        drop(unsafe { Box::from_raw(mutex as *mut Mutex) });
    }
}

unsafe fn state<'a>(mutex: *mut ffi::sqlite3_mutex) -> &'a mut Mutex {
    unsafe { &mut *(mutex as *mut Mutex) }
}

unsafe extern "C" fn enter(mutex: *mut ffi::sqlite3_mutex) {
    let state = unsafe { state(mutex) };
    if state.count > 0 && !state.recursive {
        // One thread re-entering a held non-recursive mutex.
        std::process::abort();
    }
    state.count += 1;
}

unsafe extern "C" fn try_enter(mutex: *mut ffi::sqlite3_mutex) -> c_int {
    let state = unsafe { state(mutex) };
    if state.count > 0 && !state.recursive {
        return ffi::SQLITE_BUSY;
    }
    state.count += 1;
    ffi::SQLITE_OK
}

unsafe extern "C" fn leave(mutex: *mut ffi::sqlite3_mutex) {
    let state = unsafe { state(mutex) };
    if state.count == 0 {
        std::process::abort();
    }
    state.count -= 1;
}

unsafe extern "C" fn held(mutex: *mut ffi::sqlite3_mutex) -> c_int {
    c_int::from(mutex.is_null() || unsafe { state(mutex) }.count > 0)
}

unsafe extern "C" fn notheld(mutex: *mut ffi::sqlite3_mutex) -> c_int {
    c_int::from(mutex.is_null() || unsafe { state(mutex) }.count == 0)
}

static METHODS: ffi::sqlite3_mutex_methods = ffi::sqlite3_mutex_methods {
    xMutexInit: Some(init),
    xMutexEnd: Some(end),
    xMutexAlloc: Some(alloc),
    xMutexFree: Some(free),
    xMutexEnter: Some(enter),
    xMutexTry: Some(try_enter),
    xMutexLeave: Some(leave),
    xMutexHeld: Some(held),
    xMutexNotheld: Some(notheld),
};

/// Installs the mutexes and initializes SQLite; must run before any other
/// SQLite call in the process.
pub fn initialize() -> c_int {
    let status = unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_MUTEX, &METHODS as *const _) };
    if status != ffi::SQLITE_OK {
        return status;
    }
    unsafe { ffi::sqlite3_initialize() }
}
