//! The worker side of init-brokered spawning: the request and reply
//! channel and the slots the startup record named, plus the raw handle I/O
//! `std::process` needs for the slot pipes. `std` reaches this only through
//! the `__absd_std_process_*` and `__absd_std_handle_*` hooks below.
//!
//! The process is single-threaded (ABSD `std` has no threads), so the one
//! broker is a plain global touched only from those hooks.

use core::cell::UnsafeCell;

use absd_broker::{Book, BookError, MAX_REQUEST, MAX_SLOTS, RequestError, encode_request};

use crate::syscall3;

const SYS_WRITE: u64 = 1;
const SYS_CLOSE: u64 = 9;
const SYS_READ: u64 = 15;
const SYS_TRANSFER: u64 = 21;
const TRANSFER_READ: u64 = 0;
const MAX_TRANSFER: usize = 256;
const ERROR_INVALID: i64 = -22;
const ERROR_TIMEOUT: i64 = -110;

/// Hook results below every kernel error code. `std` maps them to
/// `io::ErrorKind`s; keep `sys/process/absd.rs` in step.
pub const SPAWN_NO_BROKER: i64 = -2000;
pub const SPAWN_NO_SLOT: i64 = -2001;
pub const SPAWN_INVALID: i64 = -2002;
pub const SPAWN_TOO_LARGE: i64 = -2003;
pub const BROKER_PROTOCOL: i64 = -2005;
pub const BROKER_CLOSED: i64 = -2006;
/// A REFUSED reply with code `c` is reported as `SPAWN_REFUSED_BASE - c`.
pub const SPAWN_REFUSED_BASE: i64 = -2100;

struct Broker {
    request: u64,
    reply: u64,
    /// Worker-side ends `[stdin writer, stdout reader, stderr reader]`,
    /// handed to `std` when the slot's child starts.
    slots: [[u64; 3]; MAX_SLOTS],
    book: Book,
}

struct Global(UnsafeCell<Option<Broker>>);
// SAFETY: ABSD processes are single-threaded; the hooks never re-enter.
unsafe impl Sync for Global {}
static BROKER: Global = Global(UnsafeCell::new(None));

fn broker() -> Option<&'static mut Broker> {
    // SAFETY: see `Global`; no reference outlives one hook call.
    unsafe { (*BROKER.0.get()).as_mut() }
}

pub(crate) fn installed() -> bool {
    broker().is_some()
}

pub(crate) fn install(request: u64, reply: u64, slots: &[[u64; 3]]) {
    let mut table = [[0u64; 3]; MAX_SLOTS];
    table[..slots.len()].copy_from_slice(slots);
    // SAFETY: called once from `__absd_start`, before `main`.
    unsafe {
        *BROKER.0.get() = Some(Broker { request, reply, slots: table, book: Book::new(slots.len()) });
    }
}

/// Reads at most one transfer; `timeout` in ticks, zero for none.
fn read(handle: u64, bytes: &mut [u8], timeout: u64) -> i64 {
    let length = bytes.len().min(MAX_TRANSFER) as u64;
    if timeout == 0 {
        return unsafe { syscall3(SYS_READ, handle, bytes.as_mut_ptr() as u64, length) };
    }
    let record = [bytes.as_mut_ptr() as u64, length, timeout];
    unsafe { syscall3(SYS_TRANSFER, handle, record.as_ptr() as u64, TRANSFER_READ) }
}

fn write_all(handle: u64, mut bytes: &[u8]) -> i64 {
    while !bytes.is_empty() {
        let length = bytes.len().min(MAX_TRANSFER);
        let written = unsafe { syscall3(SYS_WRITE, handle, bytes.as_ptr() as u64, length as u64) };
        if written <= 0 {
            return if written == 0 { ERROR_INVALID } else { written };
        }
        bytes = &bytes[written as usize..];
    }
    0
}

fn book_error(error: BookError) -> i64 {
    match error {
        BookError::Protocol => BROKER_PROTOCOL,
        BookError::NotPending => ERROR_INVALID,
    }
}

/// Moves whatever init has written into the book. End-of-file means init
/// closed the channel: nothing more can arrive, so the book is poisoned.
fn receive(broker: &mut Broker, timeout: u64) -> Result<(), i64> {
    let mut bytes = [0u8; MAX_TRANSFER];
    let count = read(broker.reply, &mut bytes, timeout);
    if count == 0 {
        broker.book.poison();
        return Err(BROKER_CLOSED);
    }
    if count < 0 {
        return Err(count);
    }
    broker.book.feed(&bytes[..count as usize]).map_err(book_error)
}

/// Sends one request and waits for its STARTED or REFUSED. On success
/// `out` is `[slot, pid, stdin writer, stdout reader, stderr reader]` and
/// the three handles belong to the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_process_spawn(
    path: *const u8,
    path_length: usize,
    args: *const [usize; 2],
    argc: usize,
    out: *mut [u64; 5],
) -> i64 {
    let Some(broker) = broker() else { return SPAWN_NO_BROKER };
    if broker.book.is_poisoned() {
        return BROKER_PROTOCOL;
    }
    let Some(slot) = broker.book.next_unspent() else { return SPAWN_NO_SLOT };
    let path = unsafe { core::slice::from_raw_parts(path, path_length) };
    let args = unsafe { core::slice::from_raw_parts(args, argc) };
    let args = args
        .iter()
        .map(|&[pointer, length]| unsafe { core::slice::from_raw_parts(pointer as *const u8, length) });
    let mut request = alloc::vec![0u8; MAX_REQUEST];
    let length = match encode_request(slot as u8, path, args, &mut request) {
        Ok(length) => length,
        Err(RequestError::Invalid) => return SPAWN_INVALID,
        Err(RequestError::TooManyArguments | RequestError::TooLarge) => return SPAWN_TOO_LARGE,
    };
    if let Err(error) = broker.book.mark_requested(slot) {
        return book_error(error);
    }
    let written = write_all(broker.request, &request[..length]);
    if written < 0 {
        // Init may hold part of a request: the channel cannot be trusted.
        broker.book.poison();
        return written;
    }
    loop {
        match broker.book.take_spawn(slot) {
            Ok(Some(Ok(pid))) => {
                let [stdin, stdout, stderr] = broker.slots[slot];
                broker.slots[slot] = [0; 3];
                unsafe { *out = [slot as u64, pid, stdin, stdout, stderr] };
                return 0;
            }
            Ok(Some(Err(code))) => return SPAWN_REFUSED_BASE - code as i64,
            Ok(None) => {
                if let Err(error) = receive(broker, 0) {
                    return error;
                }
            }
            Err(error) => return book_error(error),
        }
    }
}

/// 1 with `*value` set once the slot's EXITED has arrived; 0 when
/// `nonblocking` and it has not arrived within about one tick; else an error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_process_wait(slot: u64, nonblocking: u64, value: *mut i64) -> i64 {
    if slot & crate::process::IMAGE_CHILD != 0 {
        return crate::process::wait(slot, nonblocking != 0, unsafe { &mut *value });
    }
    let Some(broker) = broker() else { return SPAWN_NO_BROKER };
    let slot = slot as usize;
    loop {
        match broker.book.exit_value(slot) {
            Ok(Some(outcome)) => {
                unsafe { *value = outcome };
                return 1;
            }
            Ok(None) => {}
            Err(error) => return book_error(error),
        }
        match receive(broker, if nonblocking != 0 { 1 } else { 0 }) {
            Ok(()) => {}
            Err(ERROR_TIMEOUT) if nonblocking != 0 => return 0,
            Err(error) => return error,
        }
    }
}

/// One read of at most 256 bytes from a slot pipe; 0 is end-of-file.
/// `timeout` in ticks, zero for none; `-110` when it passes first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_handle_read(
    handle: u64,
    bytes: *mut u8,
    length: usize,
    timeout: u64,
) -> isize {
    if length == 0 {
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts_mut(bytes, length) };
    read(handle, bytes, timeout) as isize
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_handle_write(handle: u64, bytes: *const u8, length: usize) -> isize {
    if length == 0 {
        return 0;
    }
    unsafe { syscall3(SYS_WRITE, handle, bytes as u64, length.min(MAX_TRANSFER) as u64) as isize }
}

#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_handle_close(handle: u64) -> i64 {
    unsafe { syscall3(SYS_CLOSE, handle, 0, 0) }
}
