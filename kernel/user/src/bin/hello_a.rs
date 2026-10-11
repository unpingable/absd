//! Negative controls for the syscall ABI, a buffer spanning two user-stack
//! pages, and enough busy work to be timer-preempted.
#![no_std]
#![no_main]

use absd_abi::syscall::{
    ERROR_BAD_HANDLE, ERROR_FAULT, ERROR_NOT_IMPLEMENTED, SYS_CELL_READ, SYS_INFO, SYS_WRITE,
};
use absd_user::{Cell, Start, close, syscall3, wait_raw};

absd_user::entry!(main);

const BUFFERED: &[u8] = b"hello from userspace buffer\n";
static READONLY_RECORD: [u64; 4] = [
    0x1122_3344_5566_7788,
    0x99aa_bbcc_ddee_ff00,
    0x0123_4567_89ab_cdef,
    0xfedc_ba98_7654_3210,
];

fn main(start: Start) -> i32 {
    let console = start.console;
    let _ = console.write_str("user-A: hello from ELF userspace\n");

    // Exercise the defined unknown-call error without changing state.
    if unsafe { syscall3(999, 0, 0, 0) } != ERROR_NOT_IMPLEMENTED {
        return 99;
    }
    // A supervisor address is not a valid userspace buffer.
    if unsafe { syscall3(SYS_WRITE, console.raw(), 0x10_0000, 8) } != ERROR_FAULT {
        return 99;
    }
    // Handles are resolved only through this process's table: zero, a
    // guessed value, and a handle of the wrong kind all fail.
    if unsafe { syscall3(SYS_WRITE, 0, BUFFERED.as_ptr() as u64, 1) } != ERROR_BAD_HANDLE {
        return 99;
    }
    if unsafe { syscall3(SYS_WRITE, console.raw() + 1, BUFFERED.as_ptr() as u64, 1) }
        != ERROR_BAD_HANDLE
    {
        return 99;
    }
    let mut record = [0xdead_beefu64; 4];
    if wait_raw(console.raw(), record.as_mut_ptr() as u64) != ERROR_BAD_HANDLE {
        return 99;
    }
    // A wait record must be writable user memory.
    if wait_raw(1, 0x10_0000) != ERROR_FAULT {
        return 99;
    }
    // A bogus handle is refused and the record left untouched.
    if wait_raw(1, record.as_mut_ptr() as u64) != ERROR_BAD_HANDLE {
        return 99;
    }
    if core::hint::black_box(record) != [0xdead_beefu64; 4] {
        return 99;
    }
    // A record that ends in unmapped memory is refused before it is written.
    let stack_top = absd_abi::layout::USER_STACK_TOP;
    if wait_raw(1, stack_top - 8) != ERROR_FAULT {
        return 99;
    }
    // Kernel output paths must reject a present user page without write
    // permission. The immutable sentinel also proves that refusal happened
    // before any partial write, independently of the returned error.
    let readonly = READONLY_RECORD;
    let readonly_address = READONLY_RECORD.as_ptr() as u64;
    if unsafe { syscall3(SYS_INFO, 0, readonly_address, 0) } != ERROR_FAULT
        || wait_raw(0, readonly_address) != ERROR_FAULT
    {
        return 99;
    }
    let cell = match Cell::create(7) {
        Ok(cell) => cell,
        Err(_) => return 99,
    };
    if unsafe { syscall3(SYS_CELL_READ, cell.raw(), readonly_address, 0) } != ERROR_FAULT
        || close(cell.raw()).is_err()
        || READONLY_RECORD != readonly
    {
        return 99;
    }
    let _ = console.write_str("READONLY USER BUFFER OK\n");
    let _ = console.write_str("SYSCALL NEGATIVE CONTROLS OK\n");

    // Put the message across two mapped user-stack pages: find the first
    // page boundary inside a buffer larger than a page and straddle it.
    let mut buffer = [0u8; 4096 + 64];
    let start = buffer.as_ptr() as usize;
    let boundary = (start + 4096) & !4095;
    let offset = boundary - start - BUFFERED.len() / 2;
    buffer[offset..offset + BUFFERED.len()].copy_from_slice(BUFFERED);
    if console
        .write_once(&buffer[offset..offset + BUFFERED.len()])
        .is_err()
    {
        return 99;
    }

    // Give the timer something to preempt.
    for _ in 0..2_000_000u32 {
        unsafe { core::arch::asm!("pause", options(nomem, nostack)) };
    }

    // Handle lifecycle is explicit: after close, the console is gone.
    if close(console.raw()).is_err() {
        return 99;
    }
    if console.write_str("must not appear\n").is_ok() {
        return 99;
    }
    0
}
