//! The first native object with a conditional state transition: a cell
//! changes only when the caller names the version it last saw.
#![no_std]
#![no_main]

use absd_abi::syscall::{ERROR_BAD_HANDLE, SYS_CELL_TRANSITION};
use absd_user::{Cell, Console, Error, Start, close, syscall3};

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    match run(console) {
        Ok(()) => {
            let _ = console.write_str("user-cell: conditional transitions verified\n");
            0
        }
        Err(step) => {
            let _ = console.write_str("user-cell: FAILED at ");
            let _ = console.write_str(step);
            let _ = console.write_str("\n");
            91
        }
    }
}

fn run(console: Console) -> Result<(), &'static str> {
    let cell = Cell::create(10).map_err(|_| "create")?;
    if cell.read() != Ok((0, 10)) {
        return Err("initial state");
    }
    // The transition succeeds only from the version the caller saw.
    if cell.transition(0, 11) != Ok(1) {
        return Err("first transition");
    }
    match cell.transition(0, 12) {
        Err(Error::Stale) => {}
        _ => return Err("stale transition accepted"),
    }
    if cell.read() != Ok((1, 11)) {
        return Err("stale transition changed state");
    }
    // Read-then-transition loop: every step names the version it observed.
    let mut version = 1;
    for step in 0..100u64 {
        let (seen, value) = cell.read().map_err(|_| "loop read")?;
        if seen != version || value != 11 + step {
            return Err("loop state");
        }
        version = cell
            .transition(seen, value + 1)
            .map_err(|_| "loop transition")?;
    }
    if cell.read() != Ok((101, 111)) {
        return Err("final state");
    }
    // Only a cell handle transitions; a console handle is the wrong kind.
    if unsafe { syscall3(SYS_CELL_TRANSITION, console.raw(), 101, 0) } != ERROR_BAD_HANDLE {
        return Err("wrong kind");
    }
    // Closing the handle frees the cell; the value never resolves again.
    close(cell.raw()).map_err(|_| "close")?;
    match cell.read() {
        Err(Error::BadHandle) => {}
        _ => return Err("read after close"),
    }
    // The kernel table is bounded: create until refused, then release all.
    let mut held = [Cell::from_raw(0); 33];
    let mut count = 0;
    loop {
        match Cell::create(count as u64) {
            Ok(cell) => {
                held[count] = cell;
                count += 1;
            }
            Err(Error::NoMemory) => break,
            Err(_) => return Err("fill table"),
        }
        if count == held.len() {
            return Err("table never filled");
        }
    }
    // One cell stays open on purpose: process exit must release it.
    for cell in &held[1..count] {
        close(cell.raw()).map_err(|_| "drain table")?;
    }
    Ok(())
}
