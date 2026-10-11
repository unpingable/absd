//! Exercises anonymous memory: pages arrive zeroed, hold data, are reused
//! after unmap, and bad requests fail closed. The kernel proves afterwards
//! that every frame came back.
#![no_std]
#![no_main]

use absd_abi::layout::{USER_HEAP_BASE, USER_HEAP_END, USER_HEAP_PAGES};
use absd_abi::syscall::MAX_MAP_PAGES;
use absd_user::{Error, Start, map, unmap};

absd_user::entry!(main);

const PAGE: usize = 4096;

fn main(start: Start) -> i32 {
    let console = start.console;
    match run() {
        Ok(()) => {
            let _ = console.write_str("user-heap: map/unmap verified\n");
            0
        }
        Err(step) => {
            let _ = console.write_str("user-heap: FAILED at ");
            let _ = console.write_str(step);
            let _ = console.write_str("\n");
            94
        }
    }
}

fn run() -> Result<(), &'static str> {
    // Pages are zeroed, writable, and start at the bottom of the window.
    let first = map(3).map_err(|_| "map 3")?;
    if first as u64 != USER_HEAP_BASE {
        return Err("first address");
    }
    let bytes = unsafe { core::slice::from_raw_parts_mut(first, 3 * PAGE) };
    if bytes.iter().any(|&byte| byte != 0) {
        return Err("zero fill");
    }
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    if bytes
        .iter()
        .enumerate()
        .any(|(index, &byte)| byte != (index % 251) as u8)
    {
        return Err("read back");
    }

    // A second mapping lands after the first; freeing the first lets the
    // next request reuse its addresses (lowest free run first).
    let second = map(1).map_err(|_| "map 1")?;
    if second as u64 != USER_HEAP_BASE + 3 * PAGE as u64 {
        return Err("second address");
    }
    unmap(first, 3).map_err(|_| "unmap 3")?;
    let third = map(2).map_err(|_| "map 2")?;
    if third != first {
        return Err("reuse");
    }
    // Reused pages must arrive zeroed again, not carrying old contents.
    let reused = unsafe { core::slice::from_raw_parts(third, 2 * PAGE) };
    if reused.iter().any(|&byte| byte != 0) {
        return Err("zero on reuse");
    }
    unmap(third, 2).map_err(|_| "unmap 2")?;
    unmap(second, 1).map_err(|_| "unmap 1")?;

    // Negative controls, none of which may change the address space.
    match map(0) {
        Err(Error::Invalid) => {}
        _ => return Err("map 0"),
    }
    match map(MAX_MAP_PAGES + 1) {
        Err(Error::Invalid) => {}
        _ => return Err("map too many"),
    }
    match unmap(first, 1) {
        Err(Error::Invalid) => {}
        _ => return Err("unmap unmapped"),
    }
    match unmap((USER_HEAP_END - PAGE as u64) as *mut u8, 2) {
        Err(Error::Invalid) => {}
        _ => return Err("unmap past window"),
    }

    // Fill the whole window, then one more page must be refused.
    let mut chunks = [core::ptr::null_mut::<u8>(); (USER_HEAP_PAGES / MAX_MAP_PAGES) as usize];
    for chunk in chunks.iter_mut() {
        *chunk = map(MAX_MAP_PAGES).map_err(|_| "fill window")?;
    }
    match map(1) {
        Err(Error::NoMemory) => {}
        _ => return Err("map beyond window"),
    }
    for chunk in chunks {
        unmap(chunk, MAX_MAP_PAGES).map_err(|_| "drain window")?;
    }

    // Many cycles: the kernel checks frame counts return to baseline.
    for cycle in 0..100u64 {
        let pages = cycle % MAX_MAP_PAGES + 1;
        let block = map(pages).map_err(|_| "cycle map")?;
        unsafe { core::ptr::write_volatile(block, cycle as u8) };
        unmap(block, pages).map_err(|_| "cycle unmap")?;
    }
    Ok(())
}
