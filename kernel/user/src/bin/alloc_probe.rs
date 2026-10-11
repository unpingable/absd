//! Exercises the reusable map-backed userspace allocator with ordinary
//! `alloc` containers. Mapped chunks stay process-owned until teardown.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::alloc::{alloc, dealloc};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::Layout;

use absd_abi::layout::USER_HEAP_PAGES;
use absd_user::{MapAllocator, Start};

#[global_allocator]
static ALLOCATOR: MapAllocator = MapAllocator::new();

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    match run() {
        Ok(()) => {
            let _ = start.console.write_str("USER HEAP ALLOC OK\n");
            0
        }
        Err(step) => {
            let _ = start.console.write_str("alloc-probe: FAILED at ");
            let _ = start.console.write_str(step);
            let _ = start.console.write_str("\n");
            108
        }
    }
}

fn run() -> Result<(), &'static str> {
    // A released container must be immediately reusable at the same first-fit
    // address, with alignment and contents preserved across resize.
    let mut first = Vec::<u64>::new();
    first
        .try_reserve_exact(4_096)
        .map_err(|_| "reserve first vector")?;
    for value in 0..4_096u64 {
        first.push(value ^ 0x55aa_55aa_55aa_55aa);
    }
    let first_pointer = first.as_ptr();
    let first_capacity = first.capacity();
    if first_capacity < 4_096
        || first
            .iter()
            .enumerate()
            .any(|(index, &value)| value != (index as u64 ^ 0x55aa_55aa_55aa_55aa))
    {
        return Err("first vector contents");
    }
    drop(first);

    let mut reused = Vec::<u64>::new();
    reused
        .try_reserve_exact(first_capacity)
        .map_err(|_| "reserve reused vector")?;
    if reused.as_ptr() != first_pointer {
        return Err("first-fit reuse");
    }
    reused.resize(first_capacity, 7);
    reused
        .try_reserve_exact(first_capacity)
        .map_err(|_| "grow reused vector")?;
    let old_len = reused.len();
    reused.resize(first_capacity * 2, 9);
    if reused[..old_len].iter().any(|&value| value != 7)
        || reused[old_len..].iter().any(|&value| value != 9)
    {
        return Err("vector resize contents");
    }
    drop(reused);

    let boxed = Box::new((0x1234_5678_u64, 0x9abc_def0_u64));
    if *boxed != (0x1234_5678, 0x9abc_def0) {
        return Err("box contents");
    }
    drop(boxed);

    let mut text = String::from("allocator:");
    text.try_reserve(8_192).map_err(|_| "reserve string")?;
    for _ in 0..8_192 {
        text.push('x');
    }
    if text.len() != 8_202 || !text.starts_with("allocator:") || !text.ends_with("xxxx") {
        return Err("string contents");
    }
    drop(text);

    // Exercise alignment without placing a page-aligned temporary on the
    // stack. Deallocation returns the exact layout to the free list.
    let aligned_layout = Layout::from_size_align(96, 4_096).map_err(|_| "aligned layout")?;
    let aligned = unsafe { alloc(aligned_layout) };
    if aligned.is_null() || !(aligned as usize).is_multiple_of(4_096) {
        return Err("aligned allocation");
    }
    unsafe {
        core::ptr::write_bytes(aligned, 0xa5, aligned_layout.size());
        dealloc(aligned, aligned_layout);
    }

    // One larger allocation still grows through a single bounded map call.
    let mut large = Vec::<u8>::new();
    large
        .try_reserve_exact(200 * 1_024)
        .map_err(|_| "reserve large vector")?;
    large.resize(200 * 1_024, 0x5a);
    if large.len() != 200 * 1_024 || large.iter().any(|&byte| byte != 0x5a) {
        return Err("large vector contents");
    }
    drop(large);

    // Repeated differently-sized lifetimes exercise splitting and coalescing.
    for cycle in 1..=64usize {
        let length = cycle * 97;
        let mut values = Vec::<u32>::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| "reserve lifecycle vector")?;
        values.resize(length, cycle as u32);
        if values.first() != Some(&(cycle as u32)) || values.last() != Some(&(cycle as u32)) {
            return Err("lifecycle contents");
        }
    }

    // A request larger than the complete heap cannot be satisfied by one
    // bounded growth chunk and returns through the fallible collection API.
    let mut impossible = Vec::<u8>::new();
    if impossible
        .try_reserve_exact((USER_HEAP_PAGES as usize + 1) * 4_096)
        .is_ok()
    {
        return Err("oversized allocation succeeded");
    }
    Ok(())
}
