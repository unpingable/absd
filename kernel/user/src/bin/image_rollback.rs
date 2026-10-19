//! Per-call frame exhaustion through the real spawn_image syscall.
//! The reserved-word allowance exists only in the matching qualification kernel.
#![no_std]
#![no_main]

use absd_abi::layout::USER_IMAGE_MIN;
use absd_abi::syscall::{
    ERROR_NO_MEMORY, FRAME_LIMIT_NONE, RIGHT_READ, SYS_SPAWN_IMAGE, SpawnHandleCopy,
    SpawnImageRequest,
};
use absd_user::{
    Cell, Child, MultiStart, Outcome, Pipe, frame_stats, info, resource_census, syscall3, wait,
};
use core::fmt::Write as _;

absd_user::multi_entry!(main);

fn put(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

fn segment(bytes: &mut [u8], index: usize, flags: u32, address: u64, size: u64) {
    let at = 64 + index * 56;
    put(bytes, at, &1u32.to_le_bytes()); // PT_LOAD
    put(bytes, at + 4, &flags.to_le_bytes());
    put(bytes, at + 16, &address.to_le_bytes());
    put(bytes, at + 24, &address.to_le_bytes());
    put(bytes, at + 40, &size.to_le_bytes());
    put(bytes, at + 48, &4096u64.to_le_bytes());
}

fn image() -> [u8; 256] {
    let mut bytes = [0u8; 256];
    put(&mut bytes, 0, b"\x7fELF\x02\x01\x01\x00");
    put(&mut bytes, 16, &2u16.to_le_bytes());
    put(&mut bytes, 18, &62u16.to_le_bytes());
    put(&mut bytes, 20, &1u32.to_le_bytes());
    put(&mut bytes, 24, &(USER_IMAGE_MIN + 240).to_le_bytes());
    put(&mut bytes, 32, &64u64.to_le_bytes());
    put(&mut bytes, 52, &64u16.to_le_bytes());
    put(&mut bytes, 54, &56u16.to_le_bytes());
    put(&mut bytes, 56, &3u16.to_le_bytes());
    segment(&mut bytes, 0, 5, USER_IMAGE_MIN, 4096); // executable code
    put(&mut bytes, 64 + 32, &256u64.to_le_bytes());
    segment(&mut bytes, 1, 6, USER_IMAGE_MIN + 0x40_0000, 4096);
    segment(&mut bytes, 2, 6, USER_IMAGE_MIN + 0x80_0000, 4096);
    // mov edi,42; mov eax,3; int 0x80; ud2
    put(
        &mut bytes,
        240,
        &[0xbf, 42, 0, 0, 0, 0xb8, 3, 0, 0, 0, 0xcd, 0x80, 0x0f, 0x0b],
    );
    bytes
}

fn spawn(image: &[u8], copies: &[SpawnHandleCopy], allowance: u64) -> i64 {
    let request = SpawnImageRequest {
        image: image.as_ptr() as u64,
        image_bytes: image.len() as u64,
        handles: copies.as_ptr() as u64,
        handle_count: copies.len() as u64,
    };
    unsafe { syscall3(SYS_SPAWN_IMAGE, &request as *const _ as u64, 0, allowance) }
}

fn run(start: &MultiStart<'_>) -> Result<(), &'static str> {
    let input = *start.handles.first().ok_or("input")?;
    if Pipe::from_raw(input).read_timeout(&mut [0; 1], 500) != Ok(0) {
        return Err("input eof");
    }
    let image = image();
    let cell = Cell::create(42).map_err(|_| "cell")?;
    let copies = [SpawnHandleCopy::new(cell.raw(), RIGHT_READ)];
    let baseline = resource_census().map_err(|_| "baseline census")?;
    let baseline_frames = frame_stats().map_err(|_| "baseline frames")?;
    // Exactly 20 frames fit, including the eight-frame kernel stack. This
    // also seeds PID continuity before the first refused attempt.
    let raw = spawn(&image, &copies, 20);
    if raw < 0 {
        return Err("bounded positive spawn");
    }
    let child = Child::from_raw(raw as u64);
    let mut last_pid = info(Some(child)).map_err(|_| "bounded positive info")?.pid;
    if wait(Some(child)) != Ok(Outcome::Exited(42))
        || resource_census() != Ok(baseline)
        || frame_stats() != Ok(baseline_frames)
    {
        return Err("bounded positive reclamation");
    }
    // Root, PDPT, directory, three separate page tables and their user
    // frames, stack table/pages, and finally the contiguous kernel stack.
    // Allowances 1..11 fail at distinct single-frame allocations; 12..19
    // all stop at the final eight-frame contiguous kernel-stack request.
    for allowance in 1..=19 {
        let before = resource_census().map_err(|_| "census before")?;
        let frames_before = frame_stats().map_err(|_| "frames before")?;
        if frames_before.allocation_limit != FRAME_LIMIT_NONE {
            return Err("quota before");
        }
        if spawn(&image, &copies, allowance) != ERROR_NO_MEMORY {
            return Err("refusal status");
        }
        let after = resource_census().map_err(|_| "census after")?;
        let frames_after = frame_stats().map_err(|_| "frames after")?;
        if before != after || frames_before != frames_after || cell.read() != Ok((0, 42)) {
            return Err("rollback census or cell");
        }
        // A successful child immediately after each refusal proves the
        // parent still runs and both process capacity and frames are usable.
        let raw = spawn(&image, &copies, 0);
        if raw < 0 {
            return Err("positive spawn");
        }
        let child = Child::from_raw(raw as u64);
        let pid = info(Some(child)).map_err(|_| "positive info")?.pid;
        if pid != last_pid + 1 {
            return Err("pid gap");
        }
        last_pid = pid;
        if wait(Some(child)) != Ok(Outcome::Exited(42)) {
            return Err("positive outcome");
        }
        if resource_census() != Ok(before)
            || frame_stats() != Ok(frames_before)
            || cell.read() != Ok((0, 42))
        {
            return Err("positive reclamation");
        }
    }
    let mut console = start.console;
    let _ = writeln!(console, "SPAWN IMAGE ROLLBACK OK refusals=19 controls=20");
    Ok(())
}

fn main(start: MultiStart<'_>) -> i32 {
    match run(&start) {
        Ok(()) => 0,
        Err(step) => {
            let mut console = start.console;
            let _ = writeln!(console, "SPAWN IMAGE ROLLBACK FAILED at {step}");
            1
        }
    }
}
