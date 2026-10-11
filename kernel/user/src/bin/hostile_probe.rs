//! Deliberately hostile qualification probe. Init's `hostile` boot spawns it
//! with a case selector in `Start.arg`. Case 0 is a non-fatal syscall and
//! pointer abuse battery that must be refused cleanly; cases 1-12 each commit
//! one act the kernel must answer by terminating only this process with the
//! architecturally derived exception; case 13 floods invalid syscalls until
//! init kills it. Cases 14-25 are the state-machine spike: handle/object
//! lifetime abuse, process-table exhaustion, map/unmap churn, object-table
//! exhaustion, scheduler churn, and blocked-child helpers for init's kill
//! paths (docs/HOSTILE-USERSPACE.md). A case that returns from its act means
//! the kernel failed to terminate the offender: it exits 90 + case so init
//! fails the boot.
#![no_std]
#![no_main]

use absd_abi::layout::{USER_ADDRESS_LIMIT, USER_HEAP_BASE, USER_STACK_TOP};
use absd_abi::syscall::{
    ERROR_BAD_HANDLE, ERROR_FAULT, ERROR_INVALID, ERROR_NOT_IMPLEMENTED, ERROR_RIGHTS,
    ERROR_TOO_MANY_HANDLES, SYS_DUPLICATE, SYS_INFO, SYS_KILL, SYS_MAP, SYS_READ, SYS_SPAWN,
    SYS_TRANSFER, SYS_UNMAP, SYS_WRITE, SpawnImageRequest, TRANSFER_READ,
};
use absd_user::{
    Cell, Child, Console, Error, Outcome, Pipe, SpawnHandleCopy, Start, close, duplicate,
    frame_stats, frame_stats_raw, kill, map, pipe_info, program, spawn_image_raw, spawn_many_copy,
    spawn_many_copy_raw, spawn_with, syscall3, transfer, unmap, wait, wait_raw,
};
use core::arch::asm;

absd_user::entry!(main);

/// Inside the supervisor-only identity map every user root shares at PML4
/// entry 0 (`src/vm.rs`): present, never user.
const SUPERVISOR: u64 = 0x10_0000;
/// Between `USER_REGION_END` and `USER_ADDRESS_LIMIT`: PML4 entries 2-255 of
/// a user root are absent, so this is a plain unmapped (non-present) address.
const GAP: u64 = 0x0000_0081_0000_0000;
/// Far above the canonical range: the CPU raises #GP before any page walk.
const NONCANONICAL: u64 = 0x8000_0000_0000_0000;
/// Invalid-syscall loop bound of the non-fatal battery.
const BATTERY_ROUNDS: u32 = 100_000;

fn main(start: Start) -> i32 {
    let console = start.console;
    match start.arg {
        0 => battery(console),
        1 => fault_case(console, "read-supervisor", SUPERVISOR, 1, || unsafe {
            core::hint::black_box(core::ptr::read_volatile(SUPERVISOR as *const u64));
        }),
        2 => fault_case(console, "write-supervisor", SUPERVISOR, 2, || unsafe {
            core::ptr::write_volatile(SUPERVISOR as *mut u64, 1);
        }),
        3 => fault_case(console, "exec-supervisor", SUPERVISOR, 3, || unsafe {
            asm!("call {0}", in(reg) SUPERVISOR, out("rax") _, out("rcx") _, out("rdx") _);
        }),
        4 => {
            // Anonymous heap pages are non-executable: plant a `ret` and call it.
            let Some(page) = map(1).ok() else {
                return 94;
            };
            unsafe { core::ptr::write_volatile(page, 0xc3) };
            let target = page as u64;
            fault_case(console, "exec-nx-heap", target, 4, || unsafe {
                asm!("call {0}", in(reg) target, out("rax") _, out("rcx") _, out("rdx") _);
            })
        }
        5 => {
            // A write to this program's own read-only `.text` must fault.
            let target = text_marker as fn() as *const u8 as u64;
            fault_case(console, "write-text", target, 5, || unsafe {
                core::ptr::write_volatile(target as *mut u8, 0x90);
            })
        }
        6 => fault_case(console, "read-null", 0, 6, || unsafe {
            // Address zero is a present supervisor mapping here, not an
            // unmapped null page (PML4 entry 0 is the kernel PDPT).
            core::hint::black_box(core::ptr::read_volatile(core::ptr::null::<u64>()));
        }),
        7 => fault_case(console, "read-gap", GAP, 7, || unsafe {
            core::hint::black_box(core::ptr::read_volatile(GAP as *const u64));
        }),
        8 => fault_case(console, "divide-zero", 0, 8, || unsafe {
            // Raw `div`: Rust's own `/` panics in software instead of taking
            // the hardware exception this case qualifies.
            asm!(
                "mov rdx, 0",
                "mov rax, 1",
                "div {0}",
                in(reg) 0u64,
                out("rax") _,
                out("rdx") _,
            );
        }),
        9 => fault_case(console, "io-instruction", 0, 9, || unsafe {
            // Reprogramming the PIT from ring 3 must not be possible.
            asm!("out 0x43, al", in("al") 0x36u8);
        }),
        10 => fault_case(console, "lidt", 0, 10, || unsafe {
            let descriptor = [0u8; 10];
            asm!("lidt [{0}]", in(reg) descriptor.as_ptr());
        }),
        11 => fault_case(console, "int3", 0, 11, || unsafe {
            asm!("int3", options(nomem, nostack));
        }),
        12 => fault_case(console, "noncanonical", NONCANONICAL, 12, || unsafe {
            core::hint::black_box(core::ptr::read_volatile(NONCANONICAL as *const u64));
        }),
        13 => {
            let _ = console.write_str("hostile: case flood\n");
            loop {
                unsafe {
                    syscall3(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
                }
            }
        }
        14 => state_handles(console),
        15 => fork_bomb(console),
        16 => vm_churn(console),
        17 => exit_mapped(console),
        18 => kill_mapped(console),
        19 => objects_exhausted(console, true),
        20 => objects_exhausted(console, false),
        21 => churn(console, 200),
        22 => churn(console, u32::MAX),
        23 => fault_with_child_and_pipe(console, start.handle),
        24 => middle_waiter(console),
        25 => blocked_reader(console, start.handle),
        _ => 89,
    }
}

fn text_marker() {}

/// Announces the case and its intended fault address, then commits the act.
/// Reaching the return means the kernel left the offender alive.
fn fault_case(
    console: Console,
    name: &'static str,
    target: u64,
    case: i32,
    act: impl FnOnce(),
) -> i32 {
    let _ = console.line(format_args!(
        "hostile: case {name} target=0x{target:016x}\n"
    ));
    act();
    90 + case
}

/// Every call below must be refused with exactly the documented error and
/// leave kernel and process state coherent enough for the positive controls
/// at the end. Returns 0 only when every refusal and control held.
fn battery(console: Console) -> i32 {
    // Undefined numbers: zero, the unassigned slot 23, an arbitrary one, and
    // the largest representable number, all with garbage argument registers.
    for number in [0u64, 23, 999, u64::MAX] {
        if unsafe { syscall3(number, u64::MAX, u64::MAX, u64::MAX) } != ERROR_NOT_IMPLEMENTED {
            return 91;
        }
    }
    // Garbage arguments on defined calls.
    if unsafe { syscall3(SYS_WRITE, u64::MAX, SUPERVISOR, 8) } != ERROR_BAD_HANDLE {
        return 92;
    }
    if unsafe { syscall3(SYS_KILL, u64::MAX, u64::MAX, u64::MAX) } != ERROR_BAD_HANDLE {
        return 92;
    }
    if unsafe { syscall3(SYS_INFO, u64::MAX, 0, 0) } != ERROR_BAD_HANDLE {
        return 92;
    }
    if unsafe { syscall3(SYS_DUPLICATE, u64::MAX, u64::MAX, 0) } != ERROR_RIGHTS {
        return 92;
    }
    for pages in [0u64, 65, u64::MAX] {
        if unsafe { syscall3(SYS_MAP, pages, 0, 0) } != ERROR_INVALID {
            return 92;
        }
    }
    // A bad handle on `wait` with a valid record reaches the handle check.
    let mut record = [0xdead_beefu64; 4];
    if wait_raw(u64::MAX, record.as_mut_ptr() as u64) != ERROR_BAD_HANDLE {
        return 92;
    }

    let message = *b"hostile probe: pointer abuse buffer";
    let valid = message.as_ptr() as u64;
    // Pointer abuse on `write`: null, supervisor, the unmapped gap, a range
    // ending past the user limit, the limit itself, and near-u64::MAX.
    for (address, length) in [
        (0u64, 8u64),
        (SUPERVISOR, 8),
        (GAP, 8),
        (USER_ADDRESS_LIMIT - 8, 16),
        (USER_ADDRESS_LIMIT, 8),
        (u64::MAX - 3, 8),
    ] {
        if unsafe { syscall3(SYS_WRITE, console.raw(), address, length) } != ERROR_FAULT {
            return 93;
        }
    }
    // Length abuse: zero and one past the 256-byte maximum.
    if unsafe { syscall3(SYS_WRITE, console.raw(), valid, 0) } != ERROR_INVALID {
        return 93;
    }
    if unsafe { syscall3(SYS_WRITE, console.raw(), valid, 257) } != ERROR_INVALID {
        return 93;
    }
    // A length crossing from a mapped page into an unmapped one is refused.
    let Ok(page) = map(1) else {
        return 94;
    };
    if unsafe { syscall3(SYS_WRITE, console.raw(), page as u64 + 4096 - 8, 16) } != ERROR_FAULT {
        return 93;
    }

    // Output records at bad addresses: `wait`, `transfer`, `frame_stats`.
    // (`boot_id` is not usable here: it needs RDRAND before it ever looks at
    // the pointer, and QEMU's default CPU has none.)
    for bad_record in [0u64, GAP, USER_ADDRESS_LIMIT - 8] {
        if wait_raw(0, bad_record) != ERROR_FAULT {
            return 95;
        }
    }
    if unsafe { syscall3(SYS_TRANSFER, console.raw(), 0, 0) } != ERROR_FAULT {
        return 95;
    }
    if unsafe { syscall3(SYS_TRANSFER, console.raw(), GAP, 0) } != ERROR_FAULT {
        return 95;
    }
    if frame_stats_raw(0) != ERROR_FAULT {
        return 95;
    }
    // Read-only memory where the kernel intends to write: refused before a
    // single byte changes.
    static READONLY_RECORD: [u8; 32] = [0x5a; 32];
    if frame_stats_raw(READONLY_RECORD.as_ptr() as u64) != ERROR_FAULT {
        return 95;
    }
    if READONLY_RECORD != [0x5a; 32] {
        return 95;
    }
    // A record straddling a mapped page into an unmapped one is refused whole:
    // the mapped part must keep its sentinel.
    let straddle = unsafe { page.add(4096 - 16) };
    unsafe { core::ptr::write_bytes(straddle, 0xa5, 16) };
    if frame_stats_raw(straddle as u64 + 8) != ERROR_FAULT {
        return 95;
    }
    for offset in 0..16 {
        if unsafe { core::ptr::read_volatile(straddle.add(offset)) } != 0xa5 {
            return 95;
        }
    }

    // `unmap` abuse: null, text, stack, unmapped heap (the page above this
    // process's own one-page mapping), and wraparound ranges.
    let text = text_marker as fn() as *const u8 as u64;
    for (address, pages) in [
        (0u64, 1u64),
        (text, 1),
        (USER_STACK_TOP - 4096, 1),
        (USER_HEAP_BASE + 4096, 1),
        (USER_HEAP_BASE, u64::MAX),
    ] {
        if unsafe { syscall3(SYS_UNMAP, address, pages, 0) } != ERROR_INVALID {
            return 96;
        }
    }

    // Pipe pointers and lengths get the same validation; a 256-byte transfer
    // is the max-length positive control.
    let Ok(pipe) = Pipe::create() else {
        return 94;
    };
    if unsafe { syscall3(SYS_WRITE, pipe.raw(), 0, 8) } != ERROR_FAULT {
        return 97;
    }
    if unsafe { syscall3(SYS_READ, pipe.raw(), 0, 8) } != ERROR_FAULT {
        return 97;
    }
    if unsafe { syscall3(SYS_WRITE, pipe.raw(), valid, 0) } != ERROR_INVALID {
        return 97;
    }
    let chunk = [0xa5u8; 256];
    let mut back = [0u8; 256];
    if unsafe { syscall3(SYS_WRITE, pipe.raw(), chunk.as_ptr() as u64, 256) } != 256
        || unsafe { syscall3(SYS_READ, pipe.raw(), back.as_mut_ptr() as u64, 256) } != 256
        || back != chunk
    {
        return 97;
    }

    // Repeated invalid syscalls under timer preemption: every one must come
    // back with the defined error, a hundred thousand times in a row.
    let mut refused = 0u64;
    for _ in 0..BATTERY_ROUNDS {
        if unsafe { syscall3(u64::MAX, u64::MAX, u64::MAX, u64::MAX) } == ERROR_NOT_IMPLEMENTED {
            refused += 1;
        }
    }
    if refused != BATTERY_ROUNDS as u64 {
        return 98;
    }

    // Positive controls after the whole battery: the process is alive, its
    // remaining mapping works, and ordinary I/O is undisturbed.
    unsafe { core::ptr::write_volatile(page, 0x11) };
    if unsafe { core::ptr::read_volatile(page) } != 0x11 {
        return 99;
    }
    if unmap(page, 1).is_err() {
        return 99;
    }
    let _ = console.line(format_args!("hostile: sys abuse done refused={refused}\n"));
    0
}

/// One low-level lifecycle step of case 15/21/22's churn: a child that
/// exits on its own, reaped with its exact outcome.
fn churn_exit7() -> Result<(), i32> {
    let child = spawn_with(program::EXIT7, 0, 0).map_err(|_| 74)?;
    match wait(Some(child)) {
        Ok(Outcome::Exited(7)) => Ok(()),
        _ => Err(75),
    }
}

/// Case 14: handle and object lifetime abuse. Every crafted, stale,
/// reissued, or rights-poor reference must be refused with the defined
/// error and must never alias a live object; positive controls after each
/// refusal class prove the table still works.
fn state_handles(console: Console) -> i32 {
    let _ = console.write_str("hostile: case state-handles\n");

    // Duplicate read-only, close the original: the duplicate still reads
    // (EOF, because the original held the only write right), still refuses
    // to write, and still describes exactly one reader and no writers.
    let pipe = match Pipe::create() {
        Ok(pipe) => pipe,
        Err(_) => return 30,
    };
    let reader = match duplicate(pipe.raw(), absd_user::RIGHT_READ) {
        Ok(handle) => handle,
        Err(_) => return 30,
    };
    match pipe_info(pipe.raw()) {
        Ok(info) if info.readers == 2 && info.writers == 1 => {}
        _ => return 30,
    }
    if close(pipe.raw()).is_err() {
        return 30;
    }
    let byte = [1u8];
    if unsafe { syscall3(SYS_WRITE, reader, byte.as_ptr() as u64, 1) } != ERROR_RIGHTS {
        return 31;
    }
    let mut buffer = [0u8; 4];
    match Pipe::from_raw(reader).read_once(&mut buffer) {
        Ok(0) => {}
        _ => return 32,
    }
    match pipe_info(reader) {
        Ok(info) if info.readers == 1 && info.writers == 0 => {}
        _ => return 32,
    }
    if close(reader).is_err() {
        return 32;
    }

    // Close twice and use after close: the value is dead the first time.
    let pipe = match Pipe::create() {
        Ok(pipe) => pipe,
        Err(_) => return 33,
    };
    if close(pipe.raw()).is_err() {
        return 33;
    }
    if close(pipe.raw()) != Err(Error::BadHandle) {
        return 33;
    }
    if unsafe { syscall3(SYS_WRITE, pipe.raw(), byte.as_ptr() as u64, 1) } != ERROR_BAD_HANDLE {
        return 34;
    }

    // A closed value never aliases the object reissued into its slot.
    let stale = match Pipe::create() {
        Ok(pipe) => pipe,
        Err(_) => return 35,
    };
    let stale = stale.raw();
    if close(stale).is_err() {
        return 35;
    }
    let reissued = match Pipe::create() {
        Ok(pipe) => pipe,
        Err(_) => return 35,
    };
    if reissued.raw() == stale || pipe_info(stale) != Err(Error::BadHandle) {
        return 35;
    }

    // Crafted values resolve to nothing: zero, one, all ones, the live
    // pipe's slot with a wrong tag, and an index beyond the table.
    for value in [
        0,
        1,
        u64::MAX,
        reissued.raw() ^ (1 << 8),
        absd_user::MAX_SPAWN_HANDLES as u64,
    ] {
        if close(value) != Err(Error::BadHandle) {
            return 36;
        }
        if duplicate(value, absd_user::RIGHT_READ) != Err(Error::BadHandle) {
            return 37;
        }
    }

    // Rights never widen along a duplicate chain, alien right bits are
    // refused, and a zero-rights duplicate can do nothing at all.
    if duplicate(
        reissued.raw(),
        absd_user::RIGHT_READ | absd_user::RIGHT_KILL,
    ) != Err(Error::Rights)
    {
        return 38;
    }
    if duplicate(reissued.raw(), 1 << 7) != Err(Error::Rights) {
        return 38;
    }
    let readonly = match duplicate(reissued.raw(), absd_user::RIGHT_READ) {
        Ok(handle) => handle,
        Err(_) => return 38,
    };
    if duplicate(readonly, absd_user::RIGHT_READ | absd_user::RIGHT_WRITE) != Err(Error::Rights) {
        return 39;
    }
    let inert = match duplicate(reissued.raw(), 0) {
        Ok(handle) => handle,
        Err(_) => return 39,
    };
    if unsafe { syscall3(SYS_WRITE, inert, byte.as_ptr() as u64, 1) } != ERROR_RIGHTS {
        return 40;
    }
    if close(inert).is_err() || close(readonly).is_err() {
        return 40;
    }

    // Process handles cannot cross a spawn, as a single transfer or inside
    // a copy vector; a vector with one bad record fails whole and spawns
    // nothing.
    let child = match spawn_with(program::EXIT7, 0, 0) {
        Ok(child) => child,
        Err(_) => return 41,
    };
    if unsafe { syscall3(SYS_SPAWN, program::EXIT7, child.raw(), 0) } != ERROR_BAD_HANDLE {
        return 41;
    }
    match wait(Some(child)) {
        Ok(Outcome::Exited(7)) => {}
        _ => return 42,
    }
    let records = [
        SpawnHandleCopy::new(reissued.raw(), absd_user::RIGHT_READ),
        SpawnHandleCopy::new(0x5ead_5ead, absd_user::RIGHT_READ),
    ];
    match spawn_many_copy(program::EXIT7, &records) {
        Err(Error::BadHandle) => {}
        _ => return 43,
    }
    let child = match spawn_with(program::EXIT7, 0, 0) {
        Ok(child) => child,
        Err(_) => return 44,
    };
    let records = [SpawnHandleCopy::new(child.raw(), absd_user::RIGHT_WAIT)];
    match spawn_many_copy(program::EXIT7, &records) {
        Err(Error::BadHandle) => {}
        _ => return 44,
    }
    match wait(Some(child)) {
        Ok(Outcome::Exited(7)) => {}
        _ => return 44,
    }

    // Spawn validation: unknown program, alien flag bits, an oversized
    // copy count, an empty image, and an image that is not an ELF.
    if unsafe { syscall3(SYS_SPAWN, 999, 0, 0) } != absd_abi::syscall::ERROR_NOT_FOUND {
        return 45;
    }
    if unsafe { syscall3(SYS_SPAWN, program::EXIT7 | (1 << 40), 0, 0) } != ERROR_INVALID {
        return 45;
    }
    if spawn_many_copy_raw(program::EXIT7, 0, 65) != Err(Error::Invalid) {
        return 45;
    }
    let mut request = SpawnImageRequest {
        image: byte.as_ptr() as u64,
        image_bytes: 0,
        handles: 0,
        handle_count: 0,
    };
    if spawn_image_raw(&request as *const SpawnImageRequest as u64, 0, 0) != Err(Error::Invalid) {
        return 46;
    }
    let garbage = [0x5au8; 64];
    request.image = garbage.as_ptr() as u64;
    request.image_bytes = garbage.len() as u64;
    match spawn_image_raw(&request as *const SpawnImageRequest as u64, 0, 0) {
        Err(Error::NotExecutable) => {}
        _ => return 46,
    }

    // A bounded transfer that cannot proceed gives up on its deadline; the
    // pipe then still works.
    match transfer(reissued.raw(), TRANSFER_READ, buffer.as_mut_ptr(), 4, 30) {
        Err(Error::Timeout) => {}
        _ => return 47,
    }
    match reissued.write_once(&[0x5a; 4]) {
        Ok(4) => {}
        _ => return 47,
    }
    match transfer(reissued.raw(), TRANSFER_READ, buffer.as_mut_ptr(), 4, 30) {
        Ok(4) if buffer == [0x5a; 4] => {}
        _ => return 47,
    }

    // The handle table is bounded: 64 entries, one console and one pipe
    // held, so exactly 62 duplicates fit; the next is refused, and even an
    // otherwise valid spawn fails up front while the table is full.
    let mut issued = [0u64; 64];
    let mut count = 0usize;
    loop {
        match duplicate(reissued.raw(), absd_user::RIGHT_READ) {
            Ok(handle) => {
                issued[count] = handle;
                count += 1;
            }
            Err(Error::TooManyHandles) => break,
            Err(_) => return 48,
        }
        if count == 64 {
            return 48;
        }
    }
    if count != 62 {
        return 49;
    }
    if unsafe { syscall3(SYS_SPAWN, program::EXIT7, 0, 0) } != ERROR_TOO_MANY_HANDLES {
        return 49;
    }
    for handle in &issued[..count] {
        if close(*handle).is_err() {
            return 49;
        }
    }
    if close(reissued.raw()).is_err() {
        return 49;
    }

    // Positive control after every refusal class above.
    match Pipe::create() {
        Ok(pipe) => {
            if pipe.write_once(&[0xa5; 8]) != Ok(8) {
                return 50;
            }
            let mut back = [0u8; 8];
            if pipe.read_once(&mut back) != Ok(8) || back != [0xa5; 8] {
                return 50;
            }
            if close(pipe.raw()).is_err() {
                return 50;
            }
        }
        Err(_) => return 50,
    }
    let _ = console.write_str("hostile: state handles done\n");
    0
}

/// Case 15: fill the process table with never-waking sleepers. The spawn
/// past the last free slot must fail closed, and every spawned child is
/// then killed and reaped, leaving the table exactly as it was.
fn fork_bomb(console: Console) -> i32 {
    let _ = console.write_str("hostile: case fork-bomb\n");
    let mut children = [0u64; 16];
    let mut spawned = 0usize;
    loop {
        match spawn_with(program::SLEEPER, 0, u64::MAX) {
            Ok(child) => {
                children[spawned] = child.raw();
                spawned += 1;
            }
            Err(Error::Again) => break,
            Err(_) => return 51,
        }
        if spawned == 16 {
            return 51;
        }
    }
    // Three of the sixteen slots are taken: init, this probe, and the
    // first witness, which has exited but not been reaped yet.
    if spawned != 13 {
        return 52;
    }
    for &raw in &children[..spawned] {
        let child = Child::from_raw(raw);
        if kill(child).is_err() {
            return 53;
        }
        match wait(Some(child)) {
            Ok(Outcome::Killed) => {}
            _ => return 54,
        }
    }
    let _ = console.line(format_args!("hostile: fork bomb spawned={spawned}\n"));
    0
}

/// Case 16: map/unmap churn with sentinels, refused operations that must
/// not disturb live mappings, lowest-free-run reuse, and a complete fill
/// of the 8192-page heap window that fails closed and recovers.
fn vm_churn(console: Console) -> i32 {
    let _ = console.write_str("hostile: case vm-churn\n");
    // The warmup allocates this window's page tables; unmap returns only
    // the user pages, so the frame baseline is taken after it.
    let warm = match map(64) {
        Ok(page) => page,
        Err(_) => return 55,
    };
    if unmap(warm, 64).is_err() {
        return 55;
    }
    let baseline = match frame_stats() {
        Ok(stats) => stats,
        Err(_) => return 55,
    };
    for cycle in 0..512u64 {
        let pages = cycle % 8 + 1;
        let run = match map(pages) {
            Ok(run) => run,
            Err(_) => return 56,
        };
        for index in 0..pages {
            let page = unsafe { run.add((index * 4096) as usize) };
            let pattern = (cycle + index) as u8;
            unsafe {
                core::ptr::write_volatile(page, pattern);
                if core::ptr::read_volatile(page) != pattern {
                    return 57;
                }
            }
        }
        if unmap(run, pages).is_err() {
            return 58;
        }
    }
    let after = match frame_stats() {
        Ok(stats) => stats,
        Err(_) => return 59,
    };
    if after.allocated_frames != baseline.allocated_frames
        || after.free_frames != baseline.free_frames
    {
        return 59;
    }

    // Refused unmaps leave live mappings untouched: a misaligned address
    // and a range that is only partially mapped.
    let live = match map(2) {
        Ok(page) => page,
        Err(_) => return 60,
    };
    unsafe { core::ptr::write_bytes(live, 0x5a, 2 * 4096) };
    if unsafe { syscall3(SYS_UNMAP, live as u64 + 1, 1, 0) } != ERROR_INVALID {
        return 61;
    }
    if unsafe { syscall3(SYS_UNMAP, live as u64, 3, 0) } != ERROR_INVALID {
        return 62;
    }
    for offset in 0..2 * 4096 {
        if unsafe { core::ptr::read_volatile(live.add(offset)) } != 0x5a {
            return 63;
        }
    }
    if unmap(live, 2).is_err() {
        return 63;
    }

    // The lowest free run is reused, and the surviving neighbour keeps its
    // bytes across the churn.
    let first = match map(1) {
        Ok(page) => page,
        Err(_) => return 64,
    };
    let second = match map(1) {
        Ok(page) => page,
        Err(_) => return 64,
    };
    if second == first {
        return 64;
    }
    unsafe {
        core::ptr::write_volatile(first, 0xa1);
        core::ptr::write_volatile(second, 0xb2);
    }
    if unmap(first, 1).is_err() {
        return 65;
    }
    let reused = match map(1) {
        Ok(page) => page,
        Err(_) => return 65,
    };
    if reused != first || unsafe { core::ptr::read_volatile(second) } != 0xb2 {
        return 65;
    }
    if unmap(reused, 1).is_err() || unmap(second, 1).is_err() {
        return 66;
    }

    // Fill the whole heap window: 128 runs of 64 pages. The 129th map and
    // even a one-page map must fail closed with the window full.
    let mut regions = [core::ptr::null_mut::<u8>(); 128];
    let mut filled = 0usize;
    loop {
        match map(64) {
            Ok(region) => {
                regions[filled] = region;
                filled += 1;
            }
            Err(Error::NoMemory) => break,
            Err(_) => return 67,
        }
        if filled > 128 {
            return 67;
        }
    }
    if filled != 128 {
        return 68;
    }
    match map(1) {
        Err(Error::NoMemory) => {}
        _ => return 68,
    }
    for &region in &regions {
        unsafe {
            core::ptr::write_volatile(region, 0x11);
            if core::ptr::read_volatile(region) != 0x11 {
                return 69;
            }
        }
    }
    for &region in &regions {
        if unmap(region, 64).is_err() {
            return 69;
        }
    }
    // Recovery: the window is whole again.
    let page = match map(64) {
        Ok(page) => page,
        Err(_) => return 70,
    };
    if unmap(page, 64).is_err() {
        return 70;
    }
    let _ = console.line(format_args!(
        "hostile: heap window filled pages={}\n",
        128 * 64
    ));
    let _ = console.write_str("hostile: vm churn cycles=512\n");
    0
}

/// Case 17: own 96 touched heap pages, then fault. Init measures complete
/// reclamation with the frame counters.
fn exit_mapped(console: Console) -> i32 {
    let first = match map(64) {
        Ok(page) => page,
        Err(_) => return 71,
    };
    let second = match map(32) {
        Ok(page) => page,
        Err(_) => return 71,
    };
    for offset in 0..64 {
        unsafe { core::ptr::write_volatile(first.add(offset * 4096), 0x77) };
    }
    for offset in 0..32 {
        unsafe { core::ptr::write_volatile(second.add(offset * 4096), 0x88) };
    }
    fault_case(console, "exit-mapped", 0, 17, || unsafe {
        asm!(
            "mov rdx, 0",
            "mov rax, 1",
            "div {0}",
            in(reg) 0u64,
            out("rax") _,
            out("rdx") _,
        );
    })
}

/// Case 18: own 96 touched heap pages, then loop until init kills us.
fn kill_mapped(console: Console) -> i32 {
    let first = match map(64) {
        Ok(page) => page,
        Err(_) => return 71,
    };
    let second = match map(32) {
        Ok(page) => page,
        Err(_) => return 71,
    };
    for offset in 0..64 {
        unsafe { core::ptr::write_volatile(first.add(offset * 4096), 0x77) };
    }
    for offset in 0..32 {
        unsafe { core::ptr::write_volatile(second.add(offset * 4096), 0x88) };
    }
    let _ = console.write_str("hostile: case kill-mapped pages=96\n");
    loop {
        core::hint::spin_loop();
    }
}

/// Cases 19 and 20: fill one kernel object table through legitimate calls,
/// prove the next create fails closed, and exit still holding everything,
/// so process termination drains every reference at once.
fn objects_exhausted(console: Console, cells: bool) -> i32 {
    if cells {
        let _ = console.write_str("hostile: case cells-exhaust\n");
        let mut kept = [0u64; 32];
        let mut count = 0usize;
        loop {
            match Cell::create(0x5a) {
                Ok(cell) => {
                    kept[count] = cell.raw();
                    count += 1;
                }
                Err(Error::NoMemory) => break,
                Err(_) => return 72,
            }
            if count > 32 {
                return 72;
            }
        }
        if count != 32 {
            return 72;
        }
        // A full table changes nothing about the live objects.
        match Cell::from_raw(kept[0]).transition(0, 1) {
            Ok(1) => {}
            _ => return 72,
        }
        let _ = console.line(format_args!("hostile: cells filled={count}\n"));
        return 0;
    }
    let _ = console.write_str("hostile: case pipes-exhaust\n");
    let mut kept = [0u64; 48];
    let mut count = 0usize;
    loop {
        match Pipe::create() {
            Ok(pipe) => {
                kept[count] = pipe.raw();
                count += 1;
            }
            Err(Error::NoMemory) => break,
            Err(_) => return 73,
        }
        if count > 48 {
            return 73;
        }
    }
    if count != 48 {
        return 73;
    }
    let pipe = Pipe::from_raw(kept[0]);
    if pipe.write_once(&[0x5a; 8]) != Ok(8) {
        return 73;
    }
    let mut back = [0u8; 8];
    if pipe.read_once(&mut back) != Ok(8) || back != [0x5a; 8] {
        return 73;
    }
    let _ = console.line(format_args!("hostile: pipes filled={count}\n"));
    0
}

/// Cases 21 and 22: bounded and unbounded state churn with no yields, so
/// the PIT preempts mid-sequence: spawn and reap a child, map and unmap,
/// a pipe round trip, and a cell create/transition/close per cycle.
fn churn(console: Console, cycles: u32) -> i32 {
    let _ = console.write_str("hostile: case churn\n");
    let mut done = 0u32;
    while done < cycles {
        if let Err(code) = churn_exit7() {
            return code;
        }
        let run = match map(4) {
            Ok(run) => run,
            Err(_) => return 76,
        };
        unsafe { core::ptr::write_bytes(run, 0x5a, 4 * 4096) };
        if unmap(run, 4).is_err() {
            return 77;
        }
        let pipe = match Pipe::create() {
            Ok(pipe) => pipe,
            Err(_) => return 78,
        };
        if pipe.write_once(&[0x5a; 16]) != Ok(16) {
            return 79;
        }
        let mut back = [0u8; 16];
        if pipe.read_once(&mut back) != Ok(16) || back != [0x5a; 16] {
            return 80;
        }
        if close(pipe.raw()).is_err() {
            return 81;
        }
        let cell = match Cell::create(u64::from(done)) {
            Ok(cell) => cell,
            Err(_) => return 82,
        };
        match cell.transition(0, u64::from(done) + 1) {
            Ok(1) => {}
            _ => return 83,
        }
        if close(cell.raw()).is_err() {
            return 84;
        }
        done += 1;
    }
    let _ = console.line(format_args!("hostile: churn cycles={done}\n"));
    0
}

/// Case 23: hold the transferred pipe write end and a live sleeper child,
/// then fault. Init must see EOF on the pipe (the write end was released)
/// and must adopt and reap the sleeper.
fn fault_with_child_and_pipe(console: Console, handle: u64) -> i32 {
    if handle == 0 {
        return 29;
    }
    if spawn_with(program::SLEEPER, 0, 100).is_err() {
        return 29;
    }
    fault_case(console, "exit-with-child-and-pipe", 0, 23, || unsafe {
        asm!(
            "mov rdx, 0",
            "mov rax, 1",
            "div {0}",
            in(reg) 0u64,
            out("rax") _,
            out("rdx") _,
        );
    })
}

/// Case 24: spawn a bounded sleeper and block in `wait` on it; init kills
/// this process mid-wait, and the sleeper is adopted by init.
fn middle_waiter(console: Console) -> i32 {
    let _ = console.write_str("hostile: case middle-waiter\n");
    let child = match spawn_with(program::SLEEPER, 0, 80) {
        Ok(child) => child,
        Err(_) => return 28,
    };
    // Any return at all means the kernel lost the kill.
    let _ = wait(Some(child));
    28
}

/// Case 25: block reading a pipe whose writer (init) never writes; init
/// kills this process mid-read, releasing the only read end.
fn blocked_reader(console: Console, handle: u64) -> i32 {
    let _ = console.write_str("hostile: case blocked-reader\n");
    if handle == 0 {
        return 27;
    }
    let mut buffer = [0u8; 8];
    let _ = Pipe::from_raw(handle).read_once(&mut buffer);
    27
}
