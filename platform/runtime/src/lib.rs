#![no_std]

extern crate alloc;

mod allocator;
mod broker;
mod census_wire;
pub mod cwd;
pub mod fsd;
pub mod layout;
mod ledger;
pub mod process;
pub mod session;
pub mod storage;
mod wire_kind;

/// The server side of file server channels: a process started with the
/// block handle and channel ends (init's file server) finds its ends here.
pub mod server {
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;

    struct Global(UnsafeCell<Vec<(u64, u64)>>);
    // Single-threaded; written once by the CRT before `main`.
    unsafe impl Sync for Global {}
    static CHANNELS: Global = Global(UnsafeCell::new(Vec::new()));

    pub(crate) fn install(channels: Vec<(u64, u64)>) {
        unsafe { *CHANNELS.0.get() = channels };
    }

    /// `(request reader, reply writer)` per channel, the control channel
    /// first.
    pub fn channels() -> Vec<(u64, u64)> {
        unsafe { (*CHANNELS.0.get()).clone() }
    }
}

use core::alloc::{GlobalAlloc, Layout};
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use allocator::MapAllocator;

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 3;
const SYS_GETPID: u64 = 4;
const SYS_CLOSE: u64 = 9;
const SYS_MAP: u64 = 7;
const SYS_UNMAP: u64 = 8;
const SYS_CELL_READ: u64 = 11;
const SYS_CELL_TRANSITION: u64 = 12;
const SYS_READ: u64 = 15;
const SYS_TIME: u64 = 17;
const SYS_DUPLICATE: u64 = 13;
const SYS_BLOCK_INFO: u64 = 24;
const SYS_BLOCK_READ: u64 = 25;
const SYS_BLOCK_WRITE: u64 = 26;
const SYS_BLOCK_FLUSH: u64 = 27;
/// `block_read_many`/`block_write_many` (kernel `abi/src/syscall.rs`):
/// `1..=8` consecutive sectors in one request, described by a 16-byte
/// `{lba, sectors}` record. Additive to ABI generation 1; a kernel without
/// them answers `-38` and `layout` falls back to single sectors.
const SYS_BLOCK_READ_MANY: u64 = 43;
const SYS_BLOCK_WRITE_MANY: u64 = 44;
/// `machine_stop(handle, code)` (kernel `abi/src/syscall.rs`). The older
/// boot-mode-gated `stop` (28) is retired: the kernel answers it `-38`.
const SYS_MACHINE_STOP: u64 = 37;
const SYS_BOOT_ID: u64 = 29;
const SYS_WALL_CLOCK: u64 = 30;
const SYS_FRAME_STATS: u64 = 35;
const SYS_TRANSFER: u64 = 21;
const SYS_SLEEP: u64 = 18;
const SYS_NIC_INFO: u64 = 32;
const SYS_NIC_SEND: u64 = 33;
const SYS_NIC_RECEIVE: u64 = 34;
/// `abi_version()` (kernel `abi/src/syscall.rs`): the kernel's syscall ABI
/// generation, which must equal `absd_release::KERNEL_ABI` (this table's
/// generation); `-38` from a kernel older than the call.
const SYS_ABI_VERSION: u64 = 42;
const MAX_TRANSFER: usize = 256;

#[global_allocator]
static ALLOCATOR: MapAllocator = MapAllocator::new();

static INPUT: AtomicU64 = AtomicU64::new(0);
static OUTPUT: AtomicU64 = AtomicU64::new(0);
/// Output explicitly named by a validated startup record, without console fallback.
static STARTUP_OUTPUT: AtomicU64 = AtomicU64::new(0);
/// Standard error when the startup record names one; else the console.
static ERROR: AtomicU64 = AtomicU64::new(0);
/// The startup record's environment: `KEY=VALUE` entries as `[pointer,
/// length]` pairs, fixed before `main` and never changed.
static ENVIRONMENT: AtomicU64 = AtomicU64::new(0);
static ENVIRONMENT_COUNT: AtomicU64 = AtomicU64::new(0);

/// The read-only environment init's policy gave this process (empty unless
/// the startup record carried one). Stores the entry count at `count`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_environ(count: *mut usize) -> *const [usize; 2] {
    unsafe { *count = ENVIRONMENT_COUNT.load(Ordering::Relaxed) as usize };
    ENVIRONMENT.load(Ordering::Relaxed) as *const [usize; 2]
}
/// The block device handle (durable boots only) and this boot's step word.
static BLOCK: AtomicU64 = AtomicU64::new(0);
static STEP: AtomicU64 = AtomicU64::new(0);
/// The NIC handle, when the startup record names one (`net` boots).
static NIC: AtomicU64 = AtomicU64::new(0);
/// The machine handle, when the startup record names one: init gives a
/// qualification durable worker one with the stop right only.
static MACHINE: AtomicU64 = AtomicU64::new(0);
/// The liveness cell, when the startup record names one: init gives a
/// served service one with read and write rights. This process is the
/// cell's only writer and is single-threaded, so it keeps the cell's
/// version and value itself after one read instead of reading per beat.
static LIVENESS: AtomicU64 = AtomicU64::new(0);
static LIVENESS_KNOWN: AtomicBool = AtomicBool::new(false);
static LIVENESS_VERSION: AtomicU64 = AtomicU64::new(0);
static LIVENESS_VALUE: AtomicU64 = AtomicU64::new(0);
/// Currently owned anonymous heap pages, including retained pooled pages.
static MAPPED_PAGES: AtomicU64 = AtomicU64::new(0);

#[inline]
unsafe fn syscall3(number: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let raw: i64;
    unsafe {
        asm!(
            "int 0x80",
            inout("rax") number => raw,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            options(nostack, preserves_flags),
        );
    }
    raw
}

pub fn link_anchor() {}

/// This boot's step word from the read-only cell init handed over; zero when
/// the process was not started through a durable boot.
pub fn step() -> u64 {
    STEP.load(Ordering::Relaxed)
}

/// Whether the kernel handed this process a block device.
pub fn has_block_device() -> bool {
    BLOCK.load(Ordering::Relaxed) != 0
}

/// Abrupt machine stop at a named point: QEMU exits with this code through
/// the debug-exit device and no later instruction runs. The authority is
/// the machine handle the startup record named; a process given none (every
/// session program, every child) passes none and the kernel refuses with
/// `-9`, `-1` without the stop right. Returns only with that refusal.
pub fn stop(code: u64) -> i64 {
    unsafe { syscall3(SYS_MACHINE_STOP, MACHINE.load(Ordering::Relaxed), code, 0) }
}

/// The kernel's syscall ABI generation (`abi_version`, syscall 42), or its
/// refusal (`-38` from a kernel without the call). Every process has
/// already checked it equals `absd_release::KERNEL_ABI` before `main`.
pub fn kernel_abi() -> i64 {
    unsafe { syscall3(SYS_ABI_VERSION, 0, 0, 0) }
}

/// The first thing every process does (`docs/RELEASE.md` section 3, item
/// 4): the kernel must speak the syscall ABI generation this runtime's
/// hand-copied table was written for. Otherwise one line on the console
/// and exit 103, using only `write` and `exit`, before the startup record
/// is read, before any allocation, and before any file-server use.
fn require_kernel_abi(console: u64) {
    let answer = kernel_abi();
    if answer == i64::from(absd_release::KERNEL_ABI) {
        return;
    }
    let mut buffer = [0u8; absd_release::ABI_LINE_BYTES];
    let line = absd_release::abi_refusal_line(answer, &mut buffer);
    unsafe { syscall3(SYS_WRITE, console, line.as_ptr() as u64, line.len() as u64) };
    __absd_std_exit(ABI_REFUSED);
}

/// Exit status of a process whose kernel speaks another syscall ABI.
pub const ABI_REFUSED: i32 = 103;

/// PIT ticks since boot, about 1 kHz.
pub fn ticks() -> u64 {
    unsafe { syscall3(SYS_TIME, 0, 0, 0) as u64 }
}

#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_ticks() -> u64 {
    ticks()
}

/// Milliseconds since boot, floored, from the PIT tick counter. The kernel
/// programs PIT channel 0 with divisor 1193 (kernel `src/main.rs`), so a
/// tick is 1193 / 1193181.67 s, about 0.99985 ms (1000.15 Hz), and this
/// converts exactly rather than calling a tick a millisecond. Resolution is
/// one tick. The counter counts delivered timer interrupts: it is monotonic
/// within one boot, restarts at zero every boot, and under emulation may
/// run slow against host time.
pub fn boot_millis() -> u64 {
    // f = 3579545 / 3 Hz; ms = ticks * 1193 * 1000 / f.
    (u128::from(ticks()) * 1193 * 3000 / 3_579_545) as u64
}

/// This boot's 16-byte identity (`SYS_BOOT_ID`): drawn once per boot by the
/// kernel, the same for every process of the boot, different across boots.
/// The kernel refuses it (negative code) without a hardware source.
pub fn boot_id() -> Result<[u8; 16], i64> {
    let mut id = [0u8; 16];
    let result = unsafe { syscall3(SYS_BOOT_ID, id.as_mut_ptr() as u64, 0, 0) };
    if result < 0 { Err(result) } else { Ok(id) }
}

/// Seconds since the Unix epoch from the kernel's CMOS RTC reading
/// (`SYS_WALL_CLOCK`, kernel `src/rtc.rs`): whole seconds, the RTC declared
/// to hold UTC, no correction of any kind. The kernel refuses (negative
/// code) when the RTC gives no stable, valid calendar reading; a kernel
/// without the call refuses it as unknown.
pub fn wall_clock_seconds() -> Result<u64, i64> {
    let result = unsafe { syscall3(SYS_WALL_CLOCK, 0, 0, 0) };
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}

/// `std::time::SystemTime::now`: the RTC's seconds, or a negative kernel
/// refusal (std then panics rather than invent a time).
#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_wall_clock_seconds() -> i64 {
    match wall_clock_seconds() {
        Ok(seconds) => seconds as i64,
        Err(code) => code,
    }
}

/// The kernel frame allocator's counts at one instant (`SYS_FRAME_STATS`,
/// kernel `abi/src/syscall.rs` and `docs/TERMINOLOGY.md`): tracked physical
/// frames free and allocated (any owner, the caller's own included), the
/// allocation limit if one is set, and the frame size. The kernel reads
/// them with interrupts disabled on its one CPU, so they are one exact
/// state, not an estimate; it keeps no history or average of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameStats {
    pub free_frames: u64,
    pub allocated_frames: u64,
    /// `None` unless the kernel's own exhaustion test set a limit.
    pub allocation_limit: Option<u64>,
    pub frame_bytes: u64,
}

/// One instantaneous kernel dispatcher snapshot: occupied process slots
/// (including Created/terminal), live handle entries, live pipe/cell objects,
/// and tracked allocated physical 4 KiB frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceCensus {
    pub processes: u64,
    pub handles: u64,
    pub pipes: u64,
    pub cells: u64,
    pub frames: u64,
}

pub fn resource_census() -> Result<ResourceCensus, i64> {
    let mut bytes = [0u8; 40];
    let result = unsafe { syscall3(census_wire::SYSCALL_NUMBER, bytes.as_mut_ptr() as u64, 0, 0) };
    if result < 0 {
        return Err(result);
    }
    let [processes, handles, pipes, cells, frames] = census_wire::decode(bytes);
    Ok(ResourceCensus {
        processes,
        handles,
        pipes,
        cells,
        frames,
    })
}

/// Reads [`FrameStats`]. A kernel without the call refuses it (negative
/// code); no count is ever substituted.
pub fn frame_stats() -> Result<FrameStats, i64> {
    let mut record = [0u8; 32];
    let result = unsafe { syscall3(SYS_FRAME_STATS, record.as_mut_ptr() as u64, 0, 0) };
    if result < 0 {
        return Err(result);
    }
    let word = |index: usize| {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&record[index * 8..index * 8 + 8]);
        u64::from_le_bytes(raw)
    };
    Ok(FrameStats {
        free_frames: word(0),
        allocated_frames: word(1),
        allocation_limit: if word(2) == u64::MAX {
            None
        } else {
            Some(word(2))
        },
        frame_bytes: word(3),
    })
}

pub const RIGHT_READ: u64 = 1 << 2;
/// The kernel's write right on a handle (a pipe's writing end).
pub const RIGHT_WRITE: u64 = 1;

/// A new handle to the same object with a subset of the rights.
pub fn duplicate(handle: u64, rights: u64) -> Result<u64, i64> {
    let result = unsafe { syscall3(SYS_DUPLICATE, handle, rights, 0) };
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}

/// A timed read (`transfer`) of at most 256 bytes from a pipe handle: waits
/// at most `ticks` (at least one) for data. `Ok(0)` is end of stream; the
/// kernel's timeout is `Err(-110)`.
pub fn read_within(handle: u64, bytes: &mut [u8], ticks: u64) -> Result<usize, i64> {
    let length = bytes.len().min(MAX_TRANSFER) as u64;
    let record = [bytes.as_mut_ptr() as u64, length, ticks.max(1)];
    let result = unsafe { syscall3(SYS_TRANSFER, handle, record.as_ptr() as u64, 0) };
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// A timed write (`transfer`) of at most 256 bytes to a pipe handle: waits
/// at most `ticks` (at least one) for room; returns the bytes taken.
pub fn write_within(handle: u64, bytes: &[u8], ticks: u64) -> Result<usize, i64> {
    let length = bytes.len().min(MAX_TRANSFER) as u64;
    let record = [bytes.as_ptr() as u64, length, ticks.max(1)];
    let result = unsafe { syscall3(SYS_TRANSFER, handle, record.as_ptr() as u64, 1) };
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Whether init handed this process a liveness cell.
pub fn has_liveness() -> bool {
    LIVENESS.load(Ordering::Relaxed) != 0
}

/// Transitions the liveness cell once: the value is a counter, so every
/// beat moves the cell's version. A beat says only that the caller's loop
/// reached its top again; it proves nothing about the work being correct.
/// Init judges a cell left unchanged after readiness for its bound as a
/// fault of this service (kernel
/// `docs/service-lifecycle-20261008/LIVENESS.md`). Returns false, without
/// a system call, when there is no cell, and false when the transition
/// fails twice; it never exits, since a service must not stop because its
/// beat could not be recorded. A transition refused because the version
/// moved (some other writer) re-reads the cell and tries once more.
pub fn liveness_beat() -> bool {
    let cell = LIVENESS.load(Ordering::Relaxed);
    if cell == 0 {
        return false;
    }
    for _ in 0..2 {
        if !LIVENESS_KNOWN.load(Ordering::Relaxed) {
            let mut record = [0u64; 2];
            if unsafe { syscall3(SYS_CELL_READ, cell, record.as_mut_ptr() as u64, 0) } < 0 {
                return false;
            }
            LIVENESS_VERSION.store(record[0], Ordering::Relaxed);
            LIVENESS_VALUE.store(record[1], Ordering::Relaxed);
            LIVENESS_KNOWN.store(true, Ordering::Relaxed);
        }
        let version = LIVENESS_VERSION.load(Ordering::Relaxed);
        let value = LIVENESS_VALUE.load(Ordering::Relaxed).wrapping_add(1);
        let result = unsafe { syscall3(SYS_CELL_TRANSITION, cell, version, value) };
        if result >= 0 {
            LIVENESS_VERSION.store(result as u64, Ordering::Relaxed);
            LIVENESS_VALUE.store(value, Ordering::Relaxed);
            return true;
        }
        LIVENESS_KNOWN.store(false, Ordering::Relaxed);
    }
    false
}

/// Sleeps at least `ticks` full timer ticks (`sleep`); zero yields.
pub fn sleep_ticks(ticks: u64) {
    unsafe { syscall3(SYS_SLEEP, ticks, 0, 0) };
}

/// Closes a handle this process owns.
pub fn close(handle: u64) -> Result<(), i64> {
    let result = unsafe { syscall3(SYS_CLOSE, handle, 0, 0) };
    if result < 0 { Err(result) } else { Ok(()) }
}

/// This process's legacy input and fallback-console capabilities.
/// A protocol with separately named startup output uses `startup_stream_handles`.
pub fn standard_stream_handles() -> (u64, u64) {
    (INPUT.load(Ordering::Relaxed), OUTPUT.load(Ordering::Relaxed))
}

/// The input and output capabilities explicitly named by a startup record.
/// Missing roles refuse the pair; the diagnostic console is never substituted.
/// This observes existing handles without duplication; their rights and lifetime apply.
pub fn startup_stream_handles() -> Option<(u64, u64)> {
    let input = INPUT.load(Ordering::Relaxed);
    let output = STARTUP_OUTPUT.load(Ordering::Relaxed);
    if input == 0 || output == 0 {
        None
    } else {
        Some((input, output))
    }
}

/// The block device handle, for consumers that own regions directly.
pub fn block_handle() -> u64 {
    BLOCK.load(Ordering::Relaxed)
}

pub(crate) fn map(pages: u64) -> *mut u8 {
    let result = unsafe { syscall3(SYS_MAP, pages, 0, 0) };
    if result < 0 {
        return core::ptr::null_mut();
    }
    MAPPED_PAGES.fetch_add(pages, Ordering::Relaxed);
    result as *mut u8
}

// Only dedicated allocations call this, with their exact owned map range.
// Refusal is an allocator invariant failure: do not adjust accounting or
// reuse uncertain storage. The existing abort path exits without allocation.
pub(crate) fn unmap(address: *mut u8, pages: u64) {
    if !try_unmap(address, pages) {
        __absd_std_exit(101);
    }
}

// When a request for pages of its own finds no room in the window, the
// allocator calls this once for one free, page-aligned pooled run of at most
// 64 pages, already removed from the free list; a held block is never
// unmapped (allocator.rs, R16). Returns whether the kernel unmapped the
// range; on refusal nothing changed, accounting included.
pub(crate) fn try_unmap(address: *mut u8, pages: u64) -> bool {
    let result = unsafe { syscall3(SYS_UNMAP, address as u64, pages, 0) };
    if result != 0 {
        return false;
    }
    MAPPED_PAGES.fetch_sub(pages, Ordering::Relaxed);
    true
}

/// Diagnostic build only (`ABSD_HEAP_DIAG` set when the runtime is
/// compiled): one console line per heap growth, naming the allocation
/// that caused it, written without allocating. Never set for a qualified
/// build; the line is for attributing a mapped-page step.
pub(crate) fn heap_diag(size: usize, pages: usize) {
    heap_diag_line(b"HEAP MAP size=", size, pages);
}

/// Diagnostic build only: one line per free pooled run returned to the
/// window for a request of `size` bytes (R16), after the unmap.
pub(crate) fn heap_diag_pool_unmap(size: usize, pages: usize) {
    heap_diag_line(b"HEAP POOL UNMAP size=", size, pages);
}

fn heap_diag_line(label: &[u8], size: usize, pages: usize) {
    if option_env!("ABSD_HEAP_DIAG").is_none() {
        return;
    }
    let mut line = [0u8; 96];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        for &b in bytes {
            if at < line.len() {
                line[at] = b;
                at += 1;
            }
        }
    };
    let mut decimal = |mut value: u64, put: &mut dyn FnMut(&[u8])| {
        let mut digits = [0u8; 20];
        let mut n = digits.len();
        if value == 0 {
            n -= 1;
            digits[n] = b'0';
        }
        while value > 0 {
            n -= 1;
            digits[n] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        put(&digits[n..]);
    };
    put(label);
    decimal(size as u64, &mut put);
    put(b" pages=");
    decimal(pages as u64, &mut put);
    put(b" mapped=");
    decimal(MAPPED_PAGES.load(Ordering::Relaxed), &mut put);
    put(b"\n");
    let handle = OUTPUT.load(Ordering::Relaxed);
    if handle != 0 {
        unsafe { syscall3(SYS_WRITE, handle, line.as_ptr() as u64, at as u64) };
    }
}

/// Anonymous heap pages currently owned by the allocator. Dedicated pages
/// are returned on deallocation; free pooled pages stay owned until teardown,
/// except that when a request for pages of its own finds no room in the
/// window, one free, page-aligned pooled run of at most 64 pages is unmapped
/// and the request retried once (held blocks are never moved or unmapped).
/// This excludes the kernel page tables retained for the address space.
pub fn heap_mapped_pages() -> u64 {
    MAPPED_PAGES.load(Ordering::Relaxed)
}

/// Process-local reusable pooled storage in page-equivalents:
/// floor(sum(free-list byte lengths) / 4096), including free-node storage.
/// Not aligned reclaimable pages, a largest-fit guarantee or kernel frames.
/// The allocator lock is released before this returns; callers may then log.
/// Sampling separately from mapped pages/census is not an atomic snapshot.
pub fn heap_free_pooled_pages() -> u64 {
    ALLOCATOR.free_pooled_pages() as u64
}

/// The network interface calls (kernel `abi/src/nic.rs`, `docs/NETWORK.md`):
/// whole Ethernet frames through the NIC handle the startup record named.
/// Errors are the kernel's negative codes.
pub mod nic {
    use super::{NIC, Ordering, syscall3};

    /// Largest frame the ABI carries (header included, no FCS).
    pub const FRAME_MAX: usize = 1514;
    pub const FRAME_MIN: usize = 14;
    pub const INFO_BYTES: usize = 64;
    pub const ERROR_AGAIN: i64 = -11;
    pub const ERROR_TIMEOUT: i64 = -110;
    /// `send` only: no carrier, the frame was not reported done; the NIC is
    /// not disabled (kernel `abi/src/syscall.rs` `ERROR_NO_CARRIER`).
    pub const ERROR_NO_CARRIER: i64 = -100;
    pub const FLAG_LINK_UP: u16 = 1;
    pub const FLAG_DISABLED: u16 = 2;

    /// This process's NIC handle; zero when it was given none.
    pub fn handle() -> u64 {
        NIC.load(Ordering::Relaxed)
    }

    /// `nic_info`: the raw 64-byte record (MAC, flags, six counters).
    pub fn info(handle: u64) -> Result<[u8; INFO_BYTES], i64> {
        let mut record = [0u8; INFO_BYTES];
        let result =
            unsafe { syscall3(super::SYS_NIC_INFO, handle, record.as_mut_ptr() as u64, 0) };
        if result < 0 { Err(result) } else { Ok(record) }
    }

    /// `nic_send`: one frame of `FRAME_MIN..=FRAME_MAX` bytes. `Err(ERROR_NO_CARRIER)`
    /// when the link has no carrier (the NIC stays enabled).
    pub fn send(handle: u64, frame: &[u8]) -> Result<(), i64> {
        let result = unsafe {
            syscall3(
                super::SYS_NIC_SEND,
                handle,
                frame.as_ptr() as u64,
                frame.len() as u64,
            )
        };
        if result < 0 { Err(result) } else { Ok(()) }
    }

    /// `nic_receive`: the next accepted frame's length. `timeout` 0 polls
    /// (`ERROR_AGAIN` when none is waiting); otherwise at most that many
    /// ticks (`ERROR_TIMEOUT`).
    pub fn receive(handle: u64, buffer: &mut [u8; FRAME_MAX], timeout: u64) -> Result<usize, i64> {
        let result = unsafe {
            syscall3(
                super::SYS_NIC_RECEIVE,
                handle,
                buffer.as_mut_ptr() as u64,
                timeout,
            )
        };
        if result < 0 {
            Err(result)
        } else {
            Ok(result as usize)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_alloc(size: usize, align: usize) -> *mut u8 {
    let Ok(layout) = Layout::from_size_align(size, align) else {
        return core::ptr::null_mut();
    };
    unsafe { GlobalAlloc::alloc(&ALLOCATOR, layout) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_dealloc(ptr: *mut u8, size: usize, align: usize) {
    if let Ok(layout) = Layout::from_size_align(size, align) {
        unsafe { GlobalAlloc::dealloc(&ALLOCATOR, ptr, layout) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_realloc(
    ptr: *mut u8,
    old_size: usize,
    align: usize,
    new_size: usize,
) -> *mut u8 {
    let Ok(layout) = Layout::from_size_align(old_size, align) else {
        return core::ptr::null_mut();
    };
    unsafe { GlobalAlloc::realloc(&ALLOCATOR, ptr, layout, new_size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_read(bytes: *mut u8, length: usize) -> isize {
    if length == 0 {
        return 0;
    }
    let handle = INPUT.load(Ordering::Relaxed);
    if handle == 0 {
        return 0;
    }
    unsafe {
        syscall3(
            SYS_READ,
            handle,
            bytes as u64,
            length.min(MAX_TRANSFER) as u64,
        ) as isize
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_write(bytes: *const u8, length: usize) -> isize {
    if length == 0 {
        return 0;
    }
    let handle = OUTPUT.load(Ordering::Relaxed);
    if handle == 0 {
        return -1;
    }
    unsafe {
        syscall3(
            SYS_WRITE,
            handle,
            bytes as u64,
            length.min(MAX_TRANSFER) as u64,
        ) as isize
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_stderr_write(bytes: *const u8, length: usize) -> isize {
    if length == 0 {
        return 0;
    }
    let handle = match ERROR.load(Ordering::Relaxed) {
        0 => OUTPUT.load(Ordering::Relaxed),
        handle => handle,
    };
    if handle == 0 {
        return -1;
    }
    unsafe {
        syscall3(
            SYS_WRITE,
            handle,
            bytes as u64,
            length.min(MAX_TRANSFER) as u64,
        ) as isize
    }
}

/// `std::process::id`: the kernel's PID for this process.
#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_getpid() -> u32 {
    unsafe { syscall3(SYS_GETPID, 0, 0, 0) as u32 }
}

#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_exit(code: i32) -> ! {
    unsafe {
        syscall3(SYS_EXIT, code as i64 as u64, 0, 0);
    }
    loop {
        unsafe {
            asm!("ud2", options(nomem, nostack));
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __absd_start(console: u64, handles: *const u64, count: usize) -> ! {
    require_kernel_abi(console);
    // Two handles is the ordinary external boot: input pipe, console. Four
    // is a durable boot: input pipe, block device, step cell, console. Five
    // or more carry a startup record on handles[0] naming the rest.
    if (count != 2 && count != 4 && count < absd_broker::MIN_RECORD_HANDLES)
        || handles.is_null()
        || !(handles as usize).is_multiple_of(core::mem::align_of::<u64>())
    {
        __absd_std_exit(102);
    }
    let handles = unsafe { core::slice::from_raw_parts(handles, count) };
    if handles[count - 1] != console {
        __absd_std_exit(102);
    }
    OUTPUT.store(console, Ordering::Relaxed);
    INPUT.store(handles[0], Ordering::Relaxed);
    if count == 4 {
        BLOCK.store(handles[1], Ordering::Relaxed);
        STEP.store(read_step(handles[2]), Ordering::Relaxed);
    }
    // ABSD has no exec: without a startup record's arguments a program image
    // carries the arguments its deployment gives it, fixed when it is built
    // (`ABSD_PROGRAM_ARGS`, whitespace-separated), after its name
    // (`ABSD_PROGRAM_NAME`, else `absd-std-probe`), which roles such as
    // Pulse's select on.
    let name = option_env!("ABSD_PROGRAM_NAME").unwrap_or("absd-std-probe");
    let mut name = name.as_bytes().to_vec();
    let mut words: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    let mut named = false;
    if count >= absd_broker::MIN_RECORD_HANDLES {
        // A parent that started this image from a file names it (argv[0]),
        // and its argv is then exactly the record's, even when empty.
        if let Some(given) = start_from_record(handles, &mut words) {
            name = given;
            named = true;
        }
    }
    name.push(0);
    // A startup record with arguments replaces the build-time arguments;
    // the name stays the build-time one unless the record names it.
    if words.is_empty()
        && !named
        && let Some(arguments) = option_env!("ABSD_PROGRAM_ARGS")
    {
        for word in arguments.split_ascii_whitespace() {
            let mut bytes = word.as_bytes().to_vec();
            bytes.push(0);
            words.push(bytes);
        }
    }
    let mut argv: alloc::vec::Vec<*const u8> = alloc::vec::Vec::with_capacity(words.len() + 2);
    argv.push(name.as_ptr());
    argv.extend(words.iter().map(|word| word.as_ptr()));
    argv.push(core::ptr::null());
    // A client of a file server asks it who it is before anything else
    // (`docs/RELEASE.md` section 3, item 5); a server of another protocol,
    // or none that answers, refuses the process (status 104).
    if fsd::active() {
        fsd::require_server(0, false);
    }
    #[cfg(not(feature = "c-entry"))]
    let status = unsafe { main(argv.len() as isize - 1, argv.as_ptr()) };
    #[cfg(feature = "c-entry")]
    let status = c_entry(&argv);
    __absd_std_exit(status as i32)
}

fn read_step(cell: u64) -> u64 {
    let mut record = [0u64; 2];
    if unsafe { syscall3(SYS_CELL_READ, cell, record.as_mut_ptr() as u64, 0) } < 0 {
        __absd_std_exit(102);
    }
    record[1]
}

/// The record shape: everything on `handles[0]` until end-of-file is the
/// startup record (kernel `docs/BROKER.md`). Any read failure, an oversized
/// or malformed record, or a vector that does not match it exits 102.
fn start_from_record(
    handles: &[u64],
    words: &mut alloc::vec::Vec<alloc::vec::Vec<u8>>,
) -> Option<alloc::vec::Vec<u8>> {
    let mut record = alloc::vec::Vec::new();
    let mut chunk = [0u8; MAX_TRANSFER];
    loop {
        let count = unsafe {
            syscall3(
                SYS_READ,
                handles[0],
                chunk.as_mut_ptr() as u64,
                MAX_TRANSFER as u64,
            )
        };
        if count < 0 || record.len() + count as usize > absd_broker::MAX_STARTUP {
            __absd_std_exit(102);
        }
        if count == 0 {
            break;
        }
        record.extend_from_slice(&chunk[..count as usize]);
    }
    unsafe { syscall3(SYS_CLOSE, handles[0], 0, 0) };
    // The environment is read for the life of the process.
    let record: &'static [u8] = record.leak();
    let Ok(startup) = absd_broker::parse_startup(record, handles.len()) else {
        __absd_std_exit(102);
    };
    let handle = |index: Option<usize>| index.map_or(0, |index| handles[index]);
    INPUT.store(handle(startup.stdin), Ordering::Relaxed);
    STARTUP_OUTPUT.store(handle(startup.stdout), Ordering::Relaxed);
    ERROR.store(handle(startup.stderr), Ordering::Relaxed);
    BLOCK.store(handle(startup.block), Ordering::Relaxed);
    if let Some(view) = startup.fs {
        // A child started from a filesystem image: its view of the
        // filesystem is read-only, mounted before `main`. A failed mount
        // leaves it without one (std::fs then reports not-found).
        BLOCK.store(handles[view], Ordering::Relaxed);
        let _ = storage::mount_view(handles[view]);
    }
    if !startup.cwd.is_empty() {
        cwd::set(startup.cwd.to_vec());
    }
    NIC.store(handle(startup.nic), Ordering::Relaxed);
    MACHINE.store(handle(startup.machine), Ordering::Relaxed);
    if let (Some(events), Some(requests)) = (startup.session_events, startup.session_requests) {
        session::install(handles[events], handles[requests]);
    }
    if let Some(step) = startup.step {
        STEP.store(read_step(handles[step]), Ordering::Relaxed);
    }
    if let Some(liveness) = startup.liveness {
        LIVENESS.store(handles[liveness], Ordering::Relaxed);
    }
    if let (Some(request), Some(reply)) = (startup.request, startup.reply) {
        let mut slots = [[0u64; 3]; absd_broker::MAX_SLOTS];
        for (slot, ends) in slots.iter_mut().zip(&startup.slots[..startup.slot_count]) {
            *slot = [
                handles[ends.stdin],
                handles[ends.stdout],
                handles[ends.stderr],
            ];
        }
        broker::install(
            handles[request],
            handles[reply],
            &slots[..startup.slot_count],
        );
    }
    if startup.channel_count > 0 && startup.block.is_none() {
        // A client of a file server: std::fs goes through its channel.
        // (The server itself holds the block handle and serves its ends.)
        let channels: alloc::vec::Vec<(u64, u64)> = startup.channels[..startup.channel_count]
            .iter()
            .map(|ends| (handles[ends.request], handles[ends.reply]))
            .collect();
        fsd::install(&channels);
    } else if startup.channel_count > 0 {
        let channels: alloc::vec::Vec<(u64, u64)> = startup.channels[..startup.channel_count]
            .iter()
            .map(|ends| (handles[ends.request], handles[ends.reply]))
            .collect();
        server::install(channels);
    }
    if startup.envc > 0 {
        let entries: alloc::vec::Vec<[usize; 2]> = startup
            .env()
            .map(|entry| [entry.as_ptr() as usize, entry.len()])
            .collect();
        let entries: &'static [[usize; 2]] = entries.leak();
        ENVIRONMENT.store(entries.as_ptr() as u64, Ordering::Relaxed);
        ENVIRONMENT_COUNT.store(entries.len() as u64, Ordering::Relaxed);
    }
    for argument in startup.args() {
        let mut bytes = argument.to_vec();
        bytes.push(0);
        words.push(bytes);
    }
    (!startup.name.is_empty()).then(|| startup.name.to_vec())
}

// Validate the machine-level startup contract before a Rust prologue can
// obscure it. The failure path uses the syscall ABI directly so it remains
// usable even when the incoming stack is malformed.
global_asm!(
    ".globl _start",
    "_start:",
    "  test rsp, 15",
    "  jnz 2f",
    "  pushfq",
    "  pop rax",
    "  test rax, 0x400",
    "  jnz 2f",
    "  test rax, 0x200",
    "  jz 2f",
    "  call __absd_start",
    "  ud2",
    "2:",
    "  mov eax, 3",
    "  mov edi, 103",
    "  xor esi, esi",
    "  xor edx, edx",
    "  int 0x80",
    "  ud2",
);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(destination: *mut u8, source: *const u8, count: usize) -> *mut u8 {
    for index in 0..count {
        unsafe { destination.add(index).write(source.add(index).read()) };
    }
    destination
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(destination: *mut u8, source: *const u8, count: usize) -> *mut u8 {
    if (destination as usize) <= (source as usize) {
        unsafe { memcpy(destination, source, count) };
    } else {
        for index in (0..count).rev() {
            unsafe { destination.add(index).write(source.add(index).read()) };
        }
    }
    destination
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(destination: *mut u8, value: i32, count: usize) -> *mut u8 {
    for index in 0..count {
        unsafe { destination.add(index).write(value as u8) };
    }
    destination
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
    for index in 0..count {
        let left = unsafe { left.add(index).read() };
        let right = unsafe { right.add(index).read() };
        if left != right {
            return left as i32 - right as i32;
        }
    }
    0
}

// The program entry `__absd_start` calls last. These sit at the end of the
// file so that the `c-entry` feature moves no line above them: a Rust
// executable's panic locations, and so its bytes, stay what they were.
#[cfg(not(feature = "c-entry"))]
unsafe extern "C" {
    fn main(argc: isize, argv: *const *const u8) -> isize;
}

/// A C program's `main(argc, argv, envp)`: the environment as NUL-terminated
/// `KEY=VALUE` strings behind a NULL-terminated vector, built once and leaked
/// like argv. The C entry owns exit: it returns only if the program's `main`
/// returned without calling `exit`, and then its value is the status.
#[cfg(feature = "c-entry")]
fn c_entry(argv: &[*const u8]) -> i32 {
    let mut count = 0usize;
    let entries = unsafe { __absd_std_environ(&mut count) };
    let mut strings: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::with_capacity(count);
    for index in 0..count {
        let [pointer, length] = unsafe { entries.add(index).read() };
        let mut bytes = unsafe { core::slice::from_raw_parts(pointer as *const u8, length) }.to_vec();
        bytes.push(0);
        strings.push(bytes);
    }
    let mut envp: alloc::vec::Vec<*const u8> = alloc::vec::Vec::with_capacity(count + 1);
    envp.extend(strings.iter().map(|entry| entry.as_ptr()));
    envp.push(core::ptr::null());
    // Leaked, not dropped: the strings and the vector outlive the call
    // (a C program may keep `environ` pointers until it exits).
    core::mem::forget(strings);
    let envp = envp.leak();
    unsafe extern "C" {
        fn __absd_program_main(argc: isize, argv: *const *const u8, envp: *const *const u8) -> i32;
    }
    unsafe { __absd_program_main(argv.len() as isize - 1, argv.as_ptr(), envp.as_ptr()) }
}
