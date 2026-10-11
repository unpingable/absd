//! Freestanding ABSD userspace support: the `int 0x80` wrappers, the process
//! entry convention, and the runtime shims a `no_std` binary needs.
//!
//! Programs are ordinary Rust binaries built for the host target with a
//! static, non-PIE link (see `scripts/build-user.sh`). They may use SSE
//! freely; the kernel preserves x87/XMM state across every switch.
#![no_std]

mod allocator;
pub mod broker;
pub mod ledger;
pub mod semantic_trace;

pub use allocator::MapAllocator;

#[cfg(not(test))]
use core::ffi::c_void;

pub use absd_abi::program;
pub use absd_abi::syscall::Outcome;
pub use absd_abi::syscall::PipeInfo;
use absd_abi::syscall::{
    BLOCK_INFO_BYTES, ERROR_IO, ERROR_NOT_EXECUTABLE, PIPE_INFO_BYTES, SPAWN_IMAGE_REQUEST_BYTES,
    SYS_BLOCK_FLUSH, SYS_BLOCK_INFO, SYS_BLOCK_READ, SYS_BLOCK_READ_MANY, SYS_BLOCK_WRITE,
    SYS_BLOCK_WRITE_MANY, SYS_MACHINE_RECOVER, SYS_MACHINE_RESTART, SYS_MACHINE_STOP,
    SYS_PIPE_INFO, SYS_SPAWN_IMAGE, SpawnImageRequest,
};
pub use absd_abi::syscall::{BLOCK_MAX_TRANSFER_SECTORS, BlockTransfer};
pub use absd_abi::syscall::{
    BLOCK_SECTOR_BYTES, MACHINE_RIGHT_RECOVER, MACHINE_RIGHT_RESTART, MACHINE_RIGHT_STOP,
    STOP_CODE_MAX, STOP_CODE_MIN,
};
use absd_abi::syscall::{
    ERROR_AGAIN, ERROR_BAD_HANDLE, ERROR_FAULT, ERROR_INVALID, ERROR_NO_CHILD, ERROR_NO_MEMORY,
    ERROR_NOT_FOUND, ERROR_NOT_IMPLEMENTED, ERROR_PID_EXHAUSTED, ERROR_PIPE, ERROR_RIGHTS,
    ERROR_STALE, ERROR_TIMEOUT, ERROR_TOO_MANY_HANDLES, RESOURCE_CENSUS_BYTES, SYS_CELL_CREATE,
    SYS_CELL_READ, SYS_CELL_TRANSITION, SYS_CELL_WAIT, SYS_CLOSE, SYS_DUPLICATE, SYS_EXIT,
    SYS_GETPID, SYS_INFO, SYS_KILL, SYS_MAP, SYS_PIPE_CREATE, SYS_READ, SYS_RESOURCE_CENSUS,
    SYS_SLEEP, SYS_SPAWN, SYS_SPAWN_MANY_COPY, SYS_TIME, SYS_TRANSFER, SYS_UNMAP, SYS_WAIT,
    SYS_WRITE, SYS_YIELD, TRANSFER_READ, TRANSFER_WRITE,
};
pub use absd_abi::syscall::{
    INFO_STATE_LIVE, INFO_STATE_TERMINAL, INFO_STATE_WAITING, ProcessInfo, SPAWN_CONSOLE,
};
pub use absd_abi::syscall::{
    MAX_SPAWN_HANDLES, RIGHT_KILL, RIGHT_READ, RIGHT_WAIT, RIGHT_WRITE, SPAWN_HANDLE_COPY_CONSOLE,
    SpawnHandleCopy,
};
pub use absd_abi::syscall::{MAX_SPAWN_IMAGE_BYTES, SPAWN_NO_SPAWN};

pub use absd_abi::nic::{NIC_FRAME_MAX, NIC_FRAME_MIN, NicInfo};

/// A handle to the network interface (`absd_abi::nic`): whole Ethernet
/// frames. Read right receives, write right sends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nic(u64);

impl Nic {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub fn info(self) -> Result<NicInfo, Error> {
        let mut bytes = [0u8; absd_abi::nic::NIC_INFO_BYTES];
        result(unsafe {
            syscall3(
                absd_abi::nic::SYS_NIC_INFO,
                self.0,
                bytes.as_mut_ptr() as u64,
                0,
            )
        })?;
        Ok(NicInfo::from_bytes(&bytes))
    }

    /// Sends one frame; the kernel refuses a length outside
    /// `NIC_FRAME_MIN..=NIC_FRAME_MAX` before anything reaches the device.
    pub fn send(self, frame: &[u8]) -> Result<(), Error> {
        self.send_raw(frame.as_ptr() as u64, frame.len() as u64)
            .map(|_| ())
    }

    /// Unchecked `nic_send` for negative controls.
    pub fn send_raw(self, address: u64, length: u64) -> Result<u64, Error> {
        result(unsafe { syscall3(absd_abi::nic::SYS_NIC_SEND, self.0, address, length) })
    }

    /// The next accepted frame, its length returned. `timeout` 0 polls
    /// (`Error::Again` when nothing is waiting); otherwise at most that many
    /// ticks (`Error::Timeout`).
    pub fn receive(self, buffer: &mut [u8; NIC_FRAME_MAX], timeout: u64) -> Result<usize, Error> {
        self.receive_raw(buffer.as_mut_ptr() as u64, timeout)
            .map(|length| length as usize)
    }

    /// Unchecked `nic_receive` for negative controls.
    pub fn receive_raw(self, address: u64, timeout: u64) -> Result<u64, Error> {
        result(unsafe { syscall3(absd_abi::nic::SYS_NIC_RECEIVE, self.0, address, timeout) })
    }
}

/// Largest single `write` the kernel accepts.
pub const MAX_WRITE: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Rights,
    NotFound,
    /// The block device failed or did not answer.
    Io,
    BadHandle,
    NoChild,
    Again,
    NoMemory,
    Fault,
    Invalid,
    TooManyHandles,
    NotImplemented,
    /// The kernel has no representable PID left, despite having a free slot.
    PidExhausted,
    /// The object moved past the version a conditional transition expected.
    Stale,
    /// No reader is left on the pipe being written.
    BrokenPipe,
    /// A timed wait ended before the awaited event.
    Timeout,
    /// `spawn_image` refused the image: not a static ELF64 the loader takes.
    NotExecutable,
    Unknown(i64),
}

impl Error {
    /// Explicit syscall error number, suitable for fixed-width evidence.
    pub const fn code(self) -> i64 {
        match self {
            Self::Rights => ERROR_RIGHTS,
            Self::NotFound => ERROR_NOT_FOUND,
            Self::Io => ERROR_IO,
            Self::BadHandle => ERROR_BAD_HANDLE,
            Self::NoChild => ERROR_NO_CHILD,
            Self::Again => ERROR_AGAIN,
            Self::NoMemory => ERROR_NO_MEMORY,
            Self::Fault => ERROR_FAULT,
            Self::Invalid => ERROR_INVALID,
            Self::TooManyHandles => ERROR_TOO_MANY_HANDLES,
            Self::NotImplemented => ERROR_NOT_IMPLEMENTED,
            Self::PidExhausted => ERROR_PID_EXHAUSTED,
            Self::Stale => ERROR_STALE,
            Self::BrokenPipe => ERROR_PIPE,
            Self::Timeout => ERROR_TIMEOUT,
            Self::NotExecutable => ERROR_NOT_EXECUTABLE,
            Self::Unknown(code) => code,
        }
    }
    pub const fn from_code(code: i64) -> Self {
        match code {
            ERROR_RIGHTS => Self::Rights,
            ERROR_NOT_FOUND => Self::NotFound,
            ERROR_IO => Self::Io,
            ERROR_BAD_HANDLE => Self::BadHandle,
            ERROR_NO_CHILD => Self::NoChild,
            ERROR_AGAIN => Self::Again,
            ERROR_NO_MEMORY => Self::NoMemory,
            ERROR_FAULT => Self::Fault,
            ERROR_INVALID => Self::Invalid,
            ERROR_TOO_MANY_HANDLES => Self::TooManyHandles,
            ERROR_NOT_IMPLEMENTED => Self::NotImplemented,
            ERROR_PID_EXHAUSTED => Self::PidExhausted,
            ERROR_STALE => Self::Stale,
            ERROR_PIPE => Self::BrokenPipe,
            ERROR_TIMEOUT => Self::Timeout,
            ERROR_NOT_EXECUTABLE => Self::NotExecutable,
            other => Self::Unknown(other),
        }
    }
}

fn result(raw: i64) -> Result<u64, Error> {
    if raw < 0 {
        Err(Error::from_code(raw))
    } else {
        Ok(raw as u64)
    }
}

/// Raw `int 0x80`. The kernel returns its result in `RAX` and preserves
/// every other register.
///
/// # Safety
///
/// `a0..a2` must be valid for the requested syscall; pointer arguments must
/// stay valid until the call returns.
pub unsafe fn syscall3(number: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    unsafe { arch::syscall3(number, a0, a1, a2) }
}
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
mod arch;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64.rs"]
mod arch;

/// Handle to the process-local console object, handed to a program in
/// `RDI` at entry. Handles are opaque values that only the owning process's
/// table can resolve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Console(u64);

/// What a program receives at entry: its console handle, the handle its
/// parent chose to hand over (zero for none), and one argument word.
/// `nic` is nonzero only for init in a boot that probed a NIC: the kernel's
/// grant of the NIC handle, in `RCX`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Start {
    pub console: Console,
    pub handle: u64,
    pub arg: u64,
    pub nic: u64,
    /// The machine handle (stop and restart rights): the kernel gives one
    /// to init in every boot and to no other process.
    pub machine: u64,
}

/// Entry state for a program started by `spawn_many_copy`. Handles appear in
/// exactly the same order as the parent's copy records. A console-replacement
/// record is included in this slice as well as being installed in `console`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiStart<'a> {
    pub console: Console,
    pub handles: &'a [u64],
}

/// Handle to a child process, returned with wait and kill rights and consumed
/// by `wait`. Local duplicates may narrow those rights independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Child(u64);

impl Child {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl Console {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
    /// One bounded kernel `write`; at most `MAX_WRITE` bytes.
    pub fn write_once(self, bytes: &[u8]) -> Result<usize, Error> {
        let length = bytes.len().min(MAX_WRITE) as u64;
        let raw = unsafe { syscall3(SYS_WRITE, self.0, bytes.as_ptr() as u64, length) };
        result(raw).map(|written| written as usize)
    }
    /// Writes all of `bytes` in `MAX_WRITE` chunks.
    /// Writes all of `bytes`. A console backed by a pipe may take only
    /// part of a chunk when the pipe is nearly full, so advance by what was
    /// actually written.
    pub fn write_all(self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            let written = self.write_once(bytes)?;
            if written == 0 {
                return Err(Error::Invalid);
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }
    pub fn write_str(self, text: &str) -> Result<(), Error> {
        self.write_all(text.as_bytes())
    }
    /// One kernel `read` of console input: blocks until at least one byte
    /// has arrived, then returns up to `MAX_WRITE` bytes.
    pub fn read_once(self, buffer: &mut [u8]) -> Result<usize, Error> {
        let length = buffer.len().min(MAX_WRITE) as u64;
        let raw = unsafe { syscall3(SYS_READ, self.0, buffer.as_mut_ptr() as u64, length) };
        result(raw).map(|count| count as usize)
    }
    /// `read_once` that gives up with `Error::Timeout` after `ticks`.
    pub fn read_timeout(self, buffer: &mut [u8], ticks: u64) -> Result<usize, Error> {
        transfer(
            self.0,
            TRANSFER_READ,
            buffer.as_mut_ptr(),
            buffer.len(),
            ticks,
        )
    }
}

impl core::fmt::Write for Console {
    /// Each piece of a formatted message becomes its own `write`; use
    /// `Console::line` when the message must not interleave with another
    /// process's output.
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        Console::write_str(*self, text).map_err(|_| core::fmt::Error)
    }
}

/// Formats into a fixed buffer so a whole line can go out in one `write`.
pub struct LineBuffer {
    bytes: [u8; MAX_WRITE],
    length: usize,
}

impl LineBuffer {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_WRITE],
            length: 0,
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

impl Default for LineBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Write for LineBuffer {
    /// Text beyond the buffer is dropped rather than split across writes.
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let room = MAX_WRITE - self.length;
        let take = text.len().min(room);
        self.bytes[self.length..self.length + take].copy_from_slice(&text.as_bytes()[..take]);
        self.length += take;
        Ok(())
    }
}

impl Console {
    /// Writes one formatted message with a single kernel `write`, so no
    /// other process's output can land in the middle of it.
    pub fn line(self, arguments: core::fmt::Arguments<'_>) -> Result<(), Error> {
        let mut buffer = LineBuffer::new();
        let _ = core::fmt::Write::write_fmt(&mut buffer, arguments);
        self.write_all(buffer.as_bytes())
    }
}

/// `println!` for a console: one formatted line, one kernel `write`.
#[macro_export]
macro_rules! cprintln {
    ($console:expr, $($arg:tt)*) => {
        $console.line(format_args!("{}\n", format_args!($($arg)*)))
    };
}

pub fn yield_now() {
    unsafe {
        syscall3(SYS_YIELD, 0, 0, 0);
    }
}

pub fn exit(status: i32) -> ! {
    unsafe {
        syscall3(SYS_EXIT, status as i64 as u64, 0, 0);
    }
    // The kernel never resumes an exited process.
    loop {
        arch::halt_after_exit();
    }
}

pub fn getpid() -> u64 {
    unsafe { syscall3(SYS_GETPID, 0, 0, 0) as u64 }
}

/// A `read` (`TRANSFER_READ`) or `write` (`TRANSFER_WRITE`) of at most
/// `MAX_WRITE` bytes that gives up with `Error::Timeout` after `ticks`
/// (zero: never).
pub fn transfer(
    handle: u64,
    direction: u64,
    bytes: *mut u8,
    length: usize,
    ticks: u64,
) -> Result<usize, Error> {
    let record = [bytes as u64, length.min(MAX_WRITE) as u64, ticks];
    let raw = unsafe { syscall3(SYS_TRANSFER, handle, record.as_ptr() as u64, direction) };
    result(raw).map(|count| count as usize)
}

/// Ends a child now, wherever it is blocked; `wait` then reports `Killed`.
pub fn kill(child: Child) -> Result<(), Error> {
    result(unsafe { syscall3(SYS_KILL, child.raw(), 0, 0) }).map(|_| ())
}

/// Metadata about this process (`None`) or a child by handle.
pub fn info(target: Option<Child>) -> Result<ProcessInfo, Error> {
    let mut record = [0u64; 4];
    let raw = unsafe {
        syscall3(
            SYS_INFO,
            target.map_or(0, Child::raw),
            record.as_mut_ptr() as u64,
            0,
        )
    };
    result(raw)?;
    Ok(ProcessInfo::from_words(record))
}

/// Ticks of the kernel's ~1 kHz timer since boot.
pub fn time() -> u64 {
    unsafe { syscall3(SYS_TIME, 0, 0, 0) as u64 }
}

/// Blocks for at least `ticks` timer ticks; zero just yields.
pub fn sleep(ticks: u64) {
    unsafe {
        syscall3(SYS_SLEEP, ticks, 0, 0);
    }
}

/// Finish this RT instance. Ordinary tasks receive Invalid; this never admits.
pub fn rt_next() -> Result<(), Error> {
    result(unsafe { syscall3(absd_abi::syscall::SYS_RT_NEXT, 0, 0, 0) }).map(|_| ())
}

/// Starts one of the catalog programs as a child of this process and
/// returns a handle that can wait for it.
pub fn spawn(program: u64) -> Result<Child, Error> {
    spawn_with(program, 0, 0)
}

/// `spawn`, also handing the child a duplicate of `handle` (zero for none)
/// and the word `arg`, which it receives in `Start`.
pub fn spawn_with(program: u64, handle: u64, arg: u64) -> Result<Child, Error> {
    result(unsafe { syscall3(SYS_SPAWN, program, handle, arg) }).map(Child)
}

/// `spawn` with the child's console replaced by `console`, a writable pipe
/// or console handle, so everything the child writes flows into it.
pub fn spawn_captured(program: u64, console: u64, arg: u64) -> Result<Child, Error> {
    spawn_with(program | SPAWN_CONSOLE, console, arg)
}

/// Starts a child while explicitly copying an ordered array of narrowed
/// handles. Sources remain live in the parent. Duplicate sources create
/// distinct child handles. Programs use `multi_entry!` to receive the array.
pub fn spawn_many_copy(program: u64, copies: &[SpawnHandleCopy]) -> Result<Child, Error> {
    result(unsafe {
        syscall3(
            SYS_SPAWN_MANY_COPY,
            program,
            copies.as_ptr() as u64,
            copies.len() as u64,
        )
    })
    .map(Child)
}

/// Starts a multi-start child from a static ELF64 image in this process's
/// memory (`spawn_image`), with the same ordered handle copies as
/// `spawn_many_copy`. `flags` may carry only `SPAWN_NO_SPAWN`.
pub fn spawn_image(image: &[u8], copies: &[SpawnHandleCopy], flags: u64) -> Result<Child, Error> {
    let request = SpawnImageRequest {
        image: image.as_ptr() as u64,
        image_bytes: image.len() as u64,
        handles: copies.as_ptr() as u64,
        handle_count: copies.len() as u64,
    };
    spawn_image_raw(&request as *const SpawnImageRequest as u64, flags, 0)
}

/// Raw `spawn_image` for pointer, flag, and bound negative controls.
pub fn spawn_image_raw(request: u64, flags: u64, reserved: u64) -> Result<Child, Error> {
    const _: () = assert!(core::mem::size_of::<SpawnImageRequest>() == SPAWN_IMAGE_REQUEST_BYTES);
    result(unsafe { syscall3(SYS_SPAWN_IMAGE, request, flags, reserved) }).map(Child)
}

/// Raw `spawn_many_copy` for pointer/count negative controls.
pub fn spawn_many_copy_raw(program: u64, records: u64, count: u64) -> Result<Child, Error> {
    result(unsafe { syscall3(SYS_SPAWN_MANY_COPY, program, records, count) }).map(Child)
}

/// The identity and outcome returned by an identified wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitResult {
    pub pid: u64,
    pub outcome: Outcome,
}

/// Blocks until `target` (or, for `None`, any child) terminates and reaps it.
/// The child's handle is closed by the kernel as part of reaping. This legacy
/// wrapper discards the returned PID; use `wait_any` to learn which child was reaped.
pub fn wait(target: Option<Child>) -> Result<Outcome, Error> {
    wait_timeout(target, 0)
}

/// `wait` that gives up with `Error::Timeout` after `ticks` (zero: never).
pub fn wait_timeout(target: Option<Child>, ticks: u64) -> Result<Outcome, Error> {
    wait_identified_timeout(target, ticks).map(|result| result.outcome)
}

/// Identified wait for a target or any child. On success, the returned PID is
/// the exact child whose unchanged 32-byte outcome record was delivered.
pub fn wait_identified_timeout(target: Option<Child>, ticks: u64) -> Result<WaitResult, Error> {
    let mut record = [0u64; 4];
    let raw = unsafe {
        syscall3(
            SYS_WAIT,
            target.map_or(0, Child::raw),
            record.as_mut_ptr() as u64,
            ticks,
        )
    };
    let pid = result(raw)?;
    let outcome = Outcome::from_words(record).ok_or(Error::Invalid)?;
    Ok(WaitResult { pid, outcome })
}

/// Reaps any child and reports its identity as well as its outcome.
pub fn wait_any() -> Result<WaitResult, Error> {
    wait_any_timeout(0)
}

/// Timed identified wait for any child.
pub fn wait_any_timeout(ticks: u64) -> Result<WaitResult, Error> {
    wait_identified_timeout(None, ticks)
}

/// Handle to a versioned kernel cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cell(u64);

impl Cell {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
    /// A new cell at version 0 holding `value`.
    pub fn create(value: u64) -> Result<Self, Error> {
        result(unsafe { syscall3(SYS_CELL_CREATE, value, 0, 0) }).map(Self)
    }
    /// Current `(version, value)`.
    pub fn read(self) -> Result<(u64, u64), Error> {
        let mut record = [0u64; 2];
        result(unsafe { syscall3(SYS_CELL_READ, self.0, record.as_mut_ptr() as u64, 0) })?;
        Ok((record[0], record[1]))
    }
    /// Stores `value` only if the cell is still at `expected`; returns the
    /// new version, or `Error::Stale` having changed nothing.
    pub fn transition(self, expected: u64, value: u64) -> Result<u64, Error> {
        result(unsafe { syscall3(SYS_CELL_TRANSITION, self.0, expected, value) })
    }
    /// Returns the version once it differs from `seen`, blocking until a
    /// transition moves it if necessary.
    pub fn wait_change(self, seen: u64) -> Result<u64, Error> {
        self.wait_change_timeout(seen, 0)
    }
    /// `wait_change` that gives up with `Error::Timeout` after `ticks`.
    pub fn wait_change_timeout(self, seen: u64, ticks: u64) -> Result<u64, Error> {
        result(unsafe { syscall3(SYS_CELL_WAIT, self.0, seen, ticks) })
    }
}

/// A second handle to the same object holding only `rights`, which must be
/// a subset of what `handle` holds.
pub fn duplicate(handle: u64, rights: u64) -> Result<u64, Error> {
    result(unsafe { syscall3(SYS_DUPLICATE, handle, rights, 0) })
}

/// Handle to a bounded byte stream. A freshly created pipe handle carries
/// both rights; `duplicate` splits it into a read end and a write end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pipe(u64);

impl Pipe {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
    pub fn create() -> Result<Self, Error> {
        result(unsafe { syscall3(SYS_PIPE_CREATE, 0, 0, 0) }).map(Self)
    }
    /// One kernel `read`: up to `MAX_WRITE` bytes, blocking while empty;
    /// zero means no writer is left.
    pub fn read_once(self, buffer: &mut [u8]) -> Result<usize, Error> {
        let length = buffer.len().min(MAX_WRITE) as u64;
        let raw = unsafe { syscall3(SYS_READ, self.0, buffer.as_mut_ptr() as u64, length) };
        result(raw).map(|count| count as usize)
    }
    /// One kernel `write`: up to `MAX_WRITE` bytes, possibly partial.
    pub fn write_once(self, bytes: &[u8]) -> Result<usize, Error> {
        let length = bytes.len().min(MAX_WRITE) as u64;
        let raw = unsafe { syscall3(SYS_WRITE, self.0, bytes.as_ptr() as u64, length) };
        result(raw).map(|count| count as usize)
    }
    /// `read_once` that gives up with `Error::Timeout` after `ticks`.
    pub fn read_timeout(self, buffer: &mut [u8], ticks: u64) -> Result<usize, Error> {
        transfer(
            self.0,
            TRANSFER_READ,
            buffer.as_mut_ptr(),
            buffer.len(),
            ticks,
        )
    }
    /// `write_once` that gives up with `Error::Timeout` after `ticks`.
    pub fn write_timeout(self, bytes: &[u8], ticks: u64) -> Result<usize, Error> {
        transfer(
            self.0,
            TRANSFER_WRITE,
            bytes.as_ptr().cast_mut(),
            bytes.len(),
            ticks,
        )
    }
    /// `pipe_info`: how full the pipe is and how many handles can read and
    /// write it, without blocking.
    pub fn info(self) -> Result<PipeInfo, Error> {
        pipe_info(self.0)
    }
    /// Writes every byte, blocking as the pipe fills.
    pub fn write_all(self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            let written = self.write_once(bytes)?;
            bytes = &bytes[written..];
        }
        Ok(())
    }
}

/// `pipe_info` on any raw handle: a stale or non-pipe handle is refused.
pub fn pipe_info(handle: u64) -> Result<PipeInfo, Error> {
    let mut record = [0u8; PIPE_INFO_BYTES];
    result(unsafe { syscall3(SYS_PIPE_INFO, handle, record.as_mut_ptr() as u64, 0) })?;
    Ok(PipeInfo::from_bytes(record))
}

/// The raw `pipe_info` result for a caller-chosen record address, for
/// negative controls.
pub fn pipe_info_raw(handle: u64, record: u64) -> i64 {
    unsafe { syscall3(SYS_PIPE_INFO, handle, record, 0) }
}

/// Handle to the one block storage device. Transfers are whole sectors; the
/// kernel returns from a write only once the device reported it complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Block(u64);

/// What `block_info` reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockInfo {
    pub sectors: u64,
    pub sector_bytes: u64,
}

impl Block {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
    pub fn info(self) -> Result<BlockInfo, Error> {
        let mut record = [0u8; BLOCK_INFO_BYTES];
        result(unsafe { syscall3(SYS_BLOCK_INFO, self.0, record.as_mut_ptr() as u64, 0) })?;
        let word = |offset: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&record[offset..offset + 8]);
            u64::from_le_bytes(raw)
        };
        Ok(BlockInfo {
            sectors: word(0),
            sector_bytes: word(8),
        })
    }
    pub fn read_sector(self, lba: u64, buffer: &mut [u8; BLOCK_SECTOR_BYTES]) -> Result<(), Error> {
        result(unsafe { syscall3(SYS_BLOCK_READ, self.0, lba, buffer.as_mut_ptr() as u64) })
            .map(|_| ())
    }
    pub fn write_sector(self, lba: u64, buffer: &[u8; BLOCK_SECTOR_BYTES]) -> Result<(), Error> {
        result(unsafe { syscall3(SYS_BLOCK_WRITE, self.0, lba, buffer.as_ptr() as u64) })
            .map(|_| ())
    }
    /// The device's durability barrier for every completed write.
    pub fn flush(self) -> Result<(), Error> {
        result(unsafe { syscall3(SYS_BLOCK_FLUSH, self.0, 0, 0) }).map(|_| ())
    }

    /// Reads `buffer.len() / BLOCK_SECTOR_BYTES` consecutive sectors from
    /// `lba` in one kernel request (`1..=BLOCK_MAX_TRANSFER_SECTORS`). The
    /// buffer must be a whole number of sectors; on an error its content is
    /// unspecified.
    pub fn read_sectors(self, lba: u64, buffer: &mut [u8]) -> Result<(), Error> {
        let request = Self::transfer(lba, buffer.len())?.to_bytes();
        result(unsafe {
            syscall3(
                SYS_BLOCK_READ_MANY,
                self.0,
                request.as_ptr() as u64,
                buffer.as_mut_ptr() as u64,
            )
        })
        .map(|_| ())
    }

    /// Writes `buffer.len() / BLOCK_SECTOR_BYTES` consecutive sectors from
    /// `lba` in one kernel request. Returns once the device reported the
    /// whole request complete; after an error some subset of the sectors
    /// may be on the device (a leading run on ATA PIO and QEMU's NVMe, not
    /// promised by the NVMe specification). Completion is not durability:
    /// `flush` is still the barrier.
    pub fn write_sectors(self, lba: u64, buffer: &[u8]) -> Result<(), Error> {
        let request = Self::transfer(lba, buffer.len())?.to_bytes();
        result(unsafe {
            syscall3(
                SYS_BLOCK_WRITE_MANY,
                self.0,
                request.as_ptr() as u64,
                buffer.as_ptr() as u64,
            )
        })
        .map(|_| ())
    }

    fn transfer(lba: u64, bytes: usize) -> Result<BlockTransfer, Error> {
        if !bytes.is_multiple_of(BLOCK_SECTOR_BYTES) {
            return Err(Error::Invalid);
        }
        Ok(BlockTransfer {
            lba,
            sectors: (bytes / BLOCK_SECTOR_BYTES) as u64,
        })
    }
}

/// Abrupt machine stop with `code` through a machine handle holding the
/// stop right. Returns only with the kernel's refusal: `BadHandle` without
/// a machine handle, `Rights` without the right, `Invalid` for a code
/// outside `STOP_CODE_MIN..=STOP_CODE_MAX`.
pub fn machine_stop(machine: u64, code: u64) -> Error {
    let raw = unsafe { syscall3(SYS_MACHINE_STOP, machine, code, 0) };
    Error::from_code(raw)
}

/// Arms a restart of the machine for the end of this boot (a machine
/// handle holding the restart right).
pub fn machine_restart(machine: u64) -> Result<(), Error> {
    result(unsafe { syscall3(SYS_MACHINE_RESTART, machine, 0, 0) }).map(|_| ())
}

/// Immediate whole-machine reset through a machine handle holding the
/// recover right, whoever holds it and whatever the boot mode. It does not
/// claim that children were reaped or that open writes were committed. A
/// successful call never returns; a refusal reports the kernel's error.
pub fn machine_recover(machine: u64) -> Error {
    Error::from_code(unsafe { syscall3(SYS_MACHINE_RECOVER, machine, 0, 0) })
}

/// This boot's 16-byte identity, the same for every process of the boot.
pub fn boot_id() -> Result<[u8; absd_abi::syscall::BOOT_ID_BYTES], Error> {
    let mut id = [0u8; absd_abi::syscall::BOOT_ID_BYTES];
    result(unsafe { syscall3(absd_abi::syscall::SYS_BOOT_ID, id.as_mut_ptr() as u64, 0, 0) })?;
    Ok(id)
}

/// The kernel's syscall ABI generation (`abi_version`, syscall 42): a
/// constant of the kernel build, `absd_abi::KERNEL_ABI` for a matching one.
/// `Error::NotImplemented` from a kernel older than the syscall.
pub fn abi_version() -> Result<u64, Error> {
    result(unsafe { syscall3(absd_abi::syscall::SYS_ABI_VERSION, 0, 0, 0) })
}

/// Seconds since the Unix epoch from the CMOS RTC, which ABSD declares to
/// hold UTC; whole seconds only. `Error::Io` when the RTC gives no valid
/// reading.
pub fn wall_clock() -> Result<u64, Error> {
    result(unsafe { syscall3(absd_abi::syscall::SYS_WALL_CLOCK, 0, 0, 0) })
}

/// The physical frame allocator's counts at the instant of the call
/// (`SYS_FRAME_STATS`; see the ABI for what is counted).
pub fn frame_stats() -> Result<absd_abi::syscall::FrameStats, Error> {
    let mut bytes = [0u8; absd_abi::syscall::FRAME_STATS_BYTES];
    result(unsafe {
        syscall3(
            absd_abi::syscall::SYS_FRAME_STATS,
            bytes.as_mut_ptr() as u64,
            0,
            0,
        )
    })?;
    Ok(absd_abi::syscall::FrameStats::from_bytes(bytes))
}

/// One read-only snapshot of occupied process slots and live kernel objects.
pub fn resource_census() -> Result<absd_abi::syscall::ResourceCensus, Error> {
    let mut bytes = [0u8; RESOURCE_CENSUS_BYTES];
    result(unsafe { syscall3(SYS_RESOURCE_CENSUS, bytes.as_mut_ptr() as u64, 0, 0) })?;
    Ok(absd_abi::syscall::ResourceCensus::from_bytes(bytes))
}

/// Raw `frame_stats` for negative controls: passes `address` unchecked.
pub fn frame_stats_raw(address: u64) -> i64 {
    unsafe { syscall3(absd_abi::syscall::SYS_FRAME_STATS, address, 0, 0) }
}

/// Releases any handle. Its value is never valid again.
pub fn close(handle: u64) -> Result<(), Error> {
    result(unsafe { syscall3(SYS_CLOSE, handle, 0, 0) }).map(|_| ())
}

/// Maps `pages` zeroed anonymous pages from the process heap window.
pub fn map(pages: u64) -> Result<*mut u8, Error> {
    result(unsafe { syscall3(SYS_MAP, pages, 0, 0) }).map(|address| address as *mut u8)
}

/// Returns `pages` pages previously obtained from `map`.
pub fn unmap(address: *mut u8, pages: u64) -> Result<(), Error> {
    result(unsafe { syscall3(SYS_UNMAP, address as u64, pages, 0) }).map(|_| ())
}

/// Raw `wait` for negative controls: passes `record` through unchecked.
pub fn wait_raw(target: u64, record: u64) -> i64 {
    unsafe { syscall3(SYS_WAIT, target, record, 0) }
}

/// Defines `_start` for a program whose `main(Start) -> i32` result is its
/// exit status. The kernel places the console handle in `RDI`, the handed
/// over handle in `RSI`, the argument word in `RDX`, and (init only) the NIC
/// grant in `RCX`, which is exactly the SysV argument order. The user stack is 16-byte aligned at entry, so
/// one `call` gives `main` the alignment the ABI expects.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn __absd_main(
            console: u64,
            handle: u64,
            arg: u64,
            nic: u64,
            machine: u64,
        ) -> ! {
            let status: i32 = $main($crate::Start {
                console: $crate::Console::from_raw(console),
                handle,
                arg,
                nic,
                machine,
            });
            $crate::exit(status)
        }
        $crate::arch_entry!();
    };
}

/// Defines `_start` for a program launched by `spawn_many_copy`. The kernel
/// supplies an ordered handle vector in the child's own stack mapping.
#[macro_export]
macro_rules! multi_entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn __absd_main(console: u64, handles: *const u64, count: usize) -> ! {
            let handles = if count == 0 {
                &[]
            } else {
                // The kernel validates `count`, writes this vector into the
                // new address space, and keeps it above the initial RSP.
                unsafe { ::core::slice::from_raw_parts(handles, count) }
            };
            let status: i32 = $main($crate::MultiStart {
                console: $crate::Console::from_raw(console),
                handles,
            });
            $crate::exit(status)
        }
        $crate::arch_entry!();
    };
}

// Host-side test harnesses link std; these runtime shims exist only in the
// freestanding build.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exit(101)
}

// The host `core` archive references this unwinder symbol even with
// `panic = abort`; a freestanding program has no unwinder.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

// No libc: provide the byte helpers the compiler may call.
#[cfg(not(test))]
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    let mut index = 0;
    while index < count {
        unsafe {
            core::ptr::write_volatile(
                destination.cast::<u8>().add(index),
                core::ptr::read_volatile(source.cast::<u8>().add(index)),
            );
        }
        index += 1;
    }
    destination
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn memmove(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    if (destination as usize) <= (source as usize) {
        return unsafe { memcpy(destination, source, count) };
    }
    let mut index = count;
    while index > 0 {
        index -= 1;
        unsafe {
            core::ptr::write_volatile(
                destination.cast::<u8>().add(index),
                core::ptr::read_volatile(source.cast::<u8>().add(index)),
            );
        }
    }
    destination
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn memset(destination: *mut c_void, value: i32, count: usize) -> *mut c_void {
    let mut index = 0;
    while index < count {
        unsafe {
            core::ptr::write_volatile(destination.cast::<u8>().add(index), value as u8);
        }
        index += 1;
    }
    destination
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, count: usize) -> i32 {
    let mut index = 0;
    while index < count {
        let a = unsafe { core::ptr::read_volatile(left.cast::<u8>().add(index)) };
        let b = unsafe { core::ptr::read_volatile(right.cast::<u8>().add(index)) };
        if a != b {
            return a as i32 - b as i32;
        }
        index += 1;
    }
    0
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn bcmp(left: *const c_void, right: *const c_void, count: usize) -> i32 {
    unsafe { memcmp(left, right, count) }
}

/// Qualification probe: checks SIMD and control state across yield/preemption.
pub fn fp_state_probe(seed: u64) -> bool {
    arch::fp_state_probe(seed)
}

pub mod fault_qualification;
