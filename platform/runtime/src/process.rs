//! `std::process` for a process that holds the kernel's spawn right and no
//! broker channel: the program is a file on the mounted filesystem, read
//! whole and started with `spawn_image` (kernel `docs/PROCESS-STARTUP.md`).
//!
//! The child's startup vector is
//! `[startup, stdin, stdout, stderr, (fs | channels), (events, requests),
//! console]`: `startup` is a pipe carrying the startup record (roles, argv,
//! environment, working directory), `fs` a read-only duplicate of this
//! process's block handle, which the child's runtime mounts read-only,
//! `channels` file server channels (`crate::fsd`: a spare bound to this
//! process's authority or less, this process's own lent to it, or none)
//! when this process reaches the filesystem through a file server,
//! `events` and `requests` a session control channel when the caller armed
//! one for this child (`crate::session`), and `console` the stdout handle
//! again. The writable filesystem view is never lent: the exclusive writer
//! stays the one process init gave the read-write handle to.
//!
//! There is no PATH search, no interpreter or `#!` line, no dynamic
//! linking, and no execute permission (ABSD files have none): what may run
//! is decided by the spawn right this process holds and by which files are
//! on the filesystem it can read.

use alloc::vec::Vec;

use absd_broker::{MAX_STARTUP, RequestError, encode_startup, role};

use crate::{BLOCK, ERROR, INPUT, OUTPUT, RIGHT_READ, RIGHT_WRITE, cwd, syscall3};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const SYS_WRITE: u64 = 1;
const SYS_WAIT: u64 = 6;
const SYS_CLOSE: u64 = 9;
const SYS_DUPLICATE: u64 = 13;
const SYS_PIPE_CREATE: u64 = 16;
const SYS_INFO: u64 = 19;
const SYS_KILL: u64 = 20;
const SYS_SPAWN_IMAGE: u64 = 31;
const COPY_CONSOLE: u64 = 1;
const MAX_TRANSFER: usize = 256;
const MAX_IMAGE: u64 = 32 << 20;
const ERROR_TIMEOUT: i64 = -110;

/// A process token for an image child: this bit plus the process handle.
/// Broker children are identified by their slot number, always below it.
pub const IMAGE_CHILD: u64 = 1 << 63;

/// Hook results below every kernel error code; `sys/process/absd.rs` maps
/// them to `io::ErrorKind`s.
pub const SPAWN_NO_PATH_SEARCH: i64 = -2010;
pub const SPAWN_BAD_ENVIRONMENT: i64 = -2011;
pub const SPAWN_TOO_LARGE: i64 = -2003;
pub const SPAWN_INVALID: i64 = -2002;
pub const SPAWN_NOT_A_FILE: i64 = -2012;
pub const SPAWN_IMAGE_TOO_LARGE: i64 = -2013;
pub const SPAWN_NOT_A_DIRECTORY: i64 = -2014;

/// Standard stream sources, as `sys/process/absd.rs` passes them.
pub const STDIO_NULL: u32 = 0;
pub const STDIO_PIPE: u32 = 1;
pub const STDIO_INHERIT: u32 = 2;
pub const STDIO_PARENT_STDOUT: u32 = 3;
pub const STDIO_PARENT_STDERR: u32 = 4;
/// A pipe end the caller holds (`RawSpawn::handles`): the child gets a copy
/// with only the right its stream needs, and the caller closes its own copy
/// once the spawn succeeds (`std` does, by consuming the `Stdio`).
pub const STDIO_HANDLE: u32 = 5;

#[repr(C)]
pub struct RawSpawn {
    pub path: *const u8,
    pub path_length: usize,
    pub args: *const [usize; 2],
    pub argc: usize,
    /// `KEY=VALUE` entries: the child's whole environment.
    pub env: *const [usize; 2],
    pub envc: usize,
    /// The child's working directory, resolved against ours; empty: ours.
    pub cwd: *const u8,
    pub cwd_length: usize,
    pub stdio: [u32; 3],
    /// The pipe end for each `STDIO_HANDLE` stream, else 0.
    pub handles: [u64; 3],
}

/// The kernel's `SPAWN_NO_SPAWN` flag: the child, and everything it could
/// start, has no spawn right.
pub const SPAWN_NO_SPAWN: u64 = 1 << 33;

/// Flags this process passes to `spawn_image` for every `Command` child.
static CHILD_FLAGS: AtomicU64 = AtomicU64::new(0);

/// The program image being started, kept between spawns with the
/// capacity of the largest image read so far. A process that starts many
/// children (sshd, a shell) would otherwise allocate and free one
/// image-sized block per child; once the heap's free space no longer
/// holds a block that size in one piece, the allocator maps new pages
/// that are never returned, which the containment matrix sees as frames
/// not returned after churn. The runtime is single-threaded and `spawn`
/// is not re-entered, so the buffer has one user at a time.
static mut IMAGE: Vec<u8> = Vec::new();

/// Personality policy: when `deny` is set, children `std::process` starts
/// from now on get no spawn right (the kernel's `SPAWN_NO_SPAWN`), so they
/// and their descendants cannot start programs at all. The right only
/// narrows; clearing this affects later children only.
pub fn deny_spawn_to_children(deny: bool) {
    CHILD_FLAGS.store(if deny { SPAWN_NO_SPAWN } else { 0 }, Ordering::Relaxed);
}

/// Whether children with piped stdout and stderr share one pipe.
static MERGE_OUTPUT: AtomicBool = AtomicBool::new(false);

/// Personality policy: when `merge` is set, a child `std::process` starts
/// from now on with both stdout and stderr piped gets one pipe for both
/// (its stderr end is a second copy of its stdout end), so the caller
/// reads them as one ordered stream, as a terminal shows them. The caller
/// then holds no stderr end: `Child::stderr` is `None`. sshd uses this
/// for PTY sessions.
pub fn merge_output_for_children(merge: bool) {
    MERGE_OUTPUT.store(merge, Ordering::Relaxed);
}

/// The raw `spawn_image(request, flags, reserved)` syscall, for callers
/// that build their own request record (negative controls).
pub fn spawn_image_raw(request: u64, flags: u64, reserved: u64) -> i64 {
    unsafe { syscall3(SYS_SPAWN_IMAGE, request, flags, reserved) }
}

/// Whether `std::process` goes through init's broker (a brokered worker)
/// rather than starting files itself.
#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_process_brokered() -> u64 {
    u64::from(crate::broker::installed())
}

struct Owned(Vec<u64>);

impl Owned {
    fn keep(&mut self, handle: u64) -> u64 {
        self.0.push(handle);
        handle
    }
    /// Closes `handle` now and forgets it.
    fn close(&mut self, handle: u64) {
        if let Some(at) = self.0.iter().position(|&held| held == handle) {
            self.0.swap_remove(at);
        }
        unsafe { syscall3(SYS_CLOSE, handle, 0, 0) };
    }
    /// Stops owning `handle` (it now belongs to the caller).
    fn release(&mut self, handle: u64) -> u64 {
        if let Some(at) = self.0.iter().position(|&held| held == handle) {
            self.0.swap_remove(at);
        }
        handle
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        for &handle in &self.0 {
            unsafe { syscall3(SYS_CLOSE, handle, 0, 0) };
        }
    }
}

fn result(raw: i64) -> Result<u64, i64> {
    if raw < 0 { Err(raw) } else { Ok(raw as u64) }
}

fn duplicate(handle: u64, rights: u64) -> Result<u64, i64> {
    result(unsafe { syscall3(SYS_DUPLICATE, handle, rights, 0) })
}

/// A new pipe split into `(reader, writer)`.
fn pipe(owned: &mut Owned) -> Result<(u64, u64), i64> {
    let both = owned.keep(result(unsafe { syscall3(SYS_PIPE_CREATE, 0, 0, 0) })?);
    let reader = owned.keep(duplicate(both, RIGHT_READ)?);
    let writer = owned.keep(duplicate(both, RIGHT_WRITE)?);
    owned.close(both);
    Ok((reader, writer))
}

fn write_all(handle: u64, mut bytes: &[u8]) -> i64 {
    while !bytes.is_empty() {
        let length = bytes.len().min(MAX_TRANSFER);
        let written = unsafe { syscall3(SYS_WRITE, handle, bytes.as_ptr() as u64, length as u64) };
        if written <= 0 {
            return if written == 0 { -22 } else { written };
        }
        bytes = &bytes[written as usize..];
    }
    0
}

unsafe fn pairs<'a>(pointer: *const [usize; 2], count: usize) -> Vec<&'a [u8]> {
    if count == 0 {
        return Vec::new();
    }
    unsafe { core::slice::from_raw_parts(pointer, count) }
        .iter()
        .map(|&[bytes, length]| {
            if length == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(bytes as *const u8, length) } }
        })
        .collect()
}

unsafe fn bytes<'a>(pointer: *const u8, length: usize) -> &'a [u8] {
    if length == 0 { &[] } else { unsafe { core::slice::from_raw_parts(pointer, length) } }
}

/// The handle this process writes its own stdout or stderr to.
fn own_output(stream: u32) -> u64 {
    match stream {
        STDIO_PARENT_STDERR => match ERROR.load(Ordering::Relaxed) {
            0 => OUTPUT.load(Ordering::Relaxed),
            handle => handle,
        },
        _ => OUTPUT.load(Ordering::Relaxed),
    }
}

/// Starts the file at `path` as a child. On success `out` is
/// `[IMAGE_CHILD | process handle, pid, stdin writer, stdout reader,
/// stderr reader]`; a stream that is inherited has no end here (0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_process_spawn_image(request: *const RawSpawn, out: *mut [u64; 5]) -> i64 {
    let request = unsafe { &*request };
    // A session control channel armed for this child is spent by this
    // spawn whatever its outcome; its drop closes this process's copies of
    // the child's ends.
    let control = crate::session::take_next();
    match unsafe { spawn(request, control.as_ref()) } {
        Ok(ends) => {
            unsafe { *out = ends };
            0
        }
        Err(code) => code,
    }
}

unsafe fn spawn(request: &RawSpawn, control: Option<&crate::session::ChildEnds>) -> Result<[u64; 5], i64> {
    let path = unsafe { bytes(request.path, request.path_length) };
    if path.is_empty() || path.contains(&0) {
        return Err(SPAWN_INVALID);
    }
    // A bare name would need a search path; ABSD has none (yet).
    if !path.contains(&b'/') {
        return Err(SPAWN_NO_PATH_SEARCH);
    }
    let args = unsafe { pairs(request.args, request.argc) };
    let env = unsafe { pairs(request.env, request.envc) };
    for entry in &env {
        let key_end = entry.iter().position(|&byte| byte == b'=');
        if key_end.is_none_or(|end| end == 0) {
            return Err(SPAWN_BAD_ENVIRONMENT);
        }
    }
    let child_cwd = match unsafe { bytes(request.cwd, request.cwd_length) } {
        b"" => cwd::get().to_vec(),
        given => {
            let directory = cwd::normalize(given);
            match crate::storage::stat_kind(&directory) {
                Some(Ok(absd_fs::Kind::Dir)) => {}
                Some(Ok(_)) => return Err(SPAWN_NOT_A_DIRECTORY),
                Some(Err(code)) => return Err(code),
                None if directory == b"/" => {}
                None => return Err(-2),
            }
            directory
        }
    };
    // SAFETY: single-threaded runtime; no other reference to IMAGE is
    // live while `spawn` runs (see the static's comment).
    let image: &mut Vec<u8> = unsafe { &mut *core::ptr::addr_of_mut!(IMAGE) };
    crate::storage::read_file_into(path, MAX_IMAGE, image).map_err(|code| match code {
        -21 => SPAWN_NOT_A_FILE,
        -27 => SPAWN_IMAGE_TOO_LARGE,
        other => other,
    })?;

    let mut owned = Owned(Vec::new());
    let (startup_reader, startup_writer) = pipe(&mut owned)?;
    // Each stream: the end the child gets, and the end this process keeps.
    let mut child_ends = [0u64; 3];
    let mut parent_ends = [0u64; 3];
    let mut close_after_start = [false; 3];
    let merge = MERGE_OUTPUT.load(Ordering::Relaxed) && request.stdio[1] == STDIO_PIPE && request.stdio[2] == STDIO_PIPE;
    for (stream, &mode) in request.stdio.iter().enumerate() {
        if stream == 2 && merge {
            // stdout's writer again; this process keeps no stderr end.
            child_ends[2] = child_ends[1];
            continue;
        }
        let inherited = match (stream, mode) {
            // Copied below as the stream's direction only (read for stdin,
            // write for output); the kernel refuses a right the end lacks.
            (_, STDIO_HANDLE) if request.handles[stream] != 0 => request.handles[stream],
            (_, STDIO_HANDLE) => return Err(SPAWN_INVALID),
            (0, STDIO_INHERIT) => INPUT.load(Ordering::Relaxed),
            (0, _) => 0,
            (_, STDIO_INHERIT) => own_output(if stream == 1 { STDIO_PARENT_STDOUT } else { STDIO_PARENT_STDERR }),
            (_, STDIO_PARENT_STDOUT | STDIO_PARENT_STDERR) => own_output(mode),
            _ => 0,
        };
        if inherited != 0 {
            child_ends[stream] = inherited;
            continue;
        }
        if !matches!(mode, STDIO_NULL | STDIO_PIPE | STDIO_INHERIT) {
            return Err(SPAWN_INVALID);
        }
        // Piped, null, or an inherited stdin this process does not have:
        // a pipe. Null stdin loses its writer once the child runs (EOF);
        // null output keeps a reader the caller drains and discards.
        let (reader, writer) = pipe(&mut owned)?;
        if stream == 0 {
            child_ends[0] = reader;
            parent_ends[0] = writer;
            close_after_start[0] = mode != STDIO_PIPE;
        } else {
            child_ends[stream] = writer;
            parent_ends[stream] = reader;
        }
    }
    // Decided (and bound by the server) last, once nothing else can fail
    // before the spawn but the spawn itself.
    let plan = crate::fsd::plan_child()?;
    let channel_ends = plan.ends();
    let block = BLOCK.load(Ordering::Relaxed);
    let view = if block != 0 && !matches!(plan, crate::fsd::Plan::NoFs) {
        match duplicate(block, RIGHT_READ) {
            Ok(view) => owned.keep(view),
            Err(code) => {
                crate::fsd::child_failed(&plan);
                return Err(code);
            }
        }
    } else {
        0
    };

    let mut copies: Vec<[u64; 3]> = Vec::with_capacity(6);
    let mut roles: Vec<(u8, u8)> = Vec::with_capacity(4);
    copies.push([startup_reader, RIGHT_READ, 0]);
    copies.push([child_ends[0], RIGHT_READ, 0]);
    copies.push([child_ends[1], RIGHT_WRITE, 0]);
    copies.push([child_ends[2], RIGHT_WRITE, 0]);
    roles.extend([(role::STDIN, 1), (role::STDOUT, 2), (role::STDERR, 3)]);
    if view != 0 {
        roles.push((role::FS, copies.len() as u8));
        copies.push([view, RIGHT_READ, 0]);
    }
    for &(request, reply) in &channel_ends {
        roles.push((role::FS_REQUEST, copies.len() as u8));
        copies.push([request, RIGHT_WRITE, 0]);
        roles.push((role::FS_REPLY, copies.len() as u8));
        copies.push([reply, RIGHT_READ, 0]);
    }
    if let Some(control) = control {
        roles.push((role::SESSION_EVENTS, copies.len() as u8));
        copies.push([control.events, RIGHT_READ, 0]);
        roles.push((role::SESSION_REQUESTS, copies.len() as u8));
        copies.push([control.requests, RIGHT_WRITE, 0]);
    }
    copies.push([child_ends[1], RIGHT_WRITE, COPY_CONSOLE]);

    let mut record = alloc::vec![0u8; MAX_STARTUP];
    let encoded = encode_startup(&roles, args.iter().copied(), env.iter().copied(), &child_cwd, path, copies.len(), &mut record)
        .map_err(|error| match error {
            RequestError::Invalid => SPAWN_INVALID,
            RequestError::TooManyArguments | RequestError::TooLarge => SPAWN_TOO_LARGE,
        });
    let length = match encoded {
        Ok(length) => length,
        Err(code) => {
            crate::fsd::child_failed(&plan);
            return Err(code);
        }
    };

    let spawn_request = [image.as_ptr() as u64, image.len() as u64, copies.as_ptr() as u64, copies.len() as u64];
    let flags = CHILD_FLAGS.load(Ordering::Relaxed);
    let child = match result(spawn_image_raw(spawn_request.as_ptr() as u64, flags, 0)) {
        Ok(child) => child,
        Err(code) => {
            crate::fsd::child_failed(&plan);
            return Err(code);
        }
    };
    // The child holds this copy now. Free it before FSD records its WAIT
    // holder: successful spawn needed one slot and used it for `child`,
    // so this guarantees another slot in the single-threaded runtime.
    owned.close(startup_reader);
    crate::fsd::child_started(&plan, child);
    // The child holds its own copy of the image; the buffer keeps its
    // capacity for the next spawn.
    image.clear();
    // The child holds its own copies now.
    for stream in 0..3 {
        if parent_ends[stream] != 0 {
            owned.close(child_ends[stream]);
        }
    }
    if view != 0 {
        owned.close(view);
    }
    for (stream, close) in close_after_start.iter().enumerate() {
        if *close {
            owned.close(parent_ends[stream]);
            parent_ends[stream] = 0;
        }
    }
    let written = write_all(startup_writer, &record[..length]);
    owned.close(startup_writer);
    let mut info = [0u64; 4];
    let identified = unsafe { syscall3(SYS_INFO, child, info.as_mut_ptr() as u64, 0) };
    if written < 0 || identified < 0 {
        // The child cannot have read a whole record: end it and reap it.
        unsafe { syscall3(SYS_KILL, child, 0, 0) };
        let mut outcome = [0u64; 4];
        unsafe { syscall3(SYS_WAIT, child, outcome.as_mut_ptr() as u64, 0) };
        return Err(if written < 0 { written } else { identified });
    }
    let [stdin, stdout, stderr] = parent_ends;
    for end in parent_ends {
        if end != 0 {
            owned.release(end);
        }
    }
    Ok([IMAGE_CHILD | child, info[0], stdin, stdout, stderr])
}

/// The outcome value `std` reports, in the broker's encoding: the exit
/// status; a fault is `-1000 - vector`; killed is `-1`.
fn outcome_value(record: &[u64; 4]) -> i64 {
    match record[0] {
        1 => record[1] as i32 as i64,
        2 => -1000 - record[1] as i64,
        _ => -1,
    }
}

/// `wait` for an image child: 1 with `*value` set once it has ended (and
/// is reaped: the kernel closes the process handle); 0 when `nonblocking`
/// and it has not ended within one tick.
pub(crate) fn wait(token: u64, nonblocking: bool, value: &mut i64) -> i64 {
    let handle = token & !IMAGE_CHILD;
    let mut record = [0u64; 4];
    let timeout = u64::from(nonblocking);
    let result = unsafe { syscall3(SYS_WAIT, handle, record.as_mut_ptr() as u64, timeout) };
    match result {
        ERROR_TIMEOUT if nonblocking => 0,
        result if result < 0 => result,
        _ => {
            *value = outcome_value(&record);
            1
        }
    }
}

/// `Child::kill` for an image child: the kernel ends it at once.
#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_process_kill(token: u64) -> i64 {
    if token & IMAGE_CHILD == 0 {
        return crate::broker::SPAWN_NO_BROKER;
    }
    unsafe { syscall3(SYS_KILL, token & !IMAGE_CHILD, 0, 0) }
}
