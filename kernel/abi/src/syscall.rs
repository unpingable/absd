//! ABSD's initial `int 0x80` userspace ABI.

pub const SYS_WRITE: u64 = 1;
pub const SYS_YIELD: u64 = 2;
pub const SYS_EXIT: u64 = 3;
pub const SYS_GETPID: u64 = 4;
pub const SYS_SPAWN: u64 = 5;
pub const SYS_WAIT: u64 = 6;
pub const SYS_MAP: u64 = 7;
pub const SYS_UNMAP: u64 = 8;
pub const SYS_CLOSE: u64 = 9;
pub const SYS_CELL_CREATE: u64 = 10;
pub const SYS_CELL_READ: u64 = 11;
pub const SYS_CELL_TRANSITION: u64 = 12;
pub const SYS_DUPLICATE: u64 = 13;
pub const SYS_CELL_WAIT: u64 = 14;
pub const SYS_READ: u64 = 15;
pub const SYS_PIPE_CREATE: u64 = 16;
pub const SYS_TIME: u64 = 17;
pub const SYS_SLEEP: u64 = 18;
/// Complete the current RT instance and wait for its next phase release.
/// Refused unless already admitted by kernel configuration; grants no priority.
pub const SYS_RT_NEXT: u64 = 39;
pub const SYS_INFO: u64 = 19;
pub const SYS_KILL: u64 = 20;
pub const SYS_TRANSFER: u64 = 21;
pub const SYS_SPAWN_MANY_COPY: u64 = 22;
/// Block storage: fixed 512-byte sectors on the one probed device.
pub const SYS_BLOCK_INFO: u64 = 24;
pub const SYS_BLOCK_READ: u64 = 25;
pub const SYS_BLOCK_WRITE: u64 = 26;
pub const SYS_BLOCK_FLUSH: u64 = 27;
// 28 was `stop(code)`, gated on the boot mode rather than on a handle:
// any process of a durable boot could end the machine. It is retired and
// answers `-38`; `machine_stop` (37) replaces it.
/// `boot_id(address)`: stores this boot's 16-byte identity, drawn once from
/// RDRAND the first time anything asks. Every process of one boot sees the
/// same bytes; no two boots share them. Without RDRAND it is refused.
pub const SYS_BOOT_ID: u64 = 29;
pub const BOOT_ID_BYTES: usize = 16;
/// `wall_clock()`: seconds since the Unix epoch read from the CMOS RTC,
/// whole seconds only, the RTC declared to hold UTC (kernel `src/rtc.rs`).
/// Returned directly (non-negative). `ERROR_IO` when no stable, valid
/// calendar reading can be taken; the kernel never substitutes a value.
pub const SYS_WALL_CLOCK: u64 = 30;
/// `spawn_image(request, flags, 0)`: like `spawn_many_copy`, but the program
/// is a static ELF64 image in the caller's own memory instead of a catalog
/// index. `request` points to a [`SpawnImageRequest`] record; `flags` may
/// carry only `SPAWN_NO_SPAWN`; the third argument is reserved and must be
/// zero. The kernel copies and validates the image with the same loader the
/// catalog uses; the child is multi-start. See `docs/PROCESS-STARTUP.md`.
pub const SYS_SPAWN_IMAGE: u64 = 31;
/// Size of the [`SpawnImageRequest`] record in userspace memory.
pub const SPAWN_IMAGE_REQUEST_BYTES: usize = 32;
/// Largest image `spawn_image` accepts: the size of the anonymous heap
/// window, where a caller that read the image from a file holds it.
pub const MAX_SPAWN_IMAGE_BYTES: u64 = 32 << 20;
/// `frame_stats(address)`: stores the physical frame allocator's counts as
/// a [`FrameStats`] record. The handler runs with interrupts disabled on
/// the one CPU, so the counts are one consistent state of the allocator at
/// the instant of the call, not an estimate or an average. Only frames the
/// allocator tracks are counted: those the firmware memory map marked
/// usable and the kernel tracks (below its disclosed limit, at most 64 GiB
/// on x86), minus the ranges reserved at boot (low memory, the kernel
/// image, boot information, modules, the frame table). Every frame a
/// process or the kernel holds through the allocator is allocated,
/// including page tables and the calling process's own frames.
pub const SYS_FRAME_STATS: u64 = 35;
/// Size of the [`FrameStats`] record in userspace memory.
pub const FRAME_STATS_BYTES: usize = 32;
/// `allocation_limit` when no limit is set (the normal case; a limit exists
/// only while the kernel's own exhaustion test runs).
pub const FRAME_LIMIT_NONE: u64 = u64::MAX;

/// The `frame_stats` record: four little-endian words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameStats {
    /// Tracked frames that are free now.
    pub free_frames: u64,
    /// Tracked frames allocated now, to any owner.
    pub allocated_frames: u64,
    /// The ceiling on `allocated_frames`, or [`FRAME_LIMIT_NONE`].
    pub allocation_limit: u64,
    /// Bytes per frame (the page size).
    pub frame_bytes: u64,
}

impl FrameStats {
    pub fn to_bytes(self) -> [u8; FRAME_STATS_BYTES] {
        let mut bytes = [0u8; FRAME_STATS_BYTES];
        for (index, word) in [
            self.free_frames,
            self.allocated_frames,
            self.allocation_limit,
            self.frame_bytes,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: [u8; FRAME_STATS_BYTES]) -> Self {
        let word = |index: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
            u64::from_le_bytes(raw)
        };
        Self {
            free_frames: word(0),
            allocated_frames: word(1),
            allocation_limit: word(2),
            frame_bytes: word(3),
        }
    }
}

/// `pipe_info(handle, address)`: stores a [`PipeInfo`] record for the pipe
/// `handle` names, without moving any byte and without blocking. Any
/// handle to the pipe will do, whatever its rights: the record reveals
/// only how full the pipe is and how many handles can read and write it.
/// `-9` for a stale handle or one that is not a pipe, `-14` for a record
/// that is not writable user memory. A server that holds one end of many
/// pipes polls them with it (there is no wait on many), and learns when
/// every other holder of an end is gone even while it, or a keeper of
/// spare ends, still holds a copy (docs/PROCESS-STARTUP.md, "File server").
pub const SYS_PIPE_INFO: u64 = 36;
/// Size of the [`PipeInfo`] record in userspace memory.
pub const PIPE_INFO_BYTES: usize = 32;

/// `machine_stop(handle, code)`: abrupt machine stop at a named
/// application point. `handle` must name the machine object with
/// [`MACHINE_RIGHT_STOP`]; `code` lies in `STOP_CODE_MIN..=STOP_CODE_MAX`.
/// QEMU exits at once through the debug-exit device with status
/// `4 * code + 3`, so no later guest instruction runs and nothing is
/// flushed on the way out. `-9` without a machine handle, `-1` without the
/// right, `-22` for a code outside the range; it returns only to refuse.
pub const SYS_MACHINE_STOP: u64 = 37;
/// `machine_restart(handle)`: arms a restart. `handle` must name the
/// machine object with [`MACHINE_RIGHT_RESTART`]. Nothing happens at the
/// call: when the boot ends (init has exited and the kernel's end-of-boot
/// accounting passes) the kernel resets the machine instead of halting it.
/// An accounting failure still halts. Returns 0; arming twice is allowed.
pub const SYS_MACHINE_RESTART: u64 = 38;
/// `machine_recover(handle)`: an immediate whole-machine reset. `handle`
/// must name the machine object with [`MACHINE_RIGHT_RECOVER`]; no PID and
/// no boot mode is consulted. The kernel prints a census of the processes
/// and objects the reset abandons, then resets: there is no end-of-boot
/// accounting and no process drain or filesystem sync. Memory-owned
/// resources disappear at reset, and only previously committed storage has
/// its documented durability. `-9` without a machine handle, `-1` without
/// the right, each logged like the other machine refusals; it returns only
/// to refuse.
pub const SYS_MACHINE_RECOVER: u64 = 40;
/// `resource_census(address)`: one read-only snapshot of fixed kernel
/// occupancy. The five little-endian words are occupied process slots
/// (including Created/terminal), live handle entries, live pipe objects,
/// live cell objects, and tracked allocated physical 4 KiB frames. They
/// are instantaneous counts; monotonic PIDs and event totals are excluded.
pub const SYS_RESOURCE_CENSUS: u64 = 41;
pub const RESOURCE_CENSUS_BYTES: usize = 40;
/// `abi_version()`: returns [`crate::KERNEL_ABI`], the generation of this
/// syscall interface. No arguments (any passed are ignored), no handle, no
/// rights: it is a constant
/// compiled into the kernel, not an observation of any state, and it never
/// changes during a boot. A kernel older than this syscall answers `-38`
/// (`ERROR_NOT_IMPLEMENTED`), which a caller must treat as "not my
/// generation". This is the one number the platform's hand-copied syscall
/// table must equal; its runtime asks at start and refuses to run against
/// any other answer.
pub const SYS_ABI_VERSION: u64 = 42;
/// `block_read_many(handle, request, buffer)` and
/// `block_write_many(handle, request, buffer)`: one bounded transfer of
/// `1..=BLOCK_MAX_TRANSFER_SECTORS` consecutive sectors in one device
/// command. `request` points to a [`BlockTransfer`] record `{lba, sectors}`
/// of [`BLOCK_TRANSFER_BYTES`]; `buffer` is `sectors * BLOCK_SECTOR_BYTES`
/// bytes of the caller's memory, validated before the device is touched.
/// The answer covers the whole request: zero means the device completed
/// every sector; on an error nothing is copied out, and a failed write has
/// put some subset of its sectors on the device, an indeterminate effect
/// that only a read or a fresh scan resolves. With ATA PIO (one data phase
/// per sector, in order) and QEMU's NVMe model that subset is a leading
/// run; the NVMe specification leaves a failed command's range
/// indeterminate, so no caller may rely on a prefix. `-22`
/// for zero sectors, more than the bound, or a span past the device;
/// otherwise the `block_read`/`block_write` errors. A kernel older than
/// these calls answers `-38`. Completion means the device accepted the
/// sectors, not that they are durable: `block_flush` is still the only
/// barrier, and the rights are those of `block_read`/`block_write`.
pub const SYS_BLOCK_READ_MANY: u64 = 43;
pub const SYS_BLOCK_WRITE_MANY: u64 = 44;
/// Largest `block_*_many` request: one 4 KiB page of sectors.
pub const BLOCK_MAX_TRANSFER_SECTORS: u64 = 8;
/// Size of the [`BlockTransfer`] record in userspace memory.
pub const BLOCK_TRANSFER_BYTES: usize = 16;

/// The `block_*_many` request record: `{lba: u64, sectors: u64}`, little
/// endian.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockTransfer {
    pub lba: u64,
    pub sectors: u64,
}

impl BlockTransfer {
    pub fn to_bytes(self) -> [u8; BLOCK_TRANSFER_BYTES] {
        let mut bytes = [0u8; BLOCK_TRANSFER_BYTES];
        bytes[..8].copy_from_slice(&self.lba.to_le_bytes());
        bytes[8..].copy_from_slice(&self.sectors.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8; BLOCK_TRANSFER_BYTES]) -> Self {
        let word = |offset: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(raw)
        };
        Self {
            lba: word(0),
            sectors: word(8),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceCensus {
    pub processes: u64,
    pub handles: u64,
    pub pipes: u64,
    pub cells: u64,
    pub frames: u64,
}

impl ResourceCensus {
    pub fn to_bytes(self) -> [u8; RESOURCE_CENSUS_BYTES] {
        let mut bytes = [0u8; RESOURCE_CENSUS_BYTES];
        for (index, word) in [
            self.processes,
            self.handles,
            self.pipes,
            self.cells,
            self.frames,
        ]
        .iter()
        .enumerate()
        {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: [u8; RESOURCE_CENSUS_BYTES]) -> Self {
        let word = |index: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
            u64::from_le_bytes(raw)
        };
        Self::from_words([word(0), word(1), word(2), word(3), word(4)])
    }

    pub fn from_words(words: [u64; 5]) -> Self {
        Self {
            processes: words[0],
            handles: words[1],
            pipes: words[2],
            cells: words[3],
            frames: words[4],
        }
    }
}
/// Machine-object rights (object-local meanings of the generic bits): end
/// the machine now, abruptly, at a named point.
pub const MACHINE_RIGHT_STOP: u64 = RIGHT_KILL;
/// Machine-object right: restart the machine when this boot ends.
pub const MACHINE_RIGHT_RESTART: u64 = RIGHT_WRITE;
/// Machine-object right: reset the machine now, with no end-of-boot
/// accounting and no process drain ([`SYS_MACHINE_RECOVER`]).
pub const MACHINE_RIGHT_RECOVER: u64 = RIGHT_WAIT;

/// What `pipe_info` reports: four little-endian words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipeInfo {
    /// Bytes a read would take now.
    pub available: u64,
    /// Bytes a write would place now.
    pub space: u64,
    /// Handles carrying the read right, in every process.
    pub readers: u64,
    /// Handles carrying the write right, in every process.
    pub writers: u64,
}

impl PipeInfo {
    pub fn to_bytes(self) -> [u8; PIPE_INFO_BYTES] {
        let mut bytes = [0u8; PIPE_INFO_BYTES];
        for (index, word) in [self.available, self.space, self.readers, self.writers]
            .into_iter()
            .enumerate()
        {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: [u8; PIPE_INFO_BYTES]) -> Self {
        let word = |index: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
            u64::from_le_bytes(raw)
        };
        Self {
            available: word(0),
            space: word(1),
            readers: word(2),
            writers: word(3),
        }
    }
}
/// `block_read`/`block_write` move exactly one sector; `block_read_many`/
/// `block_write_many` move up to [`BLOCK_MAX_TRANSFER_SECTORS`] of them.
pub const BLOCK_SECTOR_BYTES: usize = 512;
/// `block_info` stores `{sector_count, sector_bytes}` at the caller's address.
pub const BLOCK_INFO_BYTES: usize = 16;
/// `machine_stop` codes are bounded so QEMU's exit status stays
/// distinguishable from the ordinary success/failure statuses.
pub const STOP_CODE_MIN: u64 = 16;
pub const STOP_CODE_MAX: u64 = 63;
/// `transfer` reads `{address, length, timeout}` from this user record.
pub const TRANSFER_BYTES: usize = 24;
pub const TRANSFER_READ: u64 = 0;
pub const TRANSFER_WRITE: u64 = 1;
/// `spawn` flag (OR-ed into the program word above the index): the handed
/// over handle becomes the child's console instead of a separate handle.
pub const SPAWN_CONSOLE: u64 = 1 << 32;
/// `spawn` and `spawn_many_copy` flag: the child, and everything it could
/// start, has no spawn right. The right only narrows (docs/BROKER.md).
pub const SPAWN_NO_SPAWN: u64 = 1 << 33;
pub const SPAWN_PROGRAM_MASK: u64 = (1 << 32) - 1;
/// Maximum number of handles copied by one `spawn_many_copy` operation.
/// This deliberately matches one complete child handle table so the kernel
/// can exercise and reject destination-capacity exhaustion atomically.
pub const MAX_SPAWN_HANDLES: usize = 64;
/// Size of one [`SpawnHandleCopy`] record in userspace memory.
pub const SPAWN_HANDLE_COPY_BYTES: usize = 24;
/// The copied handle replaces the child's default console. At most one
/// record in an operation may carry this flag.
pub const SPAWN_HANDLE_COPY_CONSOLE: u64 = 1;

/// One explicitly copy-only handle transfer requested at spawn. The parent
/// keeps `source`; the child receives a distinct handle with `rights`.
/// Duplicate source entries are allowed and create distinct child handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SpawnHandleCopy {
    pub source: u64,
    pub rights: u64,
    pub flags: u64,
}

impl SpawnHandleCopy {
    pub const fn new(source: u64, rights: u64) -> Self {
        Self {
            source,
            rights,
            flags: 0,
        }
    }

    pub const fn console(source: u64, rights: u64) -> Self {
        Self {
            source,
            rights,
            flags: SPAWN_HANDLE_COPY_CONSOLE,
        }
    }

    pub const fn from_words(words: [u64; 3]) -> Self {
        Self {
            source: words[0],
            rights: words[1],
            flags: words[2],
        }
    }
}
/// What `spawn_image` reads at its first argument: the image's address and
/// length, then the address and count of [`SpawnHandleCopy`] records
/// exactly as `spawn_many_copy` takes them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SpawnImageRequest {
    pub image: u64,
    pub image_bytes: u64,
    pub handles: u64,
    pub handle_count: u64,
}

impl SpawnImageRequest {
    pub const fn from_words(words: [u64; 4]) -> Self {
        Self {
            image: words[0],
            image_bytes: words[1],
            handles: words[2],
            handle_count: words[3],
        }
    }
}
/// `info` stores this record at the caller's supplied address.
pub const INFO_BYTES: usize = 32;
pub const INFO_STATE_LIVE: u64 = 1;
pub const INFO_STATE_TERMINAL: u64 = 2;
pub const INFO_STATE_WAITING: u64 = 3;

/// What `info` reports about a process: its own, or a child's by handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessInfo {
    pub pid: u64,
    pub parent: u64,
    pub program: u64,
    /// `INFO_STATE_LIVE`, `INFO_STATE_WAITING`, or `INFO_STATE_TERMINAL`
    /// (exited or faulted, not yet reaped).
    pub state: u64,
}

impl ProcessInfo {
    pub fn to_bytes(self) -> [u8; INFO_BYTES] {
        let mut bytes = [0u8; INFO_BYTES];
        for (index, word) in [self.pid, self.parent, self.program, self.state]
            .iter()
            .enumerate()
        {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
    pub fn from_words(words: [u64; 4]) -> Self {
        Self {
            pid: words[0],
            parent: words[1],
            program: words[2],
            state: words[3],
        }
    }
}
/// Largest single `read` or `write` transfer, in bytes.
pub const MAX_TRANSFER: u64 = 256;

/// Handle rights, as passed to `duplicate` and checked on every use.
pub const RIGHT_WRITE: u64 = 1;
pub const RIGHT_WAIT: u64 = 1 << 1;
pub const RIGHT_READ: u64 = 1 << 2;
pub const RIGHT_KILL: u64 = 1 << 3;
/// `cell_read` stores `{version, value}` at the caller's supplied address.
pub const CELL_RECORD_BYTES: usize = 16;
/// Largest single `map` request, in pages.
pub const MAX_MAP_PAGES: u64 = 64;
pub const ERROR_RIGHTS: i64 = -1;
pub const ERROR_NOT_FOUND: i64 = -2;
/// The block device reported an error or did not answer in time.
pub const ERROR_IO: i64 = -5;
/// `spawn_image` refused the image itself: not an ELF64 x86-64 static
/// executable the loader accepts (bad header, truncated, a segment outside
/// the user image window, an entry point outside executable memory).
pub const ERROR_NOT_EXECUTABLE: i64 = -8;
pub const ERROR_BAD_HANDLE: i64 = -9;
pub const ERROR_NO_CHILD: i64 = -10;
pub const ERROR_AGAIN: i64 = -11;
pub const ERROR_NO_MEMORY: i64 = -12;
pub const ERROR_FAULT: i64 = -14;
pub const ERROR_INVALID: i64 = -22;
pub const ERROR_TOO_MANY_HANDLES: i64 = -24;
/// A write to a pipe that no handle can read from any more.
pub const ERROR_PIPE: i64 = -32;
pub const ERROR_NOT_IMPLEMENTED: i64 = -38;
/// No further PID can be represented by the kernel's resource-owner field.
pub const ERROR_PID_EXHAUSTED: i64 = -75;
/// `nic_send` only: the transmit bound expired while the link had no
/// carrier, or a descriptor held that way has not completed and carrier is
/// still absent. The frame was not reported done; the NIC is not disabled
/// (`ERROR_IO` keeps meaning disabled). Linux's `ENETDOWN` value.
pub const ERROR_NO_CARRIER: i64 = -100;
/// A timed wait ended before the awaited event.
pub const ERROR_TIMEOUT: i64 = -110;
/// A conditional transition found the object past the expected version.
pub const ERROR_STALE: i64 = -116;
pub const FRAME_RDI: usize = 10;
pub const FRAME_RSI: usize = 11;
pub const FRAME_RDX: usize = 12;
pub const FRAME_RAX: usize = 14;
pub const FRAME_RIP: usize = 15;

/// `wait` stores this 32-byte record at the caller's supplied address.
pub const OUTCOME_BYTES: usize = 32;
pub const OUTCOME_EXITED: u64 = 1;
pub const OUTCOME_FAULTED: u64 = 2;
pub const OUTCOME_KILLED: u64 = 3;

/// Terminal result of one process, as reported to whoever reaps it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Exited(i32),
    /// Architecture-native exception identity, fault address (CR2/FAR for
    /// memory faults, otherwise the instruction), and native error/syndrome.
    Faulted {
        vector: u64,
        address: u64,
        error: u64,
    },
    /// Ended by its parent's `kill`.
    Killed,
}

/// x86 exception vectors. AArch64 records native exception classes instead;
/// the shared disposition is Faulted, not a promise of equal native metadata.
pub const VECTOR_DIVIDE_ERROR: u64 = 0;
pub const VECTOR_INVALID_OPCODE: u64 = 6;
pub const VECTOR_GENERAL_PROTECTION: u64 = 13;
pub const VECTOR_PAGE_FAULT: u64 = 14;
/// #XM: an unmasked SSE floating-point exception (CR4.OSXMMEXCPT is set).
pub const VECTOR_SIMD_ERROR: u64 = 19;

impl Outcome {
    /// Decodes the record `wait` wrote; `None` for an unknown kind.
    pub fn from_words(words: [u64; 4]) -> Option<Self> {
        match words[0] {
            OUTCOME_EXITED => Some(Self::Exited(words[1] as i32)),
            OUTCOME_FAULTED => Some(Self::Faulted {
                vector: words[1],
                address: words[2],
                error: words[3],
            }),
            OUTCOME_KILLED => Some(Self::Killed),
            _ => None,
        }
    }
    /// Little-endian words: kind, status or vector, fault address, error code.
    pub fn to_bytes(self) -> [u8; OUTCOME_BYTES] {
        let words: [u64; 4] = match self {
            Self::Exited(status) => [OUTCOME_EXITED, status as i64 as u64, 0, 0],
            Self::Faulted {
                vector,
                address,
                error,
            } => [OUTCOME_FAULTED, vector, address, error],
            Self::Killed => [OUTCOME_KILLED, 0, 0, 0],
        };
        let mut bytes = [0u8; OUTCOME_BYTES];
        for (index, word) in words.iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_census_matches_cross_repository_vector() {
        // The platform runtime decodes the same 40-byte vector from its
        // matching resource-census.vector. Qualification compares the two
        // files byte-for-byte before using the paired kernel and userspace.
        assert_eq!(SYS_RESOURCE_CENSUS, 41);
        let record = ResourceCensus {
            processes: 0x0102_0304_0506_0708,
            handles: 0x1112_1314_1516_1718,
            pipes: 0x2122_2324_2526_2728,
            cells: 0x3132_3334_3536_3738,
            frames: 0x4142_4344_4546_4748,
        };
        let encoded = record.to_bytes();
        let hex = include_str!("../resource-census.vector").trim().as_bytes();
        assert_eq!(hex.len(), RESOURCE_CENSUS_BYTES * 2);
        for (index, byte) in encoded.iter().enumerate() {
            let pair = &hex[index * 2..index * 2 + 2];
            let expected = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
            assert_eq!(*byte, expected, "byte {index}");
        }
        assert_eq!(ResourceCensus::from_bytes(encoded), record);
    }

    #[test]
    fn kernel_abi_generation_is_one() {
        // The platform's `absd-release` crate carries the same value and its
        // runtime refuses to start (status 103) when the kernel answers
        // anything else; change both together or not at all.
        assert_eq!(crate::KERNEL_ABI, 1);
    }

    #[test]
    fn public_numbers_and_errors_are_stable() {
        assert_eq!(
            [
                SYS_WRITE,
                SYS_YIELD,
                SYS_EXIT,
                SYS_GETPID,
                SYS_SPAWN,
                SYS_WAIT,
                SYS_MAP,
                SYS_UNMAP,
                SYS_CLOSE,
                SYS_CELL_CREATE,
                SYS_CELL_READ,
                SYS_CELL_TRANSITION,
                SYS_DUPLICATE,
                SYS_CELL_WAIT,
                SYS_READ,
                SYS_PIPE_CREATE,
                SYS_TIME,
                SYS_SLEEP,
                SYS_INFO,
                SYS_KILL,
                SYS_TRANSFER,
                SYS_SPAWN_MANY_COPY,
                SYS_BLOCK_INFO,
                SYS_BLOCK_READ,
                SYS_BLOCK_WRITE,
                SYS_BLOCK_FLUSH,
                SYS_BOOT_ID,
                SYS_WALL_CLOCK,
                SYS_SPAWN_IMAGE,
                SYS_FRAME_STATS,
                SYS_PIPE_INFO,
                SYS_MACHINE_STOP,
                SYS_MACHINE_RESTART,
                SYS_MACHINE_RECOVER,
                SYS_RESOURCE_CENSUS,
                SYS_ABI_VERSION,
                SYS_BLOCK_READ_MANY,
                SYS_BLOCK_WRITE_MANY,
                SYS_FRAME_ADMIT_SELF,
                SYS_SPAWN_RESERVED_COPY
            ],
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24,
                25, 26, 27, 29, 30, 31, 35, 36, 37, 38, 40, 41, 42, 43, 44, 45, 46
            ]
        );
        assert_eq!(
            [
                ERROR_RIGHTS,
                ERROR_NOT_FOUND,
                ERROR_IO,
                ERROR_NOT_EXECUTABLE,
                ERROR_BAD_HANDLE,
                ERROR_NO_CHILD,
                ERROR_AGAIN,
                ERROR_NO_MEMORY,
                ERROR_FAULT,
                ERROR_INVALID,
                ERROR_TOO_MANY_HANDLES,
                ERROR_PIPE,
                ERROR_NOT_IMPLEMENTED,
                ERROR_PID_EXHAUSTED,
                ERROR_NO_CARRIER,
                ERROR_TIMEOUT,
                ERROR_STALE
            ],
            [
                -1, -2, -5, -8, -9, -10, -11, -12, -14, -22, -24, -32, -38, -75, -100, -110, -116
            ]
        );
    }

    #[test]
    fn outcome_records_encode_kind_status_and_fault_words() {
        let exited = Outcome::Exited(-7).to_bytes();
        assert_eq!(&exited[..8], &1u64.to_le_bytes());
        assert_eq!(&exited[8..16], &(-7i64 as u64).to_le_bytes());
        assert_eq!(&exited[16..], &[0u8; 16]);
        let faulted = Outcome::Faulted {
            vector: 14,
            address: 0x10_0000,
            error: 7,
        }
        .to_bytes();
        assert_eq!(&faulted[..8], &2u64.to_le_bytes());
        assert_eq!(&faulted[8..16], &14u64.to_le_bytes());
        assert_eq!(&faulted[16..24], &0x10_0000u64.to_le_bytes());
        assert_eq!(&faulted[24..], &7u64.to_le_bytes());
    }

    #[test]
    fn info_records_round_trip_through_words() {
        let info = ProcessInfo {
            pid: 7,
            parent: 1,
            program: 16,
            state: INFO_STATE_LIVE,
        };
        let bytes = info.to_bytes();
        let mut words = [0u64; 4];
        for (index, word) in words.iter_mut().enumerate() {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
            *word = u64::from_le_bytes(raw);
        }
        assert_eq!(ProcessInfo::from_words(words), info);
    }

    #[test]
    fn spawn_copy_records_are_fixed_size_and_preserve_ordered_fields() {
        assert_eq!(
            [RIGHT_WRITE, RIGHT_WAIT, RIGHT_READ, RIGHT_KILL],
            [1, 2, 4, 8]
        );
        assert_eq!(
            core::mem::size_of::<SpawnHandleCopy>(),
            SPAWN_HANDLE_COPY_BYTES
        );
        assert_eq!(
            SpawnHandleCopy::from_words([7, RIGHT_READ, SPAWN_HANDLE_COPY_CONSOLE]),
            SpawnHandleCopy::console(7, RIGHT_READ)
        );
        assert_eq!(SpawnHandleCopy::new(9, RIGHT_WRITE).flags, 0);
    }

    #[test]
    fn pipe_info_records_round_trip() {
        let info = PipeInfo {
            available: 3,
            space: 1021,
            readers: 1,
            writers: 2,
        };
        let bytes = info.to_bytes();
        assert_eq!(&bytes[..8], &3u64.to_le_bytes());
        assert_eq!(&bytes[24..], &2u64.to_le_bytes());
        assert_eq!(PipeInfo::from_bytes(bytes), info);
    }

    #[test]
    fn outcome_records_round_trip_through_words() {
        for outcome in [
            Outcome::Exited(7),
            Outcome::Exited(-1),
            Outcome::Killed,
            Outcome::Faulted {
                vector: 6,
                address: 0x10_0000,
                error: 7,
            },
        ] {
            let bytes = outcome.to_bytes();
            let mut words = [0u64; 4];
            for (index, word) in words.iter_mut().enumerate() {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
                *word = u64::from_le_bytes(raw);
            }
            assert_eq!(Outcome::from_words(words), Some(outcome));
        }
        assert_eq!(Outcome::from_words([9, 0, 0, 0]), None);
    }
}

/// Fixed PID-owned frame admission, available only to bootstrap init before READY.
pub const SYS_FRAME_ADMIT_SELF: u64 = 45;
pub const SYS_SPAWN_RESERVED_COPY: u64 = 46;
pub const MAX_FRAME_ADMISSION_FRAMES: u64 = 65536;
pub const SPAWN_RESERVED_REQUEST_BYTES: usize = 32;
pub const SPAWN_RESERVED_PROGRAM_OFFSET: usize = 0;
pub const SPAWN_RESERVED_COPIES_OFFSET: usize = 8;
pub const SPAWN_RESERVED_COUNT_OFFSET: usize = 16;
pub const SPAWN_RESERVED_TOTAL_OFFSET: usize = 24;

/// Explicit little-endian wire record, independent of Rust layout/alignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpawnReservedRequest {
    pub program_and_flags: u64,
    pub copies_address: u64,
    pub copies_count: u64,
    pub total_frames: u64,
}
impl SpawnReservedRequest {
    pub fn to_bytes(self) -> [u8; SPAWN_RESERVED_REQUEST_BYTES] {
        let mut bytes = [0; SPAWN_RESERVED_REQUEST_BYTES];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip([
            self.program_and_flags,
            self.copies_address,
            self.copies_count,
            self.total_frames,
        ]) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
    pub fn from_bytes(bytes: &[u8; SPAWN_RESERVED_REQUEST_BYTES]) -> Self {
        let mut words = [0; 4];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0.iter()) {
            *word = u64::from_le_bytes(*chunk);
        }
        Self {
            program_and_flags: words[0],
            copies_address: words[1],
            copies_count: words[2],
            total_frames: words[3],
        }
    }
}
#[cfg(test)]
mod frame_wire_tests {
    use super::*;
    #[test]
    fn reserved_request_is_four_little_endian_words() {
        let raw = core::array::from_fn(|i| i as u8);
        let request = SpawnReservedRequest::from_bytes(&raw);
        assert_eq!(request.program_and_flags, 0x0706050403020100);
        assert_eq!(request.copies_address, 0x0f0e0d0c0b0a0908);
        assert_eq!(request.copies_count, 0x1716151413121110);
        assert_eq!(request.total_frames, 0x1f1e1d1c1b1a1918);
        assert_eq!(request.to_bytes(), raw);
        assert_eq!(
            [
                SYS_FRAME_ADMIT_SELF,
                SYS_SPAWN_RESERVED_COPY,
                MAX_FRAME_ADMISSION_FRAMES
            ],
            [45, 46, 65536]
        );
    }
}
