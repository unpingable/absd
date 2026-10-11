//! What `std::fs` reaches on ABSD: the file server when the process holds
//! a channel to one (`crate::fsd`), else the mounted ABSD filesystem when a
//! program mounts it, otherwise the one-name `ledger` append region.
//!
//! The filesystem is a library linked into this process and owns the
//! layout's filesystem region through the block handle init gave it. Init
//! hands that handle to one process at a time, so this process's memory is
//! the complete lock and open-handle state; nothing volatile is persisted.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use absd_fs::{Attr, Device, Error, Fs, Kind, OpenFlags, SECTOR};

use crate::cwd::resolve;
use crate::layout::{self, Layout, Region};
use crate::{BLOCK, ledger};

/// One layout region as a filesystem device. Every access is bounded by
/// the region before the kernel sees it.
pub struct RegionDevice {
    block: u64,
    region: Region,
}

static WRITES: AtomicU64 = AtomicU64::new(0);
static STOP_AT: AtomicU64 = AtomicU64::new(0);
static STOP_CODE: AtomicU64 = AtomicU64::new(0);
/// Zero: the trigger stops the machine. Nonzero: only this process exits
/// with that status (the kernel, init, and the device carry on).
static EXIT_STATUS: AtomicU64 = AtomicU64::new(0);

/// Sector writes this process has issued to the filesystem region.
pub fn device_writes() -> u64 {
    WRITES.load(Ordering::Relaxed)
}

/// Stops the machine immediately before the filesystem's write number
/// `count + 1` (so exactly `count` more writes are acknowledged): the crash
/// matrix enumerates every point of an operation with this.
pub fn stop_after_writes(count: u64, code: u64) {
    STOP_CODE.store(code, Ordering::Relaxed);
    EXIT_STATUS.store(0, Ordering::Relaxed);
    STOP_AT.store(device_writes() + count + 1, Ordering::Relaxed);
}

/// As [`stop_after_writes`], but only this process dies (with `status`):
/// its memory, locks, and open handles vanish while the machine runs on.
pub fn exit_after_writes(count: u64, status: u64) {
    EXIT_STATUS.store(status, Ordering::Relaxed);
    STOP_AT.store(device_writes() + count + 1, Ordering::Relaxed);
}

static FLUSHES: AtomicU64 = AtomicU64::new(0);
/// `WRITES` when the last flush completed.
static FLUSHED_AT: AtomicU64 = AtomicU64::new(0);
static FAIL_FLUSH_AT: AtomicU64 = AtomicU64::new(0);

/// Flushes this process has issued (or failed) on the filesystem region.
pub fn device_flushes() -> u64 {
    FLUSHES.load(Ordering::Relaxed)
}

/// The filesystem flush number `count` from now fails as a device error
/// without reaching the device: the device law then promises nothing
/// about the writes it would have covered.
pub fn fail_flush(count: u64) {
    FAIL_FLUSH_AT.store(device_flushes() + count, Ordering::Relaxed);
}

/// Whether the mounted filesystem stopped after a device failure.
pub fn poisoned() -> bool {
    with_fs(|fs| fs.poisoned()).unwrap_or(false)
}

pub fn disarm() {
    STOP_AT.store(0, Ordering::Relaxed);
}

/// The power-loss device law (`docs/POWER-LOSS.md`) applied below the
/// filesystem. While armed, every write becomes a new image of its aligned
/// unit of `unit` sectors (the unit's device content is read first, so the
/// state at arming counts as stable); a completed flush makes every unit
/// stable and forgets the images. The cut resolves each unit written since
/// the last completed flush to one of its images by `seed`: 0 keeps the
/// stable image (every unflushed write lost), 1 the latest (nothing lost),
/// any other seed chooses per unit by xorshift. The chosen images are
/// written raw, flushed, and the machine stops with `code`.
struct PowerCut {
    unit: u64,
    seed: u64,
    /// The write number the cut precedes (`at_flush` false), or the write
    /// count after which the next flush is cut instead of completing.
    at: u64,
    at_flush: bool,
    code: u64,
    /// Region-relative unit -> its images: the stable one, then one per write.
    history: BTreeMap<u64, Vec<Vec<[u8; SECTOR]>>>,
}

struct CutSlot(UnsafeCell<Option<PowerCut>>);
// Single-threaded process; the device hooks never re-enter.
unsafe impl Sync for CutSlot {}
static POWER_CUT: CutSlot = CutSlot(UnsafeCell::new(None));

fn power_cut() -> &'static mut Option<PowerCut> {
    unsafe { &mut *POWER_CUT.0.get() }
}

/// Arms a power cut after `count` more filesystem writes (before write
/// `count + 1`), or, with `at_flush`, at the first flush issued after them
/// (the flush never completes). Replaces any armed machine stop.
pub fn arm_power_cut(count: u64, unit: u64, seed: u64, at_flush: bool, code: u64) {
    // The model takes the device state at arming as stable, which is true
    // only right after a completed flush.
    assert_eq!(
        FLUSHED_AT.load(Ordering::Relaxed),
        device_writes(),
        "power cut armed with unflushed writes"
    );
    disarm();
    *power_cut() = Some(PowerCut {
        unit: unit.max(1),
        seed,
        at: device_writes() + count + 1,
        at_flush,
        code,
        history: BTreeMap::new(),
    });
}

fn code(result: i64) -> Error {
    Error::Device(result)
}

impl RegionDevice {
    fn unit_image(&self, cut: &PowerCut, unit: u64) -> Result<Vec<[u8; SECTOR]>, Error> {
        let mut image = vec![[0u8; SECTOR]; cut.unit as usize];
        for (k, sector) in image.iter_mut().enumerate() {
            let lba = unit * cut.unit + k as u64;
            if lba < self.region.sectors {
                layout::read_raw(self.block, self.region.first + lba, sector).map_err(code)?;
            }
        }
        Ok(image)
    }

    fn record(&self, cut: &mut PowerCut, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        let unit = sector / cut.unit;
        if !cut.history.contains_key(&unit) {
            let stable = self.unit_image(cut, unit)?;
            cut.history.insert(unit, vec![stable]);
        }
        let history = cut.history.get_mut(&unit).unwrap();
        let mut image = history.last().unwrap().clone();
        image[(sector % cut.unit) as usize] = *buffer;
        history.push(image);
        Ok(())
    }

    /// Resolves every dirty unit by the policy, makes the result stable,
    /// and stops the machine.
    fn perform_cut(&self, cut: PowerCut) -> ! {
        let mut state = cut.seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        for (unit, images) in &cut.history {
            let pick = match cut.seed {
                0 => 0,
                1 => images.len() - 1,
                _ => {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state % images.len() as u64) as usize
                }
            };
            for (k, sector) in images[pick].iter().enumerate() {
                let lba = unit * cut.unit + k as u64;
                if lba < self.region.sectors {
                    let _ = layout::write_raw(self.block, self.region.first + lba, sector);
                }
            }
        }
        let _ = layout::flush(self.block);
        crate::stop(cut.code);
        crate::__absd_std_exit(cut.code as i32)
    }
}

// Every whole-block run the library issues must fit one kernel request.
const _: () = assert!(absd_fs::MAX_RUN_SECTORS <= layout::MAX_RUN_SECTORS);

impl RegionDevice {
    /// Region-relative `sector` for `bytes` of run, or the span is refused.
    fn span(&self, sector: u64, bytes: usize) -> Result<(), Error> {
        let sectors = (bytes / SECTOR) as u64;
        if bytes == 0 || !bytes.is_multiple_of(SECTOR) || sectors > layout::MAX_RUN_SECTORS {
            return Err(Error::Invalid);
        }
        match sector.checked_add(sectors) {
            Some(end) if end <= self.region.sectors => Ok(()),
            _ => Err(Error::Invalid),
        }
    }
}

impl Device for RegionDevice {
    fn sectors(&self) -> u64 {
        self.region.sectors
    }

    fn read_run(&mut self, sector: u64, buffer: &mut [u8]) -> Result<(), Error> {
        self.span(sector, buffer.len())?;
        layout::read_run_raw(self.block, self.region.first + sector, buffer).map_err(code)
    }

    /// One kernel request for the whole run, unless an armed machine stop,
    /// process exit, or power cut falls inside it: then the run goes sector
    /// by sector through `write`, so every trigger still fires exactly
    /// before the write it was armed for and the crash sweeps keep their
    /// sector-granular points. A power cut's history records each sector
    /// of the run separately, so the cut resolves each unit of it on its
    /// own, as for single writes. The count and the history are advanced
    /// for the whole run before the request: after a device error the
    /// count may exceed the sectors the device took, which only a poisoned
    /// mount ever observes (the matrices inject no write errors).
    fn write_run(&mut self, sector: u64, buffer: &[u8]) -> Result<(), Error> {
        self.span(sector, buffer.len())?;
        let sectors = (buffer.len() / SECTOR) as u64;
        let base = WRITES.load(Ordering::Relaxed);
        let inside = |at: u64| at > base && at <= base + sectors;
        let stop_inside = inside(STOP_AT.load(Ordering::Relaxed));
        let cut_inside = power_cut().as_ref().is_some_and(|cut| !cut.at_flush && inside(cut.at));
        if stop_inside || cut_inside {
            for (index, chunk) in buffer.chunks_exact(SECTOR).enumerate() {
                self.write(sector + index as u64, chunk.try_into().unwrap())?;
            }
            return Ok(());
        }
        WRITES.fetch_add(sectors, Ordering::Relaxed);
        if let Some(cut) = power_cut() {
            for (index, chunk) in buffer.chunks_exact(SECTOR).enumerate() {
                self.record(cut, sector + index as u64, chunk.try_into().unwrap())?;
            }
        }
        layout::write_run_raw(self.block, self.region.first + sector, buffer).map_err(code)
    }

    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        if sector >= self.region.sectors {
            return Err(Error::Invalid);
        }
        layout::read_raw(self.block, self.region.first + sector, buffer).map_err(code)
    }

    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        if sector >= self.region.sectors {
            return Err(Error::Invalid);
        }
        let number = WRITES.fetch_add(1, Ordering::Relaxed) + 1;
        if STOP_AT.load(Ordering::Relaxed) == number {
            match EXIT_STATUS.load(Ordering::Relaxed) {
                0 => {
                    crate::stop(STOP_CODE.load(Ordering::Relaxed));
                }
                status => crate::__absd_std_exit(status as i32),
            }
        }
        if let Some(cut) = power_cut() {
            if number >= cut.at && !cut.at_flush {
                let cut = power_cut().take().unwrap();
                self.perform_cut(cut);
            }
            self.record(cut, sector, buffer)?;
        }
        layout::write_raw(self.block, self.region.first + sector, buffer).map_err(code)
    }

    fn flush(&mut self) -> Result<(), Error> {
        let number = FLUSHES.fetch_add(1, Ordering::Relaxed) + 1;
        if FAIL_FLUSH_AT.load(Ordering::Relaxed) == number {
            return Err(Error::Device(-5));
        }
        if let Some(cut) = power_cut() {
            if cut.at_flush && device_writes() + 1 >= cut.at {
                let cut = power_cut().take().unwrap();
                self.perform_cut(cut);
            }
        }
        layout::flush(self.block).map_err(code)?;
        FLUSHED_AT.store(device_writes(), Ordering::Relaxed);
        if let Some(cut) = power_cut() {
            cut.history.clear();
        }
        Ok(())
    }
}

enum Backend {
    None,
    Ledger(ledger::Ledger),
    Fs(Fs<RegionDevice>),
}

struct Slot(UnsafeCell<Backend>);
// ABSD runs this process single-threaded and the hooks never re-enter.
unsafe impl Sync for Slot {}
static BACKEND: Slot = Slot(UnsafeCell::new(Backend::None));

fn backend() -> &'static mut Backend {
    unsafe { &mut *BACKEND.0.get() }
}

/// The mounted filesystem, for direct users (the SQLite VFS).
pub fn with_fs<R>(f: impl FnOnce(&mut Fs<RegionDevice>) -> R) -> Option<R> {
    match backend() {
        Backend::Fs(fs) => Some(f(fs)),
        _ => None,
    }
}

pub fn errno(error: Error) -> i64 {
    match error {
        Error::NotFound => -2,
        Error::Exists => -17,
        Error::NotDir => -20,
        Error::IsDir => -21,
        Error::NotEmpty => -39,
        Error::NoSpace => -28,
        Error::ReadOnlyFs => -30,
        Error::Denied => -13,
        Error::Invalid => -22,
        Error::WouldBlock => -11,
        Error::BadHandle => -9,
        Error::Device(-1) => -1,
        Error::Device(_) => -5,
        Error::Poisoned => -116,
        Error::Unformatted => -2,
        Error::NotBlank => -17,
        Error::Corrupt(_) => -74,
        Error::UnsupportedFormat => -95,
    }
}

fn rdrand() -> u64 {
    let mut value = 0u64;
    for _ in 0..64 {
        if unsafe { core::arch::x86_64::_rdrand64_step(&mut value) } == 1 && value != 0 {
            return value;
        }
    }
    // The runner pins a CPU with RDRAND; without it the identity would not
    // be random, so refuse to invent one.
    crate::__absd_std_exit(104)
}

#[derive(Clone, Copy, Debug)]
pub struct Mounted {
    pub formatted: bool,
    pub fs_id: u64,
    pub sequence: u64,
}

/// Mounts the layout's filesystem region. `format` permits formatting a
/// blank device and a blank region; `writable` says whether this mount may
/// write (a read-only mount refuses every mutation).
pub fn mount(format: bool, writable: bool) -> Result<Mounted, Error> {
    mount_handle(BLOCK.load(Ordering::Relaxed), format, writable)
}

/// Takes the filesystem [`mount`] mounted out of `std::fs`'s reach, for a
/// process that serves it to others (the file server): afterwards this
/// process's own `std::fs` has no filesystem.
pub fn take_mounted() -> Option<Fs<RegionDevice>> {
    match core::mem::replace(backend(), Backend::None) {
        Backend::Fs(fs) => Some(fs),
        other => {
            *backend() = other;
            None
        }
    }
}

/// Mounts through a read-only duplicate of the block handle: the kernel,
/// not only this library, then refuses every write this process issues.
/// (A read-only mount; the name predates the terminology in the kernel's
/// `docs/TERMINOLOGY.md` and is kept because patched applications call it.)
pub fn mount_read_only_authority() -> Result<(Mounted, u64), Error> {
    let block = BLOCK.load(Ordering::Relaxed);
    let reader = crate::duplicate(block, crate::RIGHT_READ).map_err(Error::Device)?;
    Ok((mount_handle(reader, false, false)?, reader))
}

/// Gives up write access for the rest of this process: mounts the
/// filesystem read-only through a read-only duplicate of the block handle,
/// makes that duplicate this process's block handle (so children started
/// later get views of it), and closes the writable handle. Returns the
/// mount and the handle; afterwards the kernel refuses every write.
pub fn relinquish_write() -> Result<(Mounted, u64), Error> {
    let block = BLOCK.load(Ordering::Relaxed);
    let reader = crate::duplicate(block, crate::RIGHT_READ).map_err(Error::Device)?;
    let mounted = mount_handle(reader, false, false)?;
    BLOCK.store(reader, Ordering::Relaxed);
    crate::close(block).map_err(Error::Device)?;
    Ok((mounted, reader))
}

fn mount_handle(block: u64, format: bool, writable: bool) -> Result<Mounted, Error> {
    if block == 0 {
        return Err(Error::NotFound);
    }
    let mut device_scanned = false;
    let layout = match Layout::open(block) {
        Ok(layout) => layout,
        Err(layout::UNFORMATTED) if format => {
            // Layout format reads every sector of the device and refuses
            // any nonzero byte, so the filesystem region is known blank.
            device_scanned = true;
            Layout::format(block).map_err(code)?
        }
        Err(layout::UNFORMATTED) => return Err(Error::Unformatted),
        Err(other) => return Err(Error::Device(other)),
    };
    let region = layout.first_of_kind(layout::KIND_FS).ok_or(Error::NotFound)?;
    let device = || RegionDevice { block, region };
    let mut formatted = false;
    let fs = match Fs::mount(device(), writable) {
        Err(Error::Unformatted) if format => {
            if device_scanned {
                absd_fs::format_verified_blank(&mut device(), rdrand())?;
            } else {
                absd_fs::format(&mut device(), rdrand())?;
            }
            formatted = true;
            Fs::mount(device(), writable)?
        }
        other => other?,
    };
    let mounted = Mounted { formatted, fs_id: fs.fs_id(), sequence: fs.sequence() };
    *backend() = Backend::Fs(fs);
    Ok(mounted)
}

/// Mounts the filesystem read-only through `handle`, a block handle the
/// startup record gave this process for exactly that (role `FS`). A mount
/// that fails leaves the process unmounted: `std::fs` then reports
/// not-found, as for a process without a filesystem.
pub(crate) fn mount_view(handle: u64) -> Result<Mounted, Error> {
    mount_handle(handle, false, false)
}

/// The kind of the object at `path` (already resolved): `None` when this
/// process has no filesystem at all.
pub(crate) fn stat_kind(path: &[u8]) -> Option<Result<Kind, i64>> {
    if crate::fsd::active() {
        return Some(crate::fsd::stat(path).map(|attr| {
            if crate::fsd::kind(&attr) == 2 { Kind::Dir } else { Kind::File }
        }));
    }
    with_fs(|fs| fs.stat(path).map(|attr| attr.kind).map_err(errno))
}

/// The whole content of the regular file at `path` (resolved against the
/// working directory) on the mounted filesystem, refusing anything longer
/// than `limit` bytes before reading it.
pub(crate) fn read_file(path: &[u8], limit: u64) -> Result<Vec<u8>, i64> {
    let mut bytes = Vec::new();
    read_file_into(path, limit, &mut bytes)?;
    Ok(bytes)
}

/// [`read_file`] into `bytes`, which is cleared first and keeps its
/// capacity: a caller that reads many files of a size (a parent reading
/// program images) reuses one allocation instead of mapping and freeing
/// an image-sized block each time.
pub(crate) fn read_file_into(path: &[u8], limit: u64, bytes: &mut Vec<u8>) -> Result<(), i64> {
    bytes.clear();
    if crate::fsd::active() {
        return crate::fsd::read_file_into(&resolve(path), limit, bytes);
    }
    let Backend::Fs(fs) = backend() else { return Err(-2) };
    let path = resolve(path);
    let attr = fs.stat(&path).map_err(errno)?;
    if !matches!(attr.kind, Kind::File) {
        return Err(-21);
    }
    if attr.size > limit {
        return Err(-27);
    }
    let flags = OpenFlags { read: true, write: false, create: false, create_new: false, truncate: false };
    let handle = fs.open(&path, flags).map_err(errno)?;
    bytes.resize(attr.size as usize, 0);
    let mut filled = 0usize;
    let outcome = loop {
        if filled == bytes.len() {
            break Ok(());
        }
        match fs.read_at(handle, filled as u64, &mut bytes[filled..]) {
            Ok(0) => break Err(-5),
            Ok(count) => filled += count,
            Err(error) => break Err(errno(error)),
        }
    };
    let _ = fs.close(handle);
    if outcome.is_err() {
        bytes.clear();
    }
    outcome
}

/// Checks the committed filesystem state without mounting it.
pub fn inspect() -> Result<(u64, u64, usize), Error> {
    let block = BLOCK.load(Ordering::Relaxed);
    let layout = Layout::open(block).map_err(code)?;
    let region = layout.first_of_kind(layout::KIND_FS).ok_or(Error::NotFound)?;
    absd_fs::inspect(&mut RegionDevice { block, region })
}

const LEDGER_FILE: u64 = 1 << 62;
const LEDGER_DIR: u64 = (1 << 62) + 1;
const LEDGER_NAME: &[u8] = b"ledger";

fn ledger_open(create_new: bool) -> Result<&'static mut ledger::Ledger, i64> {
    let block = BLOCK.load(Ordering::Relaxed);
    if block == 0 {
        return Err(-2);
    }
    if let Backend::None = backend() {
        // A brand-new journal on an unformatted device formats the layout;
        // every other open only reads it, so recovery stays read-only.
        let layout = match Layout::open(block) {
            Ok(layout) => layout,
            Err(layout::UNFORMATTED) if create_new => Layout::format(block)?,
            Err(code) => return Err(code),
        };
        let region = layout.first_of_kind(layout::KIND_LEDGER).ok_or(-2i64)?;
        *backend() = Backend::Ledger(ledger::Ledger::open(block, layout, region)?);
    }
    match backend() {
        Backend::Ledger(opened) => Ok(opened),
        _ => Err(-2),
    }
}

fn ledger() -> Result<&'static mut ledger::Ledger, i64> {
    match backend() {
        Backend::Ledger(opened) => Ok(opened),
        _ => Err(-2),
    }
}

fn result(outcome: Result<(), Error>) -> i64 {
    match outcome {
        Ok(()) => 0,
        Err(error) => errno(error),
    }
}

unsafe fn slice<'a>(bytes: *const u8, length: usize) -> &'a [u8] {
    if length == 0 { &[] } else { unsafe { core::slice::from_raw_parts(bytes, length) } }
}

#[repr(C)]
pub struct RawAttr {
    kind: u32,
    readonly: u32,
    size: u64,
    filesystem: u64,
    serial: u64,
    links: u64,
}

fn fill(out: *mut RawAttr, attr: Attr) {
    let raw = RawAttr {
        kind: match attr.kind {
            Kind::File => 1,
            Kind::Dir => 2,
        },
        readonly: u32::from(attr.readonly),
        size: attr.size,
        filesystem: attr.fs_id,
        serial: attr.serial,
        links: u64::from(attr.links),
    };
    unsafe { out.write(raw) };
}

fn ledger_attr(out: *mut RawAttr, directory: bool, size: u64) {
    unsafe {
        out.write(RawAttr { kind: if directory { 2 } else { 1 }, readonly: 0, size, filesystem: 0, serial: 0, links: 1 })
    };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_open(path: *const u8, length: usize, flags: u32) -> i64 {
    let path = unsafe { slice(path, length) };
    let raw_flags = flags;
    let flags = OpenFlags {
        read: flags & 1 != 0,
        write: flags & 2 != 0,
        create: flags & 8 != 0,
        create_new: flags & 16 != 0,
        truncate: flags & 32 != 0,
    };
    if crate::fsd::active() {
        return crate::fsd::open(&resolve(path), raw_flags);
    }
    if let Backend::Fs(fs) = backend() {
        return match fs.open(&resolve(path), flags) {
            Ok(handle) => handle as i64,
            Err(error) => errno(error),
        };
    }
    match path {
        LEDGER_NAME => {
            if flags.truncate {
                return -95;
            }
            match ledger_open(flags.create_new) {
                Ok(opened) if flags.create_new && opened.len() != 0 => -17,
                Ok(_) => LEDGER_FILE as i64,
                Err(code) => code,
            }
        }
        b"" | b"." => {
            if flags.write || flags.truncate || flags.create_new {
                -22
            } else {
                LEDGER_DIR as i64
            }
        }
        _ => -2,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_fs_close(handle: u64) -> i64 {
    if crate::fsd::active() {
        return crate::fsd::close(handle);
    }
    match backend() {
        Backend::Fs(fs) => result(fs.close(handle)),
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_read_at(handle: u64, offset: u64, bytes: *mut u8, length: usize) -> isize {
    let buffer = unsafe { core::slice::from_raw_parts_mut(bytes, length) };
    if crate::fsd::active() {
        return crate::fsd::read_at(handle, offset, buffer);
    }
    let outcome = match backend() {
        Backend::Fs(fs) => fs.read_at(handle, offset, buffer).map_err(errno),
        _ if handle == LEDGER_FILE => ledger().and_then(|opened| opened.read_at(offset, buffer).map(|count| count as usize)),
        _ => Err(-21),
    };
    match outcome {
        Ok(count) => count as isize,
        Err(code) => code as isize,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_write_at(handle: u64, offset: u64, bytes: *const u8, length: usize) -> isize {
    let data = unsafe { slice(bytes, length) };
    if crate::fsd::active() {
        return crate::fsd::write_at(handle, offset, data);
    }
    let outcome = match backend() {
        Backend::Fs(fs) => fs.write_at(handle, offset, data).map_err(errno),
        _ if handle == LEDGER_FILE => ledger().and_then(|opened| {
            // The region only grows at its end.
            if offset != opened.len() {
                return Err(-22);
            }
            opened.append(data).map(|()| data.len())
        }),
        _ => Err(-21),
    };
    match outcome {
        Ok(count) => count as isize,
        Err(code) => code as isize,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_fs_set_len(handle: u64, length: u64) -> i64 {
    if crate::fsd::active() {
        return crate::fsd::set_len(handle, length);
    }
    match backend() {
        Backend::Fs(fs) => result(fs.set_len(handle, length)),
        _ => -95,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_fs_sync(handle: u64) -> i64 {
    if crate::fsd::active() {
        return crate::fsd::sync(handle);
    }
    match backend() {
        Backend::Fs(fs) => result(fs.sync()),
        Backend::Ledger(opened) => match opened.flush() {
            Ok(()) => 0,
            Err(code) => code,
        },
        Backend::None => -2,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_fstat(handle: u64, out: *mut RawAttr) -> i64 {
    if crate::fsd::active() {
        return remote_attr(crate::fsd::fstat(handle), out);
    }
    match backend() {
        Backend::Fs(fs) => match fs.fstat(handle) {
            Ok(attr) => {
                fill(out, attr);
                0
            }
            Err(error) => errno(error),
        },
        Backend::Ledger(opened) if handle == LEDGER_FILE => {
            ledger_attr(out, false, opened.len());
            0
        }
        _ if handle == LEDGER_DIR => {
            ledger_attr(out, true, 0);
            0
        }
        _ => -9,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_stat(path: *const u8, length: usize, out: *mut RawAttr) -> i64 {
    let path = unsafe { slice(path, length) };
    if crate::fsd::active() {
        return remote_attr(crate::fsd::stat(&resolve(path)), out);
    }
    match backend() {
        Backend::Fs(fs) => match fs.stat(&resolve(path)) {
            Ok(attr) => {
                fill(out, attr);
                0
            }
            Err(error) => errno(error),
        },
        _ => match path {
            LEDGER_NAME => match ledger() {
                Ok(opened) => {
                    ledger_attr(out, false, opened.len());
                    0
                }
                Err(code) => code,
            },
            b"" | b"." => {
                ledger_attr(out, true, 0);
                0
            }
            _ => -2,
        },
    }
}

/// A file server's attribute record, whose first 40 bytes have `RawAttr`'s
/// layout; the `mtime` word after them does not reach `std` yet.
fn remote_attr(attr: Result<[u8; absd_fsd::proto::ATTR_BYTES], i64>, out: *mut RawAttr) -> i64 {
    match attr {
        Ok(bytes) => {
            let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
            let half = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let raw = RawAttr {
                kind: half(0),
                readonly: half(4),
                size: word(8),
                filesystem: word(16),
                serial: word(24),
                links: word(32),
            };
            unsafe { out.write(raw) };
            0
        }
        Err(code) => code,
    }
}

fn with_mounted(f: impl FnOnce(&mut Fs<RegionDevice>) -> Result<(), Error>) -> i64 {
    match backend() {
        Backend::Fs(fs) => result(f(fs)),
        _ => -95,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_fs_set_readonly(handle: u64, readonly: u32) -> i64 {
    if crate::fsd::active() {
        return crate::fsd::set_readonly(handle, readonly != 0);
    }
    with_mounted(|fs| fs.set_readonly(handle, readonly != 0))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_set_readonly_path(path: *const u8, length: usize, readonly: u32) -> i64 {
    let path = unsafe { slice(path, length) };
    if crate::fsd::active() {
        return crate::fsd::set_readonly_path(&resolve(path), readonly != 0);
    }
    with_mounted(|fs| fs.set_readonly_path(&resolve(path), readonly != 0))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_mkdir(path: *const u8, length: usize) -> i64 {
    let path = unsafe { slice(path, length) };
    if crate::fsd::active() {
        return crate::fsd::path_op(absd_fsd::proto::op::MKDIR, &resolve(path));
    }
    with_mounted(|fs| fs.mkdir(&resolve(path)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_rmdir(path: *const u8, length: usize) -> i64 {
    let path = unsafe { slice(path, length) };
    if crate::fsd::active() {
        return crate::fsd::path_op(absd_fsd::proto::op::RMDIR, &resolve(path));
    }
    with_mounted(|fs| fs.rmdir(&resolve(path)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_unlink(path: *const u8, length: usize) -> i64 {
    let path = unsafe { slice(path, length) };
    if crate::fsd::active() {
        return crate::fsd::path_op(absd_fsd::proto::op::UNLINK, &resolve(path));
    }
    with_mounted(|fs| fs.unlink(&resolve(path)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_rename(
    from: *const u8,
    from_length: usize,
    to: *const u8,
    to_length: usize,
    noreplace: u32,
) -> i64 {
    let (from, to) = unsafe { (slice(from, from_length), slice(to, to_length)) };
    if crate::fsd::active() {
        return crate::fsd::rename(&resolve(from), &resolve(to), noreplace != 0);
    }
    with_mounted(|fs| fs.rename(&resolve(from), &resolve(to), noreplace != 0))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_readdir(
    path: *const u8,
    length: usize,
    index: u64,
    name: *mut u8,
    capacity: usize,
    out: *mut RawAttr,
) -> isize {
    let path = unsafe { slice(path, length) };
    if crate::fsd::active() {
        return match crate::fsd::read_dir_entry(&resolve(path), index) {
            Ok(Some((entry, attr))) => {
                if entry.len() > capacity {
                    return -22;
                }
                unsafe { core::ptr::copy_nonoverlapping(entry.as_ptr(), name, entry.len()) };
                remote_attr(Ok(attr), out);
                entry.len() as isize
            }
            Ok(None) => 0,
            Err(code) => code as isize,
        };
    }
    let Backend::Fs(fs) = backend() else { return -95 };
    let entries: Vec<_> = match fs.read_dir(&resolve(path)) {
        Ok(entries) => entries,
        Err(error) => return errno(error) as isize,
    };
    let Some((entry, attr)) = entries.get(index as usize) else { return 0 };
    if entry.len() > capacity {
        return -22;
    }
    unsafe { core::ptr::copy_nonoverlapping(entry.as_ptr(), name, entry.len()) };
    fill(out, *attr);
    entry.len() as isize
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_std_fs_canonical(path: *const u8, length: usize, out: *mut u8, capacity: usize) -> isize {
    let path = unsafe { slice(path, length) };
    if crate::fsd::active() {
        return match crate::fsd::canonical(&resolve(path)) {
            Ok(canonical) if canonical.len() <= capacity => {
                unsafe { core::ptr::copy_nonoverlapping(canonical.as_ptr(), out, canonical.len()) };
                canonical.len() as isize
            }
            Ok(_) => -22,
            Err(code) => code as isize,
        };
    }
    let Backend::Fs(fs) = backend() else { return -95 };
    match fs.canonical(&resolve(path)) {
        Ok(canonical) if canonical.len() <= capacity => {
            unsafe { core::ptr::copy_nonoverlapping(canonical.as_ptr(), out, canonical.len()) };
            canonical.len() as isize
        }
        Ok(_) => -22,
        Err(error) => errno(error) as isize,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __absd_std_fs_lock(handle: u64, mode: u32) -> i64 {
    if crate::fsd::active() {
        return crate::fsd::lock(handle, mode);
    }
    with_mounted(|fs| match mode {
        0 => fs.unlock(handle),
        1 => fs.try_lock(handle, false),
        2 => fs.try_lock(handle, true),
        _ => Err(Error::Invalid),
    })
}
