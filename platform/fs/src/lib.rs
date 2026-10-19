//! Experimental ABSD filesystem: the durable naming, identity, installation,
//! and sync semantics one real workload (SQLite in WAL mode under AG's store)
//! demands, over one bounded region, entirely in userspace.
//!
//! Durability model: every namespace operation (create, mkdir, unlink,
//! rmdir, tree removal, rename, rename-no-clobber, read-only change)
//! commits a new whole metadata image before it returns. File data is
//! written through in place; size and block-map changes become durable at
//! the next commit, which any `sync` of any object performs. The single
//! linearization and durability point of a commit is one superblock sector
//! write. Mount never rolls back: it uses the newest superblock or refuses.
//!
//! Identity: an object is `(fs_id, serial)`. Serials are allocated from a
//! persisted counter and never reused, so a replacement object can never
//! validate as the object it replaced, whatever storage it lands on.
//!
//! Locks and open handles are volatile process state and are never written.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod image;
#[cfg(test)]
mod tests;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

pub use image::{BLOCK, Geometry, MAX_NAME, OBJECT_BUDGET};
use image::{
    HEADER_BYTES, Image, ROOT, Record, SECTORS_PER_BLOCK, Superblock, record_bytes, sha256,
    valid_name,
};

pub const SECTOR: usize = 512;
/// Largest run a device sees in one `read_run`/`write_run`: one block, the
/// unit every data address and both metadata halves are laid out in.
pub const MAX_RUN_SECTORS: u64 = SECTORS_PER_BLOCK;
const MAX_RUN_BYTES: usize = MAX_RUN_SECTORS as usize * SECTOR;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    File,
    Dir,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    NoSpace,
    /// The mount has no write authority.
    ReadOnlyFs,
    /// The object is read-only or the handle lacks the access.
    Denied,
    Invalid,
    WouldBlock,
    BadHandle,
    Device(i64),
    /// An earlier device failure left memory ahead of the device.
    Poisoned,
    Unformatted,
    /// Format found bytes it would destroy.
    NotBlank,
    Corrupt(&'static str),
    /// The region holds a filesystem of another format version. It is
    /// never read, repaired, or formatted over; a host-side migration
    /// (`docs/FILESYSTEM.md`, "Format 2") is the only way forward.
    UnsupportedFormat,
}

/// One bounded run of 512-byte sectors, addressed from zero. Writes are
/// acknowledged in issue order; `flush` is the device barrier.
///
/// The run methods move `1..=MAX_RUN_SECTORS` consecutive sectors in one
/// request. Data runs stay inside one block and image runs inside one
/// metadata half; only format's blank scan reads across those lines. A
/// run is not atomic: a failed `write_run` may have put any subset of its
/// sectors on the device (a leading run on the backends qualified so far,
/// as a sequence of single writes that failed part way would), and the
/// library treats every case the same: the
/// mount is poisoned, the superblocks and committed half are untouched,
/// and file bytes rewritten in place are indeterminate per sector until
/// the next commit. A failed `read_run` leaves the buffer unspecified. The
/// defaults issue one sector at a time, so a device that only knows
/// single sectors needs nothing more.
pub trait Device {
    fn sectors(&self) -> u64;
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error>;
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error>;
    fn flush(&mut self) -> Result<(), Error>;

    /// Reads `buffer.len() / SECTOR` consecutive sectors from `sector`.
    fn read_run(&mut self, sector: u64, buffer: &mut [u8]) -> Result<(), Error> {
        for (index, chunk) in buffer.chunks_exact_mut(SECTOR).enumerate() {
            self.read(sector + index as u64, chunk.try_into().unwrap())?;
        }
        Ok(())
    }

    /// Writes `buffer.len() / SECTOR` consecutive sectors from `sector`,
    /// in order.
    fn write_run(&mut self, sector: u64, buffer: &[u8]) -> Result<(), Error> {
        for (index, chunk) in buffer.chunks_exact(SECTOR).enumerate() {
            self.write(sector + index as u64, chunk.try_into().unwrap())?;
        }
        Ok(())
    }
}

/// Checks a run the library is about to issue: whole sectors, within the
/// bound, and within the device.
fn run_checked<D: Device>(device: &D, sector: u64, bytes: usize) -> Result<(), Error> {
    if bytes == 0 || !bytes.is_multiple_of(SECTOR) || bytes > MAX_RUN_BYTES {
        return Err(Error::Invalid);
    }
    match sector.checked_add((bytes / SECTOR) as u64) {
        Some(end) if end <= device.sectors() => Ok(()),
        _ => Err(Error::Invalid),
    }
}

fn read_run<D: Device>(device: &mut D, sector: u64, buffer: &mut [u8]) -> Result<(), Error> {
    run_checked(device, sector, buffer.len())?;
    device.read_run(sector, buffer)
}

fn write_run<D: Device>(device: &mut D, sector: u64, buffer: &[u8]) -> Result<(), Error> {
    run_checked(device, sector, buffer.len())?;
    device.write_run(sector, buffer)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub create_new: bool,
    pub truncate: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attr {
    pub kind: Kind,
    pub size: u64,
    pub readonly: bool,
    pub fs_id: u64,
    pub serial: u64,
    /// 1 while the object has a name, 0 once unlinked but still open.
    pub links: u32,
    /// Seconds since the Unix epoch of the last change to the object's
    /// content or size (files) or entries (directories); 0 is unknown.
    pub mtime: u64,
}

#[derive(Clone, Debug)]
struct Object {
    parent: u64,
    name: Vec<u8>,
    kind: Kind,
    readonly: bool,
    size: u64,
    blocks: Vec<u32>,
    linked: bool,
    mtime: u64,
}

#[derive(Clone, Copy, Debug)]
struct Open {
    serial: u64,
    read: bool,
    write: bool,
}

#[derive(Default)]
struct LockState {
    exclusive: Option<u64>,
    shared: BTreeSet<u64>,
}

struct Bits(Vec<u64>);

impl Bits {
    fn new(count: u32) -> Self {
        Self(vec![0; (count as usize).div_ceil(64)])
    }
    fn clear(&mut self) {
        self.0.fill(0);
    }
    fn get(&self, bit: u32) -> bool {
        self.0[bit as usize / 64] & (1 << (bit % 64)) != 0
    }
    fn set(&mut self, bit: u32, value: bool) {
        let word = &mut self.0[bit as usize / 64];
        if value {
            *word |= 1 << (bit % 64)
        } else {
            *word &= !(1 << (bit % 64))
        }
    }
}

/// What commits cost on the device, for write-amplification accounting;
/// data writes are the caller's own and are not counted here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WriteStats {
    /// Commits since mount.
    pub commits: u64,
    /// Metadata image bytes those commits wrote (whole sectors).
    pub image_bytes: u64,
    /// Superblock sectors those commits wrote (one per commit).
    pub superblock_sectors: u64,
}

pub struct Fs<D: Device> {
    device: D,
    geometry: Geometry,
    fs_id: u64,
    seq: u64,
    next_serial: u64,
    objects: BTreeMap<u64, Object>,
    children: BTreeMap<(u64, Vec<u8>), u64>,
    /// Blocks the last durable image references.
    durable: Bits,
    /// Blocks current memory references, including unlinked open objects.
    live: Bits,
    cursor: u32,
    object_bytes: usize,
    /// Object-record bytes ordinary creation may not use (`set_reserve`).
    reserve: usize,
    dirty: bool,
    poisoned: bool,
    writable: bool,
    handles: BTreeMap<u64, Open>,
    next_handle: u64,
    open_counts: BTreeMap<u64, u32>,
    locks: BTreeMap<u64, LockState>,
    stats: WriteStats,
    /// What `mtime` records for a change now (`set_clock`); 0 is unknown.
    clock: u64,
}

fn components(path: &[u8]) -> Result<Vec<&[u8]>, Error> {
    if path.first() != Some(&b'/') {
        return Err(Error::Invalid);
    }
    let mut parts = Vec::new();
    for part in path.split(|byte| *byte == b'/') {
        if part.is_empty() {
            continue;
        }
        if !valid_name(part) {
            return Err(Error::Invalid);
        }
        parts.push(part);
    }
    Ok(parts)
}

fn write_image<D: Device>(
    device: &mut D,
    geometry: &Geometry,
    fs_id: u64,
    seq: u64,
    bytes: &[u8],
) -> Result<(), Error> {
    let first = geometry.half_first(seq % 2);
    let mut run = [0u8; MAX_RUN_BYTES];
    for (index, chunk) in bytes.chunks(MAX_RUN_BYTES).enumerate() {
        let sectors = chunk.len().div_ceil(SECTOR);
        run[..chunk.len()].copy_from_slice(chunk);
        run[chunk.len()..sectors * SECTOR].fill(0);
        write_run(device, first + (index * MAX_RUN_SECTORS as usize) as u64, &run[..sectors * SECTOR])?;
    }
    device.flush()?;
    let superblock = Superblock {
        fs_id,
        seq,
        image_len: bytes.len() as u32,
        digest: sha256(bytes),
        geometry: *geometry,
    };
    device.write(seq % 2, &superblock.encode())?;
    device.flush()
}

/// Formats a region that holds no bytes at all. Anything nonzero is
/// refused: format never destroys storage it cannot account for. The one
/// exception is an interrupted format, which can only have written the
/// superblock slots and metadata halves and committed nothing.
pub fn format<D: Device>(device: &mut D, fs_id: u64) -> Result<(), Error> {
    let geometry = Geometry::for_region(device.sectors())?;
    let first = match select(device) {
        Err(Error::Unformatted) => geometry.data_first,
        _ => 0,
    };
    let mut run = [0u8; MAX_RUN_BYTES];
    let mut lba = first;
    while lba < device.sectors() {
        let sectors = (device.sectors() - lba).min(MAX_RUN_SECTORS) as usize;
        read_run(device, lba, &mut run[..sectors * SECTOR])?;
        if run[..sectors * SECTOR].iter().any(|byte| *byte != 0) {
            return Err(Error::NotBlank);
        }
        lba += sectors as u64;
    }
    format_verified_blank(device, fs_id)
}

/// Formats a region the caller has itself just read back as all zero (the
/// layout format scans the whole device first); skips the second scan.
pub fn format_verified_blank<D: Device>(device: &mut D, fs_id: u64) -> Result<(), Error> {
    let geometry = Geometry::for_region(device.sectors())?;
    let root = Record {
        serial: ROOT,
        parent: 0,
        name: Vec::new(),
        kind: Kind::Dir,
        readonly: false,
        size: 0,
        blocks: Vec::new(),
        mtime: 0,
    };
    for seq in 0..2 {
        let image = Image {
            fs_id,
            seq,
            next_serial: ROOT + 1,
            geometry,
            records: vec![root.clone()],
        };
        write_image(device, &geometry, fs_id, seq, &image.encode())?;
    }
    Ok(())
}

/// Reads and checks the committed state without building a mount: the
/// selected superblock and its decoded image.
pub fn inspect<D: Device>(device: &mut D) -> Result<(u64, u64, usize), Error> {
    let (superblock, image) = select(device)?;
    Ok((superblock.fs_id, superblock.seq, image.records.len()))
}

fn select<D: Device>(device: &mut D) -> Result<(Superblock, Image), Error> {
    let geometry = Geometry::for_region(device.sectors())?;
    let mut slots = [None, None];
    for slot in 0..2u64 {
        let mut sector = [0u8; SECTOR];
        device.read(slot, &mut sector)?;
        slots[slot as usize] = Superblock::decode(&sector, slot)?;
    }
    let (zero, one) = match slots {
        [None, None] => return Err(Error::Unformatted),
        // Format writes slot 0 (sequence 0) before slot 1, and nothing is
        // committed until both exist: this is an interrupted format.
        [Some(zero), None] if zero.seq == 0 => return Err(Error::Unformatted),
        [Some(zero), Some(one)] => (zero, one),
        _ => return Err(Error::Corrupt("one superblock slot is blank")),
    };
    if zero.fs_id != one.fs_id || zero.geometry != geometry || one.geometry != geometry {
        return Err(Error::Corrupt("superblocks disagree with the region"));
    }
    let newest = if zero.seq.checked_add(1) == Some(one.seq) {
        one
    } else if one.seq.checked_add(1) == Some(zero.seq) {
        zero
    } else {
        return Err(Error::Corrupt("superblock sequences are not consecutive"));
    };
    let length = newest.image_len as usize;
    if length > (geometry.half_sectors as usize) * SECTOR {
        return Err(Error::Corrupt("image longer than its half"));
    }
    let first = geometry.half_first(newest.seq % 2);
    let mut bytes = vec![0u8; length.next_multiple_of(SECTOR)];
    for (index, chunk) in bytes.chunks_mut(MAX_RUN_BYTES).enumerate() {
        read_run(device, first + (index * MAX_RUN_SECTORS as usize) as u64, chunk)?;
    }
    bytes.truncate(length);
    if sha256(&bytes) != newest.digest {
        return Err(Error::Corrupt("image digest"));
    }
    let image = Image::decode(&bytes, &newest)?;
    Ok((newest, image))
}

impl<D: Device> Fs<D> {
    /// Mounts the newest committed state or refuses. `writable` is the
    /// authority the caller holds; without it every mutation is refused.
    pub fn mount(mut device: D, writable: bool) -> Result<Self, Error> {
        // What a writer mounts must already be durable: a superblock still in
        // a volatile device cache (left by a predecessor that died, or whose
        // final flush failed) could vanish at a power cut after this mount
        // had acted on it. A read-only mount cannot flush.
        if writable {
            device.flush()?;
        }
        let (superblock, image) = select(&mut device)?;
        let geometry = superblock.geometry;
        let mut fs = Self {
            device,
            geometry,
            fs_id: superblock.fs_id,
            seq: superblock.seq,
            next_serial: image.next_serial,
            objects: BTreeMap::new(),
            children: BTreeMap::new(),
            durable: Bits::new(geometry.data_blocks),
            live: Bits::new(geometry.data_blocks),
            cursor: 0,
            object_bytes: HEADER_BYTES,
            reserve: 0,
            dirty: false,
            poisoned: false,
            writable,
            handles: BTreeMap::new(),
            next_handle: 1,
            open_counts: BTreeMap::new(),
            locks: BTreeMap::new(),
            stats: WriteStats::default(),
            clock: 0,
        };
        for record in image.records {
            for block in &record.blocks {
                fs.durable.set(*block, true);
                fs.live.set(*block, true);
            }
            fs.object_bytes += record_bytes(record.name.len());
            if record.serial != ROOT {
                fs.children
                    .insert((record.parent, record.name.clone()), record.serial);
            }
            fs.objects.insert(
                record.serial,
                Object {
                    parent: record.parent,
                    name: record.name,
                    kind: record.kind,
                    readonly: record.readonly,
                    size: record.size,
                    blocks: record.blocks,
                    linked: true,
                    mtime: record.mtime,
                },
            );
        }
        Ok(fs)
    }

    pub fn fs_id(&self) -> u64 {
        self.fs_id
    }

    pub fn sequence(&self) -> u64 {
        self.seq
    }

    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    pub fn writable(&self) -> bool {
        self.writable
    }

    /// A device operation failed: memory may be ahead of the device, and
    /// whether the last commit reached it is unknown.
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn write_stats(&self) -> WriteStats {
        self.stats
    }

    /// Live namespace objects in this mounted image, including the root.
    /// This is read directly from the filesystem table for capacity
    /// qualification, independently of a session's RELEASE report.
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn device(&mut self) -> &mut D {
        &mut self.device
    }

    pub fn into_device(self) -> D {
        self.device
    }

    /// Blocks neither memory nor the durable image references.
    pub fn free_blocks(&self) -> u32 {
        (0..self.geometry.data_blocks)
            .filter(|block| !self.durable.get(*block) && !self.live.get(*block))
            .count() as u32
    }

    fn usable(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }

    fn mutable(&self) -> Result<(), Error> {
        self.usable()?;
        if self.writable {
            Ok(())
        } else {
            Err(Error::ReadOnlyFs)
        }
    }

    fn device_result<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn walk(&self, parts: &[&[u8]]) -> Result<u64, Error> {
        let mut cursor = ROOT;
        for part in parts {
            if self.objects[&cursor].kind != Kind::Dir {
                return Err(Error::NotDir);
            }
            cursor = *self
                .children
                .get(&(cursor, part.to_vec()))
                .ok_or(Error::NotFound)?;
        }
        Ok(cursor)
    }

    fn resolve(&self, path: &[u8]) -> Result<u64, Error> {
        self.walk(&components(path)?)
    }

    fn resolve_parent<'p>(&self, path: &'p [u8]) -> Result<(u64, &'p [u8]), Error> {
        let parts = components(path)?;
        let (name, parents) = parts.split_last().ok_or(Error::Invalid)?;
        let parent = self.walk(parents)?;
        if self.objects[&parent].kind != Kind::Dir {
            return Err(Error::NotDir);
        }
        Ok((parent, name))
    }

    fn budget(&self, added: usize, removed: usize) -> Result<(), Error> {
        self.budget_keeping(added, removed, self.reserve)
    }

    fn budget_keeping(&self, added: usize, removed: usize, reserve: usize) -> Result<(), Error> {
        if self.object_bytes + added - removed > OBJECT_BUDGET.saturating_sub(reserve) {
            Err(Error::NoSpace)
        } else {
            Ok(())
        }
    }

    /// Keeps `bytes` of the object budget back from ordinary creation
    /// (`open` with create, `mkdir`, `rename` into a longer name), so that
    /// [`Fs::mkdir_reserved`] can still make a directory on a filesystem
    /// its users have filled. This mount's policy, not the format's: a
    /// fresh mount starts with no reserve.
    /// The wall clock, in Unix seconds, for the changes that follow until
    /// the next call; `None` (unavailable or refused) records 0, which
    /// means unknown. The caller sets it before each operation: the
    /// library never reads a clock itself. A fresh mount starts at `None`.
    pub fn set_clock(&mut self, now: Option<u64>) {
        self.clock = now.unwrap_or(0);
    }

    /// The object changed now: content or size (a file), entries (a
    /// directory). Only a linked object's change needs a commit.
    fn touch(&mut self, serial: u64) {
        let clock = self.clock;
        let object = self.objects.get_mut(&serial).unwrap();
        if object.mtime != clock {
            object.mtime = clock;
            if object.linked {
                self.dirty = true;
            }
        }
    }

    pub fn set_reserve(&mut self, bytes: usize) {
        self.reserve = bytes;
    }

    fn attr(&self, serial: u64) -> Attr {
        let object = &self.objects[&serial];
        Attr {
            kind: object.kind,
            size: object.size,
            readonly: object.readonly,
            fs_id: self.fs_id,
            serial,
            links: u32::from(object.linked),
            mtime: object.mtime,
        }
    }

    fn linked_records(&self) -> impl Iterator<Item = image::RecordRef<'_>> + Clone + '_ {
        self.objects.iter().filter(|(_, object)| object.linked).map(|(serial, object)| image::RecordRef {
            serial: *serial,
            parent: object.parent,
            name: &object.name,
            kind: object.kind,
            readonly: object.readonly,
            size: object.size,
            blocks: &object.blocks,
            mtime: object.mtime,
        })
    }

    /// Writes the whole namespace as the next image and switches the
    /// superblock to it. Blocks the previous image referenced and this one
    /// does not become allocatable only after this returns.
    fn commit(&mut self) -> Result<(), Error> {
        self.mutable()?;
        let seq = self.seq + 1;
        // Encoding borrows this linked namespace. No names or block lists
        // are cloned, and the complete owned buffer precedes device effects.
        let bytes = image::encode_records(self.fs_id, seq, self.next_serial,
                                          self.geometry, self.linked_records());
        if bytes.len() > self.geometry.half_sectors as usize * SECTOR {
            // Impossible by the object budget; refuse rather than overrun.
            self.poisoned = true;
            return Err(Error::Corrupt("image exceeds its half"));
        }
        let geometry = self.geometry;
        let result = write_image(&mut self.device, &geometry, self.fs_id, seq, &bytes);
        self.device_result(result)?;
        self.stats.commits += 1;
        self.stats.image_bytes += bytes.len().next_multiple_of(SECTOR) as u64;
        self.stats.superblock_sectors += 1;
        self.seq = seq;
        // Geometry is fixed for this mount. Rebuild only after the disk
        // commit succeeds, reusing the bitmap's existing backing storage.
        self.durable.clear();
        for object in self.objects.values().filter(|object| object.linked) {
            for block in &object.blocks {
                self.durable.set(*block, true);
            }
        }
        self.dirty = false;
        Ok(())
    }

    /// Makes every completed operation durable.
    pub fn sync(&mut self) -> Result<(), Error> {
        self.usable()?;
        if self.dirty {
            return self.commit();
        }
        if !self.writable {
            return Ok(());
        }
        let result = self.device.flush();
        self.device_result(result)
    }

    fn handle(&self, handle: u64) -> Result<Open, Error> {
        self.handles.get(&handle).copied().ok_or(Error::BadHandle)
    }

    pub fn open(&mut self, path: &[u8], flags: OpenFlags) -> Result<u64, Error> {
        self.usable()?;
        let wants_write = flags.write || flags.truncate;
        let parts = components(path)?;
        let serial = match parts.split_last() {
            None => {
                if wants_write || flags.create_new {
                    return Err(Error::IsDir);
                }
                ROOT
            }
            Some((name, parents)) => {
                let parent = self.walk(parents)?;
                if self.objects[&parent].kind != Kind::Dir {
                    return Err(Error::NotDir);
                }
                match self.children.get(&(parent, name.to_vec())).copied() {
                    Some(serial) => {
                        if flags.create_new {
                            return Err(Error::Exists);
                        }
                        let object = &self.objects[&serial];
                        if object.kind == Kind::Dir && wants_write {
                            return Err(Error::IsDir);
                        }
                        if wants_write {
                            self.mutable()?;
                            if object.readonly {
                                return Err(Error::Denied);
                            }
                        }
                        if flags.truncate {
                            self.resize(serial, 0)?;
                        }
                        serial
                    }
                    None => {
                        if !(flags.create || flags.create_new) {
                            return Err(Error::NotFound);
                        }
                        self.mutable()?;
                        self.budget(record_bytes(name.len()), 0)?;
                        let serial = self.insert(parent, name, Kind::File);
                        self.commit()?;
                        serial
                    }
                }
            }
        };
        let handle = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(
            handle,
            Open {
                serial,
                read: flags.read,
                write: flags.write,
            },
        );
        *self.open_counts.entry(serial).or_insert(0) += 1;
        Ok(handle)
    }

    fn insert(&mut self, parent: u64, name: &[u8], kind: Kind) -> u64 {
        let serial = self.next_serial;
        self.next_serial += 1;
        self.objects.insert(
            serial,
            Object {
                parent,
                name: name.to_vec(),
                kind,
                readonly: false,
                size: 0,
                blocks: Vec::new(),
                linked: true,
                mtime: self.clock,
            },
        );
        self.children.insert((parent, name.to_vec()), serial);
        self.object_bytes += record_bytes(name.len());
        self.dirty = true;
        self.touch(parent);
        serial
    }

    /// Removes the name. An object still open lives on unnamed until its
    /// last handle closes; its blocks stay reserved until then.
    fn detach(&mut self, serial: u64) {
        let object = self.objects.get_mut(&serial).unwrap();
        let parent = object.parent;
        self.children.remove(&(parent, object.name.clone()));
        object.linked = false;
        self.object_bytes -= record_bytes(object.name.len());
        self.dirty = true;
        self.touch(parent);
        if self.open_counts.get(&serial).copied().unwrap_or(0) == 0 {
            self.drop_object(serial);
        }
    }

    fn drop_object(&mut self, serial: u64) {
        let object = self.objects.remove(&serial).unwrap();
        for block in object.blocks {
            self.live.set(block, false);
        }
        self.locks.remove(&serial);
    }

    pub fn close(&mut self, handle: u64) -> Result<(), Error> {
        let open = self.handles.remove(&handle).ok_or(Error::BadHandle)?;
        self.release(open.serial, handle);
        let count = self.open_counts.get_mut(&open.serial).unwrap();
        *count -= 1;
        if *count == 0 {
            self.open_counts.remove(&open.serial);
            if !self.objects[&open.serial].linked {
                self.drop_object(open.serial);
            }
        }
        Ok(())
    }

    pub fn stat(&self, path: &[u8]) -> Result<Attr, Error> {
        self.usable()?;
        Ok(self.attr(self.resolve(path)?))
    }

    pub fn fstat(&self, handle: u64) -> Result<Attr, Error> {
        self.usable()?;
        Ok(self.attr(self.handle(handle)?.serial))
    }

    /// The normalized path of an existing object. There are no links and
    /// no dot components, so this is the path itself once it resolves.
    pub fn canonical(&self, path: &[u8]) -> Result<Vec<u8>, Error> {
        self.usable()?;
        let parts = components(path)?;
        self.walk(&parts)?;
        if parts.is_empty() {
            return Ok(b"/".to_vec());
        }
        let mut out = Vec::new();
        for part in parts {
            out.push(b'/');
            out.extend_from_slice(part);
        }
        Ok(out)
    }

    /// Entries of a directory in name order.
    pub fn read_dir(&self, path: &[u8]) -> Result<Vec<(Vec<u8>, Attr)>, Error> {
        self.usable()?;
        let serial = self.resolve(path)?;
        if self.objects[&serial].kind != Kind::Dir {
            return Err(Error::NotDir);
        }
        Ok(self
            .children
            .range((serial, Vec::new())..)
            .take_while(|((parent, _), _)| *parent == serial)
            .map(|((_, name), child)| (name.clone(), self.attr(*child)))
            .collect())
    }

    pub fn mkdir(&mut self, path: &[u8]) -> Result<(), Error> {
        self.mkdir_keeping(path, self.reserve)
    }

    /// `mkdir` that may use the reserve (`set_reserve`): for the directory
    /// a service must be able to make however full its users left the
    /// filesystem.
    pub fn mkdir_reserved(&mut self, path: &[u8]) -> Result<(), Error> {
        self.mkdir_keeping(path, 0)
    }

    fn mkdir_keeping(&mut self, path: &[u8], reserve: usize) -> Result<(), Error> {
        self.mutable()?;
        let (parent, name) = self.resolve_parent(path)?;
        if self.children.contains_key(&(parent, name.to_vec())) {
            return Err(Error::Exists);
        }
        self.budget_keeping(record_bytes(name.len()), 0, reserve)?;
        self.insert(parent, name, Kind::Dir);
        self.commit()
    }

    pub fn rmdir(&mut self, path: &[u8]) -> Result<(), Error> {
        self.mutable()?;
        let serial = self.resolve(path)?;
        if serial == ROOT {
            return Err(Error::Invalid);
        }
        if self.objects[&serial].kind != Kind::Dir {
            return Err(Error::NotDir);
        }
        if self
            .children
            .range((serial, Vec::new())..)
            .next()
            .is_some_and(|((p, _), _)| *p == serial)
        {
            return Err(Error::NotEmpty);
        }
        self.detach(serial);
        self.commit()
    }

    pub fn unlink(&mut self, path: &[u8]) -> Result<(), Error> {
        self.mutable()?;
        let serial = self.resolve(path)?;
        if self.objects[&serial].kind == Kind::Dir {
            return Err(Error::IsDir);
        }
        self.detach(serial);
        self.commit()
    }

    /// Removes everything below the directory `path`, and `path` itself
    /// when `and_self`, in one commit: the whole subtree or none of it is
    /// what a crash can expose. The walk keeps its own stack, so depth
    /// costs memory, not call frames. Returns how many objects it removed.
    pub fn remove_tree(&mut self, path: &[u8], and_self: bool) -> Result<usize, Error> {
        self.mutable()?;
        let top = self.resolve(path)?;
        if self.objects[&top].kind != Kind::Dir {
            return Err(Error::NotDir);
        }
        if and_self && top == ROOT {
            return Err(Error::Invalid);
        }
        // Every object below `top`, each after its directory.
        let mut order = Vec::new();
        let mut pending = vec![top];
        while let Some(dir) = pending.pop() {
            for ((_, _), child) in self
                .children
                .range((dir, Vec::new())..)
                .take_while(|((p, _), _)| *p == dir)
            {
                order.push(*child);
                if self.objects[child].kind == Kind::Dir {
                    pending.push(*child);
                }
            }
        }
        if and_self {
            order.insert(0, top);
        }
        let removed = order.len();
        if removed == 0 {
            return Ok(0);
        }
        // Children before their directories.
        for serial in order.into_iter().rev() {
            self.detach(serial);
        }
        self.commit()?;
        Ok(removed)
    }

    /// Moves `from` to `to` in one commit. A file may replace a file unless
    /// `noreplace`; nothing else is replaced. The old and new namespaces are
    /// the only states a crash can expose.
    pub fn rename(&mut self, from: &[u8], to: &[u8], noreplace: bool) -> Result<(), Error> {
        self.mutable()?;
        let source = self.resolve(from)?;
        if source == ROOT {
            return Err(Error::Invalid);
        }
        let (parent, name) = self.resolve_parent(to)?;
        let kind = self.objects[&source].kind;
        if kind == Kind::Dir {
            let mut cursor = parent;
            while cursor != 0 {
                if cursor == source {
                    return Err(Error::Invalid);
                }
                cursor = self.objects[&cursor].parent;
            }
        }
        let existing = self.children.get(&(parent, name.to_vec())).copied();
        if existing == Some(source) {
            return Ok(());
        }
        if let Some(target) = existing {
            if noreplace {
                return Err(Error::Exists);
            }
            if self.objects[&target].kind == Kind::Dir {
                return Err(Error::IsDir);
            }
            if kind == Kind::Dir {
                return Err(Error::NotDir);
            }
        }
        let old_len = self.objects[&source].name.len();
        let replaced = existing.map_or(0, |target| record_bytes(self.objects[&target].name.len()));
        self.budget(name.len(), old_len + replaced)?;
        if let Some(target) = existing {
            self.detach(target);
        }
        let object = self.objects.get_mut(&source).unwrap();
        let old_parent = object.parent;
        self.children.remove(&(old_parent, object.name.clone()));
        object.parent = parent;
        object.name = name.to_vec();
        self.children.insert((parent, name.to_vec()), source);
        self.object_bytes = self.object_bytes + name.len() - old_len;
        self.dirty = true;
        // Both directories' entries changed; the moved object's own mtime
        // is about its content, which did not.
        self.touch(old_parent);
        self.touch(parent);
        self.commit()
    }

    pub fn set_readonly(&mut self, handle: u64, readonly: bool) -> Result<(), Error> {
        let serial = self.handle(handle)?.serial;
        self.set_readonly_serial(serial, readonly)
    }

    pub fn set_readonly_path(&mut self, path: &[u8], readonly: bool) -> Result<(), Error> {
        let serial = self.resolve(path)?;
        self.set_readonly_serial(serial, readonly)
    }

    fn set_readonly_serial(&mut self, serial: u64, readonly: bool) -> Result<(), Error> {
        self.mutable()?;
        let object = self.objects.get_mut(&serial).unwrap();
        if object.kind == Kind::Dir {
            return Err(Error::IsDir);
        }
        if object.readonly == readonly {
            return Ok(());
        }
        object.readonly = readonly;
        self.dirty = true;
        if object.linked { self.commit() } else { Ok(()) }
    }

    fn allocate(&mut self, count: usize) -> Result<Vec<u32>, Error> {
        let total = self.geometry.data_blocks;
        let mut found = Vec::with_capacity(count);
        let mut probe = self.cursor;
        for _ in 0..total {
            if found.len() == count {
                break;
            }
            if !self.durable.get(probe) && !self.live.get(probe) {
                found.push(probe);
            }
            probe = (probe + 1) % total;
        }
        if found.len() < count {
            return Err(Error::NoSpace);
        }
        for block in &found {
            self.live.set(*block, true);
        }
        self.cursor = probe;
        Ok(found)
    }

    /// Writes `[offset, offset + len)` of a file with `data` (or zeros),
    /// one run of whole sectors per block; bytes outside the range keep
    /// their values. With `compare`, returns whether any byte in the range
    /// differed from what the device held: the run is then read first,
    /// until the first difference is found. Without it, the result means
    /// nothing. A run that fails part way leaves the file's bytes in that
    /// block indeterminate per sector until the next commit, as a failing
    /// sequence of single-sector writes already did; the committed
    /// metadata is never touched.
    fn store(
        &mut self,
        serial: u64,
        offset: u64,
        len: u64,
        data: Option<&[u8]>,
        compare: bool,
    ) -> Result<bool, Error> {
        let mut changed = false;
        let mut position = offset;
        let end = offset + len;
        let mut run = [0u8; MAX_RUN_BYTES];
        while position < end {
            let block_index = position / BLOCK as u64;
            let block_end = ((block_index + 1) * BLOCK as u64).min(end);
            let within = (position % BLOCK as u64) as usize;
            let take = (block_end - position) as usize;
            let first_sector = within / SECTOR;
            let last_sector = (within + take - 1) / SECTOR;
            let sectors = last_sector - first_sector + 1;
            let run_offset = within - first_sector * SECTOR;
            let block = self.objects[&serial].blocks[block_index as usize];
            let lba = self.geometry.block_sector(block) + first_sector as u64;
            let bytes = &mut run[..sectors * SECTOR];
            let checking = compare && !changed;
            let whole = run_offset == 0 && take == sectors * SECTOR;
            if !whole || checking {
                let result = read_run(&mut self.device, lba, bytes);
                self.device_result(result)?;
            }
            let source = (position - offset) as usize;
            let range = run_offset..run_offset + take;
            match data {
                Some(new) => {
                    let new = &new[source..source + take];
                    changed |= checking && bytes[range.clone()] != *new;
                    bytes[range].copy_from_slice(new)
                }
                None => {
                    changed |= checking && bytes[range.clone()].iter().any(|byte| *byte != 0);
                    bytes[range].fill(0)
                }
            }
            let result = write_run(&mut self.device, lba, bytes);
            self.device_result(result)?;
            position += take as u64;
        }
        Ok(changed)
    }

    /// Sets a file's length. Growth allocates every block first (all or
    /// nothing) and zero-fills the newly exposed range; shrinking releases
    /// blocks to memory only, so the durable image keeps them until commit.
    fn resize(&mut self, serial: u64, size: u64) -> Result<(), Error> {
        let old = self.objects[&serial].size;
        if size == old {
            return Ok(());
        }
        let needed = usize::try_from(size.div_ceil(BLOCK as u64)).map_err(|_| Error::NoSpace)?;
        let have = self.objects[&serial].blocks.len();
        if size < old {
            let object = self.objects.get_mut(&serial).unwrap();
            let released = object.blocks.split_off(needed);
            object.size = size;
            for block in released {
                self.live.set(block, false);
            }
        } else {
            if needed > have {
                if needed - have > self.geometry.data_blocks as usize {
                    return Err(Error::NoSpace);
                }
                let fresh = self.allocate(needed - have)?;
                self.objects.get_mut(&serial).unwrap().blocks.extend(fresh);
            }
            self.objects.get_mut(&serial).unwrap().size = size;
            self.store(serial, old, size - old, None, false)?;
        }
        self.dirty = true;
        self.touch(serial);
        Ok(())
    }

    fn file_for(&self, handle: u64, write: bool) -> Result<u64, Error> {
        let open = self.handle(handle)?;
        if (write && !open.write) || (!write && !open.read) {
            return Err(Error::Denied);
        }
        let object = &self.objects[&open.serial];
        if object.kind == Kind::Dir {
            return Err(Error::IsDir);
        }
        // The right to write is checked against the object as it is now,
        // not as it was when the handle was opened: making an object
        // read-only withdraws it from every open handle too.
        if write && object.readonly {
            return Err(Error::Denied);
        }
        Ok(open.serial)
    }

    pub fn read_at(&mut self, handle: u64, offset: u64, buffer: &mut [u8]) -> Result<usize, Error> {
        self.usable()?;
        let serial = self.file_for(handle, false)?;
        let size = self.objects[&serial].size;
        if offset >= size || buffer.is_empty() {
            return Ok(0);
        }
        let count = (size - offset).min(buffer.len() as u64) as usize;
        let mut done = 0usize;
        let mut run = [0u8; MAX_RUN_BYTES];
        while done < count {
            let position = offset + done as u64;
            let block_index = position / BLOCK as u64;
            let within = (position % BLOCK as u64) as usize;
            let take = (BLOCK - within).min(count - done);
            let first_sector = within / SECTOR;
            let last_sector = (within + take - 1) / SECTOR;
            let sectors = last_sector - first_sector + 1;
            let run_offset = within - first_sector * SECTOR;
            let block = self.objects[&serial].blocks[block_index as usize];
            let lba = self.geometry.block_sector(block) + first_sector as u64;
            let result = read_run(&mut self.device, lba, &mut run[..sectors * SECTOR]);
            self.device_result(result)?;
            buffer[done..done + take].copy_from_slice(&run[run_offset..run_offset + take]);
            done += take;
        }
        Ok(count)
    }

    /// All or nothing: space for the whole range is allocated before any
    /// byte is written. Changes `mtime` when the write changes the size or
    /// any byte in its range (a rewrite of identical bytes is no change);
    /// the bytes are compared only while `mtime` would actually move.
    pub fn write_at(&mut self, handle: u64, offset: u64, data: &[u8]) -> Result<usize, Error> {
        self.mutable()?;
        let serial = self.file_for(handle, true)?;
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(Error::Invalid)?;
        let size = self.objects[&serial].size;
        if end > size {
            let needed = usize::try_from(end.div_ceil(BLOCK as u64)).map_err(|_| Error::NoSpace)?;
            let have = self.objects[&serial].blocks.len();
            if needed > have {
                if needed - have > self.geometry.data_blocks as usize {
                    return Err(Error::NoSpace);
                }
                let fresh = self.allocate(needed - have)?;
                self.objects.get_mut(&serial).unwrap().blocks.extend(fresh);
            }
            self.objects.get_mut(&serial).unwrap().size = end;
            self.dirty = true;
            self.touch(serial);
            if offset > size {
                self.store(serial, size, offset - size, None, false)?;
            }
        }
        let compare = self.objects[&serial].mtime != self.clock;
        if self.store(serial, offset, data.len() as u64, Some(data), compare)? {
            self.touch(serial);
        }
        Ok(data.len())
    }

    pub fn set_len(&mut self, handle: u64, size: u64) -> Result<(), Error> {
        self.mutable()?;
        let serial = self.file_for(handle, true)?;
        self.resize(serial, size)
    }

    /// flock-shaped advisory locks held by a handle; never persisted.
    pub fn try_lock(&mut self, handle: u64, exclusive: bool) -> Result<(), Error> {
        self.usable()?;
        let serial = self.handle(handle)?.serial;
        let state = self.locks.entry(serial).or_default();
        let others_shared = state.shared.iter().any(|holder| *holder != handle);
        let other_exclusive = state.exclusive.is_some_and(|holder| holder != handle);
        if other_exclusive || (exclusive && others_shared) {
            return Err(Error::WouldBlock);
        }
        state.shared.remove(&handle);
        state.exclusive = None;
        if exclusive {
            state.exclusive = Some(handle);
        } else {
            state.shared.insert(handle);
        }
        Ok(())
    }

    pub fn unlock(&mut self, handle: u64) -> Result<(), Error> {
        let serial = self.handle(handle)?.serial;
        self.release(serial, handle);
        Ok(())
    }

    fn release(&mut self, serial: u64, handle: u64) {
        if let Some(state) = self.locks.get_mut(&serial) {
            state.shared.remove(&handle);
            if state.exclusive == Some(handle) {
                state.exclusive = None;
            }
            if state.exclusive.is_none() && state.shared.is_empty() {
                self.locks.remove(&serial);
            }
        }
    }

    /// Internal consistency, for tests: memory's block references match the
    /// live set exactly and never alias.
    pub fn check(&self) -> Result<(), &'static str> {
        let mut seen = Bits::new(self.geometry.data_blocks);
        for object in self.objects.values() {
            if object.kind == Kind::File
                && object.blocks.len() as u64 != object.size.div_ceil(BLOCK as u64)
            {
                return Err("file blocks do not match size");
            }
            for block in &object.blocks {
                if seen.get(*block) {
                    return Err("block aliased");
                }
                seen.set(*block, true);
            }
        }
        if seen.0 != self.live.0 {
            return Err("live set drifted");
        }
        Ok(())
    }
}
