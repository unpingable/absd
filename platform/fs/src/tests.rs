//! Host tests: structure, identity, namespace, and exhaustive crash points.
//!
//! `Disk` records every acknowledged write in order; a crash after `k`
//! writes is the image those first `k` writes produce (acknowledged sectors
//! retained, in issue order). `CacheDisk` and `Replay` model the stronger
//! device law of `docs/POWER-LOSS.md`: a volatile cache of aligned units
//! that only a completed flush makes stable, so a cut leaves every unit
//! written since in any one of its states.

use std::collections::BTreeMap;
use std::rc::Rc;
use std::cell::RefCell;
use std::vec::Vec;
use std::vec;
use std::boxed::Box;

use super::*;

#[derive(Clone)]
struct Disk {
    sectors: u64,
    base: Rc<RefCell<BTreeMap<u64, [u8; SECTOR]>>>,
    log: Rc<RefCell<Vec<(u64, [u8; SECTOR])>>>,
    /// Refuse writes after this many (device failure injection).
    fail_after: Option<usize>,
}

impl Disk {
    fn new(sectors: u64) -> Self {
        Self { sectors, base: Rc::default(), log: Rc::default(), fail_after: None }
    }

    /// The device after the first `count` logged writes, as a fresh disk.
    fn crash(&self, count: usize) -> Disk {
        let mut map = self.base.borrow().clone();
        for (lba, sector) in &self.log.borrow()[..count] {
            map.insert(*lba, *sector);
        }
        Disk { sectors: self.sectors, base: Rc::new(RefCell::new(map)), log: Rc::default(), fail_after: None }
    }

    fn settle(&self) -> Disk {
        self.crash(self.log.borrow().len())
    }

    fn writes(&self) -> usize {
        self.log.borrow().len()
    }

    fn poke(&self, lba: u64, edit: impl FnOnce(&mut [u8; SECTOR])) {
        let mut base = self.base.borrow_mut();
        let sector = base.entry(lba).or_insert([0; SECTOR]);
        edit(sector);
    }
}

impl Device for Disk {
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        assert!(sector < self.sectors);
        *buffer = [0; SECTOR];
        if let Some(found) = self.base.borrow().get(&sector) {
            *buffer = *found;
        }
        for (lba, data) in self.log.borrow().iter() {
            if *lba == sector {
                *buffer = *data;
            }
        }
        Ok(())
    }
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        assert!(sector < self.sectors);
        if self.fail_after.is_some_and(|limit| self.log.borrow().len() >= limit) {
            return Err(Error::Device(-5));
        }
        self.log.borrow_mut().push((sector, *buffer));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

const REGION: u64 = 4096; // 2 MiB

fn fresh() -> Disk {
    let mut disk = Disk::new(REGION);
    format(&mut disk, 0xabcd).unwrap();
    disk.settle()
}

fn rw() -> OpenFlags {
    OpenFlags { read: true, write: true, ..OpenFlags::default() }
}

fn create() -> OpenFlags {
    OpenFlags { create: true, ..rw() }
}

fn create_new() -> OpenFlags {
    OpenFlags { create_new: true, ..rw() }
}

fn read_all<D: Device>(fs: &mut Fs<D>, path: &[u8]) -> Option<Vec<u8>> {
    let handle = fs.open(path, OpenFlags { read: true, ..OpenFlags::default() }).ok()?;
    let size = fs.fstat(handle).unwrap().size as usize;
    let mut bytes = vec![0; size];
    assert_eq!(fs.read_at(handle, 0, &mut bytes).unwrap(), size);
    fs.close(handle).unwrap();
    Some(bytes)
}

fn put<D: Device>(fs: &mut Fs<D>, path: &[u8], bytes: &[u8]) {
    let handle = fs.open(path, create()).unwrap();
    fs.set_len(handle, 0).unwrap();
    fs.write_at(handle, 0, bytes).unwrap();
    fs.sync().unwrap();
    fs.close(handle).unwrap();
}

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|index| seed.wrapping_add((index * 7 % 251) as u8)).collect()
}

/// The whole visible namespace: path -> (kind, content or None for dirs).
fn tree<D: Device>(fs: &mut Fs<D>) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![b"/".to_vec()];
    while let Some(dir) = pending.pop() {
        for (name, attr) in fs.read_dir(&dir).unwrap() {
            let mut path = dir.clone();
            if path != b"/" {
                path.push(b'/');
            }
            path.extend_from_slice(&name);
            match attr.kind {
                Kind::Dir => {
                    out.insert(path.clone(), None);
                    pending.push(path);
                }
                Kind::File => {
                    let bytes = read_all(fs, &path).unwrap();
                    out.insert(path, Some(bytes));
                }
            }
        }
    }
    out
}

#[test]
fn format_mount_and_refusals() {
    let mut blank = Disk::new(REGION);
    assert!(matches!(Fs::mount(blank.clone(), true), Err(Error::Unformatted)));
    blank.poke(3000, |sector| sector[0] = 1);
    assert_eq!(format(&mut blank, 1), Err(Error::NotBlank));
    let disk = fresh();
    let fs = Fs::mount(disk.clone(), true).unwrap();
    assert_eq!(fs.fs_id(), 0xabcd);
    assert_eq!(fs.sequence(), 1);
    assert!(fs.read_dir(b"/").unwrap().is_empty());
    let mut again = disk.clone();
    assert_eq!(format(&mut again, 2), Err(Error::NotBlank));
    fs.check().unwrap();
}

#[test]
fn files_grow_shrink_and_persist() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    fs.mkdir(b"/ag").unwrap();
    let handle = fs.open(b"/ag/db", create_new()).unwrap();
    let data = pattern(3, 10_000);
    fs.write_at(handle, 0, &data).unwrap();
    // A gap is zero-filled, never stale.
    fs.write_at(handle, 20_000, b"tail").unwrap();
    fs.sync().unwrap();
    fs.set_len(handle, 5_000).unwrap();
    fs.set_len(handle, 9_000).unwrap();
    fs.sync().unwrap();
    fs.close(handle).unwrap();
    fs.check().unwrap();
    let mut again = Fs::mount(disk.settle(), true).unwrap();
    let bytes = read_all(&mut again, b"/ag/db").unwrap();
    assert_eq!(bytes.len(), 9_000);
    assert_eq!(&bytes[..5_000], &data[..5_000]);
    assert!(bytes[5_000..].iter().all(|byte| *byte == 0));
    again.check().unwrap();
}

#[test]
fn namespace_rules() {
    let disk = fresh();
    let mut fs = Fs::mount(disk, true).unwrap();
    assert_eq!(fs.open(b"relative", create()), Err(Error::Invalid));
    assert_eq!(fs.open(b"/a/../b", create()), Err(Error::Invalid));
    assert_eq!(fs.open(b"/./b", create()), Err(Error::Invalid));
    assert_eq!(fs.mkdir(b"/"), Err(Error::Invalid));
    fs.mkdir(b"/d").unwrap();
    assert_eq!(fs.mkdir(b"/d"), Err(Error::Exists));
    put(&mut fs, b"/d/f", b"x");
    assert_eq!(fs.open(b"/d/f/g", create()), Err(Error::NotDir));
    assert_eq!(fs.rmdir(b"/d"), Err(Error::NotEmpty));
    assert_eq!(fs.unlink(b"/d"), Err(Error::IsDir));
    assert_eq!(fs.rename(b"/d", b"/d/f2", false), Err(Error::Invalid));
    fs.mkdir(b"/e").unwrap();
    assert_eq!(fs.rename(b"/d/f", b"/e", false), Err(Error::IsDir));
    assert_eq!(fs.canonical(b"//d///f").unwrap(), b"/d/f".to_vec());
    assert_eq!(fs.canonical(b"/d/missing"), Err(Error::NotFound));
    let names: Vec<_> = fs.read_dir(b"/").unwrap().into_iter().map(|(name, _)| name).collect();
    assert_eq!(names, vec![b"d".to_vec(), b"e".to_vec()]);
    // Read-only objects refuse write opens; the flag is durable.
    let handle = fs.open(b"/d/f", rw()).unwrap();
    fs.set_readonly(handle, true).unwrap();
    fs.close(handle).unwrap();
    assert_eq!(fs.open(b"/d/f", rw()), Err(Error::Denied));
    assert!(fs.stat(b"/d/f").unwrap().readonly);
    fs.check().unwrap();
}

#[test]
fn read_only_mount_refuses_every_mutation() {
    let disk = fresh();
    {
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        put(&mut fs, b"/f", b"hello");
    }
    let before = disk.writes();
    let mut fs = Fs::mount(disk.clone(), false).unwrap();
    assert_eq!(read_all(&mut fs, b"/f").unwrap(), b"hello");
    assert_eq!(fs.open(b"/f", rw()), Err(Error::ReadOnlyFs));
    assert_eq!(fs.open(b"/g", create()), Err(Error::ReadOnlyFs));
    assert_eq!(fs.mkdir(b"/d"), Err(Error::ReadOnlyFs));
    assert_eq!(fs.unlink(b"/f"), Err(Error::ReadOnlyFs));
    assert_eq!(fs.rename(b"/f", b"/g", true), Err(Error::ReadOnlyFs));
    fs.sync().unwrap();
    assert_eq!(disk.writes(), before);
}

#[test]
fn identity_is_never_reused() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    put(&mut fs, b"/a", &pattern(1, 8192));
    let first = fs.stat(b"/a").unwrap();
    fs.unlink(b"/a").unwrap();
    // Reuse the storage: the same blocks become free and are allocated again.
    put(&mut fs, b"/a", &pattern(2, 8192));
    let second = fs.stat(b"/a").unwrap();
    assert_eq!(first.fs_id, second.fs_id);
    assert_ne!(first.serial, second.serial);
    // Across a remount the counter continues; nothing is reissued.
    drop(fs);
    let mut again = Fs::mount(disk.settle(), true).unwrap();
    put(&mut again, b"/b", b"b");
    let third = again.stat(b"/b").unwrap();
    assert!(third.serial > second.serial);
    // Another filesystem instance never shares identity.
    let other = {
        let mut disk = Disk::new(REGION);
        format(&mut disk, 0x9999).unwrap();
        disk.settle()
    };
    let mut other = Fs::mount(other, true).unwrap();
    put(&mut other, b"/a", b"x");
    assert_ne!(other.stat(b"/a").unwrap().fs_id, second.fs_id);
}

#[test]
fn unlinked_open_objects_keep_their_blocks() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    let handle = fs.open(b"/wal", create_new()).unwrap();
    fs.write_at(handle, 0, &pattern(9, 3 * BLOCK)).unwrap();
    fs.sync().unwrap();
    fs.unlink(b"/wal").unwrap();
    assert_eq!(fs.fstat(handle).unwrap().links, 0);
    // New allocations cannot land on the orphan's blocks.
    put(&mut fs, b"/other", &pattern(4, 6 * BLOCK));
    let mut bytes = vec![0; 3 * BLOCK];
    fs.read_at(handle, 0, &mut bytes).unwrap();
    assert_eq!(bytes, pattern(9, 3 * BLOCK));
    let free = fs.free_blocks();
    fs.close(handle).unwrap();
    assert_eq!(fs.free_blocks(), free + 3);
    fs.check().unwrap();
    let again = Fs::mount(disk.settle(), true).unwrap();
    assert!(again.stat(b"/wal").is_err());
    again.check().unwrap();
}

#[test]
fn locks_are_per_handle_and_volatile() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    let first = fs.open(b"/lock", create()).unwrap();
    let second = fs.open(b"/lock", rw()).unwrap();
    fs.try_lock(first, true).unwrap();
    assert_eq!(fs.try_lock(second, true), Err(Error::WouldBlock));
    assert_eq!(fs.try_lock(second, false), Err(Error::WouldBlock));
    fs.close(first).unwrap();
    fs.try_lock(second, false).unwrap();
    let third = fs.open(b"/lock", rw()).unwrap();
    fs.try_lock(third, false).unwrap();
    assert_eq!(fs.try_lock(third, true), Err(Error::WouldBlock));
    drop(fs);
    // A remount (reboot or holder death) starts with no locks.
    let mut again = Fs::mount(disk.settle(), true).unwrap();
    let handle = again.open(b"/lock", rw()).unwrap();
    again.try_lock(handle, true).unwrap();
}

#[test]
fn enospc_fails_whole_and_recovers() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    put(&mut fs, b"/keep", &pattern(5, 5000));
    let capacity = fs.free_blocks() as usize;
    let handle = fs.open(b"/fill", create_new()).unwrap();
    let chunk = pattern(6, BLOCK);
    for index in 0..capacity {
        fs.write_at(handle, (index * BLOCK) as u64, &chunk).unwrap();
    }
    assert_eq!(fs.write_at(handle, (capacity * BLOCK) as u64, b"x"), Err(Error::NoSpace));
    assert_eq!(fs.fstat(handle).unwrap().size, (capacity * BLOCK) as u64);
    // Growth of another file fails whole; the last durable state is intact.
    let other = fs.open(b"/keep", rw()).unwrap();
    assert_eq!(fs.write_at(other, 4000, &pattern(1, 5000)), Err(Error::NoSpace));
    assert_eq!(read_all(&mut fs, b"/keep").unwrap(), pattern(5, 5000));
    fs.close(other).unwrap();
    fs.sync().unwrap();
    // Truncate frees space only once that change is durable.
    fs.set_len(handle, 0).unwrap();
    assert_eq!(fs.free_blocks(), 0);
    fs.sync().unwrap();
    assert_eq!(fs.free_blocks() as usize, capacity);
    fs.close(handle).unwrap();
    put(&mut fs, b"/after", b"ok");
    fs.check().unwrap();
    // Namespace records have their own budget.
    let mut index = 0;
    loop {
        let name = std::format!("/n{index:0>200}");
        match fs.mkdir(name.as_bytes()) {
            Ok(()) => index += 1,
            Err(Error::NoSpace) => break,
            Err(other) => panic!("{other:?}"),
        }
    }
    assert!(index > 100);
    let mut again = Fs::mount(disk.settle(), true).unwrap();
    assert_eq!(read_all(&mut again, b"/keep").unwrap(), pattern(5, 5000));
    assert_eq!(read_all(&mut again, b"/after").unwrap(), b"ok");
    again.check().unwrap();
}

#[test]
fn write_stats_count_commits_only() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    assert_eq!(fs.write_stats(), WriteStats::default());
    fs.mkdir(b"/d").unwrap();
    let after_mkdir = fs.write_stats();
    assert_eq!((after_mkdir.commits, after_mkdir.superblock_sectors), (1, 1));
    assert!(after_mkdir.image_bytes >= SECTOR as u64 && after_mkdir.image_bytes % SECTOR as u64 == 0);
    let handle = fs.open(b"/d/f", create_new()).unwrap();
    fs.write_at(handle, 0, &pattern(1, 20_000)).unwrap();
    // Data writes are not commits; the sync that makes them durable is.
    assert_eq!(fs.write_stats().commits, 2);
    fs.sync().unwrap();
    fs.sync().unwrap();
    let stats = fs.write_stats();
    assert_eq!((stats.commits, stats.superblock_sectors), (3, 3));
    assert!(stats.image_bytes > after_mkdir.image_bytes);
}

#[test]
fn device_failure_poisons() {
    let mut disk = fresh();
    disk.fail_after = Some(disk.writes() + 1);
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    let error = fs.mkdir(b"/d").unwrap_err();
    assert_eq!(error, Error::Device(-5));
    assert_eq!(fs.stat(b"/"), Err(Error::Poisoned));
    assert_eq!(fs.sync(), Err(Error::Poisoned));
}

/// Runs `operation` on a mounted copy, then remounts after every prefix of
/// its writes and hands each crash state to `judge`.
fn every_crash_point(
    setup: impl Fn(&mut Fs<Disk>),
    operation: impl Fn(&mut Fs<Disk>),
    judge: impl Fn(usize, usize, &mut Fs<Disk>),
) -> usize {
    let disk = fresh();
    {
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        setup(&mut fs);
    }
    let base = disk.settle();
    let start = base.writes();
    {
        let mut fs = Fs::mount(base.clone(), true).unwrap();
        operation(&mut fs);
    }
    let total = base.writes();
    for point in start..=total {
        let crashed = base.crash(point);
        let mut fs = Fs::mount(crashed, true).expect("every crash point mounts");
        fs.check().unwrap();
        judge(point - start, total - start, &mut fs);
        // The recovered filesystem stays usable.
        put(&mut fs, b"/probe", b"p");
    }
    total - start
}

#[test]
fn crash_during_rename_noclobber_install() {
    let old = pattern(1, 6000);
    let new = pattern(2, 9000);
    let points = every_crash_point(
        |fs| {
            fs.mkdir(b"/blobs").unwrap();
            put(fs, b"/blobs/other", &old);
        },
        |fs| {
            // NamedTempFile + persist_noclobber + parent sync, as AG does.
            let handle = fs.open(b"/blobs/.tmpA", create_new()).unwrap();
            fs.write_at(handle, 0, &new).unwrap();
            fs.sync().unwrap();
            fs.set_readonly(handle, true).unwrap();
            fs.rename(b"/blobs/.tmpA", b"/blobs/final", true).unwrap();
            fs.sync().unwrap();
            fs.close(handle).unwrap();
            let dir = fs.open(b"/blobs", OpenFlags { read: true, ..OpenFlags::default() }).unwrap();
            fs.sync().unwrap();
            fs.close(dir).unwrap();
        },
        |_, _, fs| {
            let tree = tree(fs);
            assert_eq!(tree.get(b"/blobs/other".as_slice()), Some(&Some(old.clone())));
            let temp = tree.get(b"/blobs/.tmpA".as_slice());
            let fin = tree.get(b"/blobs/final".as_slice());
            match (temp, fin) {
                (None, None) => {}
                (Some(Some(bytes)), None) => {
                    // A temp file may hold any prefix of unsynced data, but
                    // nothing other than the written bytes.
                    assert!(bytes.len() == 0 || bytes.len() == new.len());
                    assert!(bytes.iter().zip(&new).all(|(a, b)| a == b || *a == 0));
                }
                (None, Some(Some(bytes))) => {
                    // The final name only ever carries the complete file.
                    assert_eq!(bytes, &new);
                    assert!(fs.stat(b"/blobs/final").unwrap().readonly);
                }
                other => panic!("both names present: {other:?}"),
            }
        },
    );
    assert!(points > 10);
}

#[test]
fn noclobber_never_replaces() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    put(&mut fs, b"/dest", b"original");
    put(&mut fs, b"/tmp", b"replacement");
    assert_eq!(fs.rename(b"/tmp", b"/dest", true), Err(Error::Exists));
    assert_eq!(read_all(&mut fs, b"/dest").unwrap(), b"original");
    assert_eq!(read_all(&mut fs, b"/tmp").unwrap(), b"replacement");
    // Replacing rename: old or new, never neither, at every crash point.
    let points = every_crash_point(
        |fs| {
            put(fs, b"/dest", b"original");
            put(fs, b"/tmp", b"replacement");
        },
        |fs| fs.rename(b"/tmp", b"/dest", false).unwrap(),
        |_, _, fs| {
            let dest = read_all(fs, b"/dest").unwrap();
            let tmp = read_all(fs, b"/tmp");
            match (dest.as_slice(), tmp) {
                (b"original", Some(tmp)) => assert_eq!(tmp, b"replacement"),
                (b"replacement", None) => {}
                other => panic!("{other:?}"),
            }
        },
    );
    assert!(points > 0);
}

#[test]
fn synced_data_survives_every_later_crash() {
    // Append-and-sync like a WAL; a crash never loses a synced prefix and
    // never shows bytes that were not written.
    let frames: Vec<Vec<u8>> = (0..6).map(|index| pattern(index as u8 + 10, 4120)).collect();
    let synced_writes = std::cell::RefCell::new(Vec::new());
    let disk = fresh();
    let base = disk.settle();
    let start = base.writes();
    {
        let mut fs = Fs::mount(base.clone(), true).unwrap();
        let handle = fs.open(b"/db-wal", create_new()).unwrap();
        let mut offset = 0u64;
        for frame in &frames {
            fs.write_at(handle, offset, frame).unwrap();
            offset += frame.len() as u64;
            fs.sync().unwrap();
            synced_writes.borrow_mut().push((base.writes(), offset));
        }
        fs.set_len(handle, 0).unwrap();
        fs.sync().unwrap();
        synced_writes.borrow_mut().push((base.writes(), 0));
    }
    let all: Vec<u8> = frames.concat();
    let total = base.writes();
    for point in start..=total {
        let mut fs = Fs::mount(base.crash(point), true).unwrap();
        fs.check().unwrap();
        let durable = synced_writes.borrow().iter().rev().find(|(at, _)| *at <= point).map(|(_, len)| *len);
        match read_all(&mut fs, b"/db-wal") {
            None => assert!(durable.is_none()),
            Some(bytes) => {
                if let Some(len) = durable {
                    if len > 0 {
                        assert!(bytes.len() as u64 >= len || point == total, "synced bytes lost");
                    }
                }
                assert!(bytes.len() <= all.len());
                assert_eq!(bytes[..], all[..bytes.len()], "bytes never written");
            }
        }
    }
}

#[test]
fn crash_during_directory_and_unlink_operations() {
    every_crash_point(
        |fs| {
            fs.mkdir(b"/a").unwrap();
            put(fs, b"/a/x", &pattern(1, 5000));
        },
        |fs| {
            fs.mkdir(b"/b").unwrap();
            fs.rename(b"/a/x", b"/b/x", true).unwrap();
            fs.rmdir(b"/a").unwrap();
            put(fs, b"/b/y", &pattern(2, 7000));
            fs.unlink(b"/b/x").unwrap();
        },
        |_, _, fs| {
            let tree = tree(fs);
            // x exists at most once and always whole.
            let places: Vec<_> = [b"/a/x".as_slice(), b"/b/x"].into_iter().filter(|p| tree.contains_key(*p)).collect();
            assert!(places.len() <= 1);
            for place in places {
                assert_eq!(tree[place], Some(pattern(1, 5000)));
            }
            if let Some(Some(y)) = tree.get(b"/b/y".as_slice()) {
                assert!(y.is_empty() || y.len() == 7000);
            }
            if !tree.contains_key(b"/a/x".as_slice()) && !tree.contains_key(b"/b/x".as_slice()) {
                // x is gone only after its unlink, which follows y's sync.
                assert_eq!(tree.get(b"/b/y".as_slice()), Some(&Some(pattern(2, 7000))));
            }
        },
    );
}

fn corrupt_mount(edit: impl FnOnce(&Disk, &Geometry)) -> Result<(), Error> {
    let disk = fresh();
    {
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        fs.mkdir(b"/d").unwrap();
        put(&mut fs, b"/d/f", &pattern(1, 9000));
        put(&mut fs, b"/g", &pattern(2, 100));
    }
    let settled = disk.settle();
    let geometry = Geometry::for_region(REGION).unwrap();
    edit(&settled, &geometry);
    Fs::mount(settled, true).map(|_| ())
}

/// Rewrites the selected image through `change` and re-signs it with a valid
/// digest and superblock, so only the structural checks can refuse it.
fn resign(disk: &Disk, geometry: &Geometry, change: impl FnOnce(&mut Image)) {
    let mut device = disk.clone();
    let (superblock, mut image) = select(&mut device).unwrap();
    change(&mut image);
    let bytes = image.encode();
    let first = geometry.half_first(superblock.seq % 2);
    for (index, chunk) in bytes.chunks(SECTOR).enumerate() {
        disk.poke(first + index as u64, |sector| {
            *sector = [0; SECTOR];
            sector[..chunk.len()].copy_from_slice(chunk);
        });
    }
    let signed = Superblock { image_len: bytes.len() as u32, digest: sha256(&bytes), ..superblock.clone() };
    disk.poke(superblock.seq % 2, |sector| *sector = signed.encode());
}

#[test]
fn corruption_is_refused_never_repaired() {
    assert!(corrupt_mount(|_, _| {}).is_ok());
    let cases: Vec<(&str, Box<dyn Fn(&Disk, &Geometry)>)> = vec![
        ("newest superblock byte", Box::new(|disk, _| {
            let mut device = disk.clone();
            let (superblock, _) = select(&mut device).unwrap();
            disk.poke(superblock.seq % 2, |s| s[30] ^= 1);
        })),
        ("older superblock byte", Box::new(|disk, _| {
            let mut device = disk.clone();
            let (superblock, _) = select(&mut device).unwrap();
            disk.poke((superblock.seq + 1) % 2, |s| s[30] ^= 1);
        })),
        ("blank superblock", Box::new(|disk, _| disk.poke(0, |s| *s = [0; SECTOR]))),
        ("image byte", Box::new(|disk, geometry| {
            let mut device = disk.clone();
            let (superblock, _) = select(&mut device).unwrap();
            disk.poke(geometry.half_first(superblock.seq % 2), |s| s[70] ^= 1);
        })),
        ("duplicated allocation", Box::new(|disk, geometry| resign(disk, geometry, |image| {
            let block = image.records[2].blocks[0];
            image.records[3].blocks[0] = block;
        }))),
        ("block outside the data area", Box::new(|disk, geometry| resign(disk, geometry, |image| {
            image.records[3].blocks[0] = image.geometry.data_blocks;
        }))),
        ("impossible file length", Box::new(|disk, geometry| resign(disk, geometry, |image| {
            image.records[3].size = 999_999;
        }))),
        ("dangling directory entry", Box::new(|disk, geometry| resign(disk, geometry, |image| {
            image.records[2].parent = 77;
        }))),
        ("duplicate name", Box::new(|disk, geometry| resign(disk, geometry, |image| {
            image.records[3].parent = image.records[2].parent;
            image.records[3].name = image.records[2].name.clone();
        }))),
        ("malformed name", Box::new(|disk, geometry| resign(disk, geometry, |image| {
            image.records[3].name = b"a/b".to_vec();
        }))),
        ("stale serial counter", Box::new(|disk, geometry| resign(disk, geometry, |image| {
            image.next_serial = image.records.last().unwrap().serial;
        }))),
        ("directory cycle", Box::new(|disk, geometry| resign(disk, geometry, |image| {
            image.records[1].parent = image.records[1].serial;
        }))),
        ("file as parent", Box::new(|disk, geometry| resign(disk, geometry, |image| {
            image.records[2].parent = image.records[3].serial;
        }))),
        ("sequence gap", Box::new(|disk, _| {
            let mut device = disk.clone();
            let (superblock, image) = select(&mut device).unwrap();
            let bumped = Superblock { seq: superblock.seq + 2, ..superblock.clone() };
            let _ = image;
            disk.poke(bumped.seq % 2, |s| *s = bumped.encode());
        })),
    ];
    for (label, edit) in cases {
        match corrupt_mount(|disk, geometry| edit(disk, geometry)) {
            Err(Error::Corrupt(_)) => {}
            other => panic!("{label}: {other:?}"),
        }
    }
}

/// A crash at any point of a format must leave a region the next boot can
/// still format (the runtime's rule: mount, and format only when the mount
/// finds no filesystem). Nothing is committed until the second superblock.
#[test]
fn crash_during_format_stays_formattable() {
    let mut whole = Disk::new(REGION);
    format(&mut whole, 0x1111).unwrap();
    let total = whole.writes();
    for point in 0..=total {
        let crashed = whole.crash(point);
        let mut device = crashed.clone();
        let fs = match Fs::mount(crashed.clone(), true) {
            Ok(fs) => {
                assert_eq!(point, total, "a partial format mounted at {point}");
                fs
            }
            Err(Error::Unformatted) => {
                format(&mut device, 0x2222).unwrap_or_else(|error| panic!("reformat at {point}: {error:?}"));
                Fs::mount(device.settle(), true).unwrap()
            }
            Err(other) => panic!("crash at write {point} of {total} left {other:?}"),
        };
        fs.check().unwrap();
        assert!(fs.read_dir(b"/").unwrap().is_empty());
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A device whose write count marks points in an operation's history.
trait Counted: Device {
    fn issued(&self) -> usize;
}

impl Counted for Disk {
    fn issued(&self) -> usize {
        self.writes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    serial: u64,
    kind: Kind,
    readonly: bool,
    content: Option<Vec<u8>>,
}

type Tree = BTreeMap<Vec<u8>, Entry>;

/// Every named object with its identity, kind, read-only flag, and content.
fn full_tree<D: Device>(fs: &mut Fs<D>) -> Tree {
    tree(fs)
        .into_iter()
        .map(|(path, content)| {
            let attr = fs.stat(&path).unwrap();
            (path, Entry { serial: attr.serial, kind: attr.kind, readonly: attr.readonly, content })
        })
        .collect()
}

/// Namespace, serials, kinds, read-only flags, and sizes: what a commit
/// fixes, without the content unsynced writes may still change.
fn shape(tree: &Tree) -> Vec<(Vec<u8>, u64, Kind, bool, Option<usize>)> {
    tree.iter()
        .map(|(p, e)| (p.clone(), e.serial, e.kind, e.readonly, e.content.as_ref().map(Vec::len)))
        .collect()
}

struct Commit {
    seq: u64,
    /// Device operations issued before the commit began / when it returned.
    start: usize,
    done: usize,
    tree: Tree,
}

/// Drives a filesystem while recording every commit (with the state it
/// made durable) and every data write (with the object it touched), so a
/// crash or cut state can be judged against exactly what was promised.
struct Run<D: Counted> {
    fs: Fs<D>,
    commits: Vec<Commit>,
    touched: Vec<(usize, u64)>,
}

impl<D: Counted> Run<D> {
    fn new(mut fs: Fs<D>) -> Self {
        let done = fs.device().issued();
        let tree = full_tree(&mut fs);
        let seq = fs.sequence();
        Self { fs, commits: vec![Commit { seq, start: done, done, tree }], touched: Vec::new() }
    }

    fn now(&mut self) -> usize {
        self.fs.device().issued()
    }

    /// One filesystem call; a sequence change records the commit.
    fn op<R>(&mut self, f: impl FnOnce(&mut Fs<D>) -> R) -> R {
        let start = self.now();
        let seq = self.fs.sequence();
        let result = f(&mut self.fs);
        if self.fs.sequence() != seq {
            let done = self.now();
            let tree = full_tree(&mut self.fs);
            self.commits.push(Commit { seq: self.fs.sequence(), start, done, tree });
        }
        result
    }

    fn write(&mut self, handle: u64, offset: u64, data: &[u8]) -> Result<usize, Error> {
        let serial = self.fs.fstat(handle)?.serial;
        let at = self.now();
        self.touched.push((at, serial));
        self.fs.write_at(handle, offset, data)
    }

    fn set_len(&mut self, handle: u64, size: u64) -> Result<(), Error> {
        let attr = self.fs.fstat(handle)?;
        // Only growth writes (its zero fill). A shrink writes nothing, so the
        // judge keeps checking the object's content: blocks a shrink frees in
        // memory must not be reused before the shrink's commit is durable.
        if size > attr.size {
            let at = self.now();
            self.touched.push((at, attr.serial));
        }
        self.fs.set_len(handle, size)
    }

    fn sync(&mut self) {
        self.op(|fs| fs.sync()).unwrap();
    }

    fn put(&mut self, path: &[u8], bytes: &[u8]) {
        let handle = self.op(|fs| fs.open(path, create())).unwrap();
        self.set_len(handle, 0).unwrap();
        self.write(handle, 0, bytes).unwrap();
        self.sync();
        self.fs.close(handle).unwrap();
    }

    /// The last commit complete at `point` and, if the next commit's
    /// superblock write is already issued, that commit in flight.
    fn legal_at(&self, point: usize) -> Vec<&Commit> {
        let k = self.commits.iter().rposition(|commit| commit.done <= point).unwrap();
        let mut legal = vec![&self.commits[k]];
        if let Some(next) = self.commits.get(k + 1) {
            if point + 1 >= next.done {
                legal.push(next);
            }
        }
        legal
    }

    /// Whether `serial` had a data write at or after `since` and before `point`.
    fn touched_between(&self, serial: u64, since: usize, point: usize) -> bool {
        self.touched.iter().any(|(at, object)| *object == serial && *at >= since && *at < point)
    }
}

/// Random histories of open, unlinked-while-open, renamed, truncated,
/// regrown, and space-exhausting files. `big` bounds the occasional large
/// write (base, spread).
fn random_history<D: Counted>(run: &mut Run<D>, seed: u64, ops: usize, big: (u64, u64)) {
    const PATHS: [&[u8]; 5] = [b"/a", b"/b", b"/d/c", b"/d/e", b"/g"];
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let mut handles: Vec<u64> = Vec::new();
    for _ in 0..ops {
        let path = PATHS[rng.below(PATHS.len() as u64) as usize];
        match rng.below(10) {
            0..=2 => {
                if let Ok(handle) = run.op(|fs| fs.open(path, create())) {
                    handles.push(handle);
                }
            }
            3 | 4 if !handles.is_empty() => {
                let handle = handles[rng.below(handles.len() as u64) as usize];
                let size = run.fs.fstat(handle).unwrap().size;
                let offset = rng.below(size + 9000);
                let len = if rng.below(8) == 0 { big.0 + rng.below(big.1) } else { 1 + rng.below(9000) } as usize;
                let _ = run.write(handle, offset, &pattern(rng.next() as u8, len));
            }
            5 if !handles.is_empty() => {
                let handle = handles[rng.below(handles.len() as u64) as usize];
                let size = run.fs.fstat(handle).unwrap().size;
                let _ = run.set_len(handle, rng.below(size + 12_000));
            }
            6 => run.sync(),
            7 => {
                let to = PATHS[rng.below(PATHS.len() as u64) as usize];
                let noreplace = rng.below(2) == 0;
                let _ = run.op(|fs| fs.rename(path, to, noreplace));
            }
            8 => {
                let _ = run.op(|fs| fs.unlink(path));
            }
            _ if !handles.is_empty() => {
                let index = rng.below(handles.len() as u64) as usize;
                run.fs.close(handles.swap_remove(index)).unwrap();
            }
            _ => {}
        }
        run.fs.check().unwrap();
    }
}

/// A crash after every acknowledged write must mount, keep block sets
/// consistent, expose exactly the last committed namespace, serials, and
/// lengths, and keep the committed content of every object no later data
/// operation touched.
#[test]
fn random_histories_recover_the_last_commit() {
    for seed in 1..=40u64 {
        let disk = fresh();
        let mut run = Run::new(Fs::mount(disk.clone(), true).unwrap());
        run.op(|fs| fs.mkdir(b"/d")).unwrap();
        random_history(&mut run, seed, 40, (400_000, 1_200_000));
        for point in run.commits[0].done..=disk.writes() {
            let expected = run.commits.iter().rev().find(|commit| commit.done <= point).unwrap();
            let mut recovered = Fs::mount(disk.crash(point), true)
                .unwrap_or_else(|error| panic!("seed {seed} point {point}: {error:?}"));
            recovered.check().unwrap();
            let view = full_tree(&mut recovered);
            assert_eq!(shape(&view), shape(&expected.tree), "seed {seed} point {point}: namespace or lengths");
            for (path, entry) in &expected.tree {
                if !run.touched_between(entry.serial, expected.done, point) {
                    assert_eq!(&view[path].content, &entry.content, "seed {seed} point {point}: content of {path:?}");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Device law (docs/POWER-LOSS.md): a volatile write cache in aligned units
// that a completed flush makes stable. `CacheDisk` records the operation
// history; `Replay` rebuilds, at any cut point, the stable state and each
// unit's images since the last completed flush; `CutDisk` is one outcome.
// ---------------------------------------------------------------------

#[derive(Clone)]
enum Event {
    Write(u64, [u8; SECTOR]),
    Flush,
}

#[derive(Clone)]
struct CacheDisk {
    sectors: u64,
    state: Rc<RefCell<(BTreeMap<u64, [u8; SECTOR]>, Vec<Event>)>>,
}

impl CacheDisk {
    fn new(sectors: u64) -> Self {
        Self { sectors, state: Rc::default() }
    }

    fn log(&self) -> Vec<Event> {
        self.state.borrow().1.clone()
    }
}

impl Device for CacheDisk {
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        assert!(sector < self.sectors);
        *buffer = self.state.borrow().0.get(&sector).copied().unwrap_or([0; SECTOR]);
        Ok(())
    }
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        assert!(sector < self.sectors);
        let mut state = self.state.borrow_mut();
        state.0.insert(sector, *buffer);
        state.1.push(Event::Write(sector, *buffer));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.state.borrow_mut().1.push(Event::Flush);
        Ok(())
    }
}

impl Counted for CacheDisk {
    fn issued(&self) -> usize {
        self.state.borrow().1.len()
    }
}

/// The device law's state machine over an event log: `stable` is what the
/// last completed flush covered; `dirty` holds, per unit written since,
/// the unit's image after each of those writes, in order.
struct Replay {
    unit: u64,
    stable: BTreeMap<u64, [u8; SECTOR]>,
    dirty: BTreeMap<u64, Vec<Vec<[u8; SECTOR]>>>,
}

impl Replay {
    fn new(unit: u64) -> Self {
        Self { unit, stable: BTreeMap::new(), dirty: BTreeMap::new() }
    }

    fn stable_unit(&self, unit: u64) -> Vec<[u8; SECTOR]> {
        (0..self.unit).map(|k| self.stable.get(&(unit * self.unit + k)).copied().unwrap_or([0; SECTOR])).collect()
    }

    fn apply(&mut self, event: &Event) {
        match event {
            Event::Write(lba, sector) => {
                let unit = lba / self.unit;
                let mut image = match self.dirty.get(&unit) {
                    Some(history) => history.last().unwrap().clone(),
                    None => self.stable_unit(unit),
                };
                image[(lba % self.unit) as usize] = *sector;
                self.dirty.entry(unit).or_default().push(image);
            }
            Event::Flush => {
                for (unit, history) in core::mem::take(&mut self.dirty) {
                    for (k, sector) in history.last().unwrap().iter().enumerate() {
                        self.stable.insert(unit * self.unit + k as u64, *sector);
                    }
                }
            }
        }
    }

    /// Every choice of one state per dirty unit (index 0 = stable, `j` =
    /// after its `j`th write) when there are at most 4096, otherwise a
    /// seeded sample of 256 that always holds all-stable and all-latest.
    fn outcomes(&self, seed: u64) -> Vec<Vec<usize>> {
        let radix: Vec<usize> = self.dirty.values().map(|history| history.len() + 1).collect();
        let product = radix.iter().try_fold(1usize, |acc, r| acc.checked_mul(*r).filter(|p| *p <= 4096));
        match product {
            Some(total) => (0..total)
                .map(|mut index| {
                    radix
                        .iter()
                        .map(|r| {
                            let digit = index % r;
                            index /= r;
                            digit
                        })
                        .collect()
                })
                .collect(),
            None => {
                let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
                let mut out = vec![vec![0; radix.len()], radix.iter().map(|r| r - 1).collect()];
                while out.len() < 256 {
                    out.push(radix.iter().map(|r| rng.below(*r as u64) as usize).collect());
                }
                out
            }
        }
    }

    /// The device after a cut resolved by `choice`.
    fn cut(&self, choice: &[usize]) -> CutDisk<'_> {
        let mut overlay = BTreeMap::new();
        for ((unit, history), digit) in self.dirty.iter().zip(choice) {
            if *digit > 0 {
                overlay.insert(*unit, &history[digit - 1]);
            }
        }
        CutDisk { unit: self.unit, stable: &self.stable, overlay, torn: None, writes: BTreeMap::new() }
    }
}

/// One outcome of a cut: stable media plus the chosen image of each dirty
/// unit, optionally one torn unit, and whatever the mounted filesystem
/// writes afterwards.
struct CutDisk<'a> {
    unit: u64,
    stable: &'a BTreeMap<u64, [u8; SECTOR]>,
    overlay: BTreeMap<u64, &'a Vec<[u8; SECTOR]>>,
    torn: Option<(u64, [u8; SECTOR])>,
    writes: BTreeMap<u64, [u8; SECTOR]>,
}

impl Device for CutDisk<'_> {
    fn sectors(&self) -> u64 {
        REGION
    }
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        assert!(sector < REGION);
        if let Some(written) = self.writes.get(&sector) {
            *buffer = *written;
            return Ok(());
        }
        if let Some((unit, garbage)) = self.torn {
            if sector / self.unit == unit {
                *buffer = garbage;
                buffer[..8].copy_from_slice(&sector.to_le_bytes());
                return Ok(());
            }
        }
        *buffer = match self.overlay.get(&(sector / self.unit)) {
            Some(image) => image[(sector % self.unit) as usize],
            None => self.stable.get(&sector).copied().unwrap_or([0; SECTOR]),
        };
        Ok(())
    }
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        assert!(sector < REGION);
        self.writes.insert(sector, *buffer);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

fn law_run() -> Run<CacheDisk> {
    let mut disk = CacheDisk::new(REGION);
    format(&mut disk, 0xabcd).unwrap();
    Run::new(Fs::mount(disk, true).unwrap())
}

/// Judges one mounted cut state against the commits `run` recorded: the
/// sequence names a legal commit, the shape is exactly that commit's, and
/// every object without a later data write carries that commit's content.
fn judge_law<D: Device>(run: &Run<CacheDisk>, point: usize, fs: &mut Fs<D>, label: &str) {
    fs.check().unwrap_or_else(|error| panic!("{label} cut {point}: {error}"));
    let legal = run.legal_at(point);
    let expected = legal
        .iter()
        .find(|commit| commit.seq == fs.sequence())
        .unwrap_or_else(|| {
            panic!(
                "{label} cut {point}: mounted sequence {} is neither the last complete commit {} nor one in flight {:?}",
                fs.sequence(),
                legal[0].seq,
                legal.get(1).map(|c| c.seq)
            )
        });
    let view = full_tree(fs);
    assert_eq!(shape(&view), shape(&expected.tree), "{label} cut {point}: state differs from commit {}", expected.seq);
    for (path, entry) in &expected.tree {
        if !run.touched_between(entry.serial, expected.start, point) {
            assert_eq!(&view[path].content, &entry.content, "{label} cut {point}: content of {path:?}");
        }
    }
}

/// Every cut point from `from` on, every (or a sample of) outcome: mount
/// must succeed and show a legal state; the mount stays usable. Returns
/// (cut points, outcomes judged).
fn law_sweep(run: &mut Run<CacheDisk>, unit: u64, from: usize, label: &str) -> (usize, usize) {
    let log = run.fs.device().log();
    let mut replay = Replay::new(unit);
    let (mut cuts, mut judged) = (0, 0);
    for point in 0..=log.len() {
        if point > 0 {
            replay.apply(&log[point - 1]);
        }
        if point < from {
            continue;
        }
        cuts += 1;
        for (index, choice) in replay.outcomes(point as u64).iter().enumerate() {
            judged += 1;
            let disk = replay.cut(choice);
            let mut fs = Fs::mount(disk, true)
                .unwrap_or_else(|error| panic!("{label} U={unit} cut {point} outcome {index}: mount refused {error:?}"));
            judge_law(run, point, &mut fs, label);
            if index < 2 {
                put(&mut fs, b"/probe", b"p");
                assert_eq!(read_all(&mut fs, b"/probe").unwrap(), b"p");
            }
        }
    }
    (cuts, judged)
}

fn ro() -> OpenFlags {
    OpenFlags { read: true, ..OpenFlags::default() }
}

type Step = Box<dyn Fn(&mut Run<CacheDisk>)>;

/// The named operations of the operation contract, each with the state
/// it starts from.
fn law_operations() -> Vec<(&'static str, Step, Step)> {
    let blob_old = pattern(1, 6000);
    let blob_new = pattern(2, 9000);
    vec![
        ("mkdir", Box::new(|_| {}), Box::new(|run| run.op(|fs| fs.mkdir(b"/d")).unwrap())),
        ("create", Box::new(|run| run.op(|fs| fs.mkdir(b"/d")).unwrap()), Box::new(|run| {
            let handle = run.op(|fs| fs.open(b"/d/f", create())).unwrap();
            run.fs.close(handle).unwrap();
        })),
        ("create_new", Box::new(|run| run.op(|fs| fs.mkdir(b"/d")).unwrap()), Box::new(|run| {
            let handle = run.op(|fs| fs.open(b"/d/g", create_new())).unwrap();
            run.fs.close(handle).unwrap();
        })),
        ("unlink", Box::new(|run| {
            run.op(|fs| fs.mkdir(b"/d")).unwrap();
            run.put(b"/d/f", &pattern(3, 5000));
        }), Box::new(|run| run.op(|fs| fs.unlink(b"/d/f")).unwrap())),
        ("rmdir", Box::new(|run| run.op(|fs| fs.mkdir(b"/d")).unwrap()), Box::new(|run| run.op(|fs| fs.rmdir(b"/d")).unwrap())),
        ("rename", Box::new(|run| {
            run.put(b"/a", &pattern(4, 3000));
            run.put(b"/b", &pattern(5, 7000));
        }), Box::new(|run| run.op(|fs| fs.rename(b"/a", b"/b", false)).unwrap())),
        ("rename_noclobber", Box::new(|run| run.put(b"/a", &pattern(4, 3000))), Box::new(|run| {
            run.op(|fs| fs.rename(b"/a", b"/c", true)).unwrap()
        })),
        ("set_readonly", Box::new(|run| run.put(b"/f", &pattern(6, 2000))), Box::new(|run| {
            let handle = run.op(|fs| fs.open(b"/f", rw())).unwrap();
            run.op(|fs| fs.set_readonly(handle, true)).unwrap();
            run.fs.close(handle).unwrap();
        })),
        ("write_sync", Box::new(|run| run.put(b"/f", &pattern(7, 6000))), Box::new(|run| {
            let handle = run.op(|fs| fs.open(b"/f", rw())).unwrap();
            run.write(handle, 2000, &pattern(8, 3000)).unwrap();
            run.sync();
            run.fs.close(handle).unwrap();
        })),
        ("truncate_sync", Box::new(|run| run.put(b"/f", &pattern(7, 9000))), Box::new(|run| {
            let handle = run.op(|fs| fs.open(b"/f", rw())).unwrap();
            run.set_len(handle, 1000).unwrap();
            run.sync();
            run.fs.close(handle).unwrap();
        })),
        ("grow_sync", Box::new(|run| run.put(b"/f", &pattern(7, 1000))), Box::new(|run| {
            let handle = run.op(|fs| fs.open(b"/f", rw())).unwrap();
            run.set_len(handle, 9000).unwrap();
            run.sync();
            run.fs.close(handle).unwrap();
        })),
        ("blob_install", Box::new(move |run| {
            run.op(|fs| fs.mkdir(b"/blobs")).unwrap();
            run.put(b"/blobs/other", &blob_old);
        }), Box::new(move |run| {
            // NamedTempFile + persist_noclobber + parent sync, as AG does.
            let handle = run.op(|fs| fs.open(b"/blobs/.tmpA", create_new())).unwrap();
            run.write(handle, 0, &blob_new).unwrap();
            run.sync();
            run.op(|fs| fs.set_readonly(handle, true)).unwrap();
            run.op(|fs| fs.rename(b"/blobs/.tmpA", b"/blobs/final", true)).unwrap();
            run.sync();
            run.fs.close(handle).unwrap();
            let dir = run.op(|fs| fs.open(b"/blobs", ro())).unwrap();
            run.sync();
            run.fs.close(dir).unwrap();
        })),
    ]
}

/// Every named operation, under both unit sizes, at every cut point and
/// every (or a sample of) outcomes the law allows: mount succeeds and shows
/// exactly the last complete commit or the one in flight.
#[test]
fn device_law_holds_for_every_operation() {
    for unit in [1u64, 8] {
        for (label, setup, operation) in law_operations() {
            let mut run = law_run();
            setup(&mut run);
            run.sync();
            let from = run.now();
            operation(&mut run);
            let (cuts, judged) = law_sweep(&mut run, unit, from, label);
            std::println!("LAW U={unit} {label}: cuts={cuts} outcomes={judged}");
            assert!(cuts > 3, "{label}: no device operations");
        }
    }
}

/// The random histories under the law: every cut point after the setup,
/// with the occasional large write bounded so every outcome is judged.
#[test]
fn device_law_holds_for_random_histories() {
    for unit in [1u64, 8] {
        let (mut cuts, mut judged) = (0, 0);
        for seed in 1..=12u64 {
            let mut run = law_run();
            run.op(|fs| fs.mkdir(b"/d")).unwrap();
            let from = run.now();
            random_history(&mut run, seed, 30, (40_000, 120_000));
            let (c, j) = law_sweep(&mut run, unit, from, &std::format!("random seed {seed}"));
            cuts += c;
            judged += j;
        }
        std::println!("LAW U={unit} random histories: cuts={cuts} outcomes={judged}");
    }
}

/// A cut anywhere in a format leaves a region that mounts empty or reads
/// as unformatted and formats again, under every outcome.
#[test]
fn device_law_holds_for_format() {
    for unit in [1u64, 8] {
        let mut disk = CacheDisk::new(REGION);
        format(&mut disk, 0x1111).unwrap();
        let log = disk.log();
        let mut replay = Replay::new(unit);
        let mut judged = 0;
        for point in 0..=log.len() {
            if point > 0 {
                replay.apply(&log[point - 1]);
            }
            for choice in replay.outcomes(point as u64) {
                judged += 1;
                let fs = match Fs::mount(replay.cut(&choice), true) {
                    Ok(fs) => fs,
                    Err(Error::Unformatted) => {
                        let mut device = replay.cut(&choice);
                        format(&mut device, 0x2222).unwrap_or_else(|error| panic!("U={unit} cut {point}: reformat {error:?}"));
                        Fs::mount(device, true).unwrap()
                    }
                    Err(other) => panic!("U={unit} cut {point} {choice:?}: {other:?}"),
                };
                fs.check().unwrap();
                assert!(fs.read_dir(b"/").unwrap().is_empty());
            }
        }
        std::println!("LAW U={unit} format: cuts={} outcomes={judged}", log.len() + 1);
    }
}

/// Outside the law: the unit being written at the cut holds garbage (a
/// pattern, or zeros), every other dirty unit stable or latest. Mount
/// must refuse or show a law-legal state, never anything else. Recorded
/// per operation and per region of the torn unit, to characterize it.
#[test]
fn torn_unit_refuses_or_stays_legal() {
    let geometry = Geometry::for_region(REGION).unwrap();
    let mut table: BTreeMap<(u64, &str, &str, &str), usize> = BTreeMap::new();
    for unit in [1u64, 8] {
        for (label, setup, operation) in law_operations() {
            let mut run = law_run();
            setup(&mut run);
            run.sync();
            let from = run.now();
            operation(&mut run);
            let log = run.fs.device().log();
            let mut replay = Replay::new(unit);
            for point in 1..=log.len() {
                replay.apply(&log[point - 1]);
                let Event::Write(lba, _) = log[point - 1] else { continue };
                if point < from {
                    continue;
                }
                let region = if lba < 2 {
                    "superblock"
                } else if lba < geometry.data_first {
                    "image"
                } else {
                    "data"
                };
                let extremes = [vec![0; replay.dirty.len()], replay.dirty.values().map(Vec::len).collect()];
                for choice in &extremes {
                    for garbage in [[0xa5u8; SECTOR], [0u8; SECTOR]] {
                        let mut disk = replay.cut(choice);
                        disk.torn = Some((lba / unit, garbage));
                        let outcome = match Fs::mount(disk, true) {
                            Ok(mut fs) => {
                                judge_law(&run, point, &mut fs, label);
                                "legal"
                            }
                            Err(Error::Corrupt(_)) => "refused",
                            Err(Error::Unformatted) => "unformatted",
                            Err(other) => panic!("{label} U={unit} cut {point}: {other:?}"),
                        };
                        *table.entry((unit, label, region, outcome)).or_default() += 1;
                    }
                }
            }
        }
    }
    for ((unit, label, region, outcome), count) in &table {
        std::println!("TORN U={unit} {label} {region}: {outcome}={count}");
    }
    // A torn superblock write is always refused: the old slot alone never
    // mounts (no fallback) and the torn one never validates.
    for ((_, _, region, outcome), _) in &table {
        if *region == "superblock" {
            assert_eq!(*outcome, "refused");
        }
    }
}

/// Free-after-commit, directly: a file filling the whole data area is
/// synced, then truncated in memory only, and another file grows. The
/// crash state is the last commit, so the truncated file must still hold
/// every byte it had; its blocks must not have been handed to the other.
#[test]
fn truncated_blocks_are_not_reused_before_commit() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    let other = fs.open(b"/y", create_new()).unwrap();
    let fill = fs.open(b"/fill", create_new()).unwrap();
    let capacity = fs.free_blocks() as usize;
    let chunk = pattern(6, BLOCK);
    for index in 0..capacity {
        fs.write_at(fill, (index * BLOCK) as u64, &chunk).unwrap();
    }
    fs.sync().unwrap();
    fs.set_len(fill, 0).unwrap();
    assert_eq!(fs.write_at(other, 0, &pattern(9, 2 * BLOCK)), Err(Error::NoSpace));
    let mut again = Fs::mount(disk.crash(disk.writes()), true).unwrap();
    let content = read_all(&mut again, b"/fill").unwrap();
    assert_eq!(content.len(), capacity * BLOCK);
    for index in 0..capacity {
        assert_eq!(&content[index * BLOCK..(index + 1) * BLOCK], &chunk[..], "block {index}");
    }
}

/// Authority to write is checked at each write, against the object's
/// current state; a handle opened while the object was writable cannot
/// spend that permission after it became read-only, and no crash point can
/// make the refused bytes appear.
#[test]
fn read_only_withdraws_open_write_handles() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    let handle = fs.open(b"/blob", create_new()).unwrap();
    fs.write_at(handle, 0, b"evidence").unwrap();
    fs.set_readonly(handle, true).unwrap();
    assert_eq!(fs.write_at(handle, 0, b"tampered"), Err(Error::Denied));
    assert_eq!(fs.set_len(handle, 0), Err(Error::Denied));
    fs.set_readonly(handle, false).unwrap();
    fs.write_at(handle, 8, b"!").unwrap();
    fs.close(handle).unwrap();
    assert_eq!(read_all(&mut fs, b"/blob").unwrap(), b"evidence!");

    every_crash_point(
        |fs| put(fs, b"/blob", b"evidence"),
        |fs| {
            let handle = fs.open(b"/blob", rw()).unwrap();
            fs.set_readonly(handle, true).unwrap();
            assert_eq!(fs.write_at(handle, 0, b"tampered"), Err(Error::Denied));
            fs.sync().unwrap();
            fs.close(handle).unwrap();
        },
        |_, _, fs| {
            assert_eq!(read_all(fs, b"/blob").unwrap(), b"evidence");
        },
    );
}


#[test]
fn remove_tree_is_one_commit_whatever_the_shape() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    fs.mkdir(b"/keep").unwrap();
    put(&mut fs, b"/keep/f", b"kept");
    fs.mkdir(b"/t").unwrap();
    // Wide: many files in one directory.
    fs.mkdir(b"/t/wide").unwrap();
    for index in 0..600 {
        // Empty, like most scratch files: the region is small.
        let path = std::format!("/t/wide/f{index}");
        let handle = fs.open(path.as_bytes(), create()).unwrap();
        fs.close(handle).unwrap();
    }
    // Deep: a chain far deeper than a recursive walk should rely on.
    let mut deep = b"/t".to_vec();
    for _ in 0..400 {
        deep.extend_from_slice(b"/d");
        fs.mkdir(&deep).unwrap();
    }
    put(&mut fs, &[&deep[..], b"/leaf"].concat(), b"leaf");
    let free_before = fs.free_blocks();
    let commits = fs.write_stats().commits;
    assert_eq!(fs.remove_tree(b"/t", false).unwrap(), 1 + 600 + 400 + 1);
    assert_eq!(fs.write_stats().commits, commits + 1);
    assert!(fs.read_dir(b"/t").unwrap().is_empty());
    assert!(fs.free_blocks() > free_before);
    fs.check().unwrap();
    // `and_self` takes the directory too; the root never.
    fs.mkdir(b"/t/again").unwrap();
    assert_eq!(fs.remove_tree(b"/t", true).unwrap(), 2);
    assert_eq!(fs.stat(b"/t"), Err(Error::NotFound));
    assert_eq!(fs.remove_tree(b"/", true), Err(Error::Invalid));
    assert_eq!(fs.remove_tree(b"/keep/f", false), Err(Error::NotDir));
    // Nothing below: no commit.
    let commits = fs.write_stats().commits;
    fs.mkdir(b"/empty").unwrap();
    assert_eq!(fs.remove_tree(b"/empty", false).unwrap(), 0);
    assert_eq!(fs.write_stats().commits, commits + 1);
    drop(fs);
    let mut fs = Fs::mount(disk.settle(), true).unwrap();
    fs.check().unwrap();
    assert_eq!(read_all(&mut fs, b"/keep/f").unwrap(), b"kept");
    assert_eq!(fs.stat(b"/t"), Err(Error::NotFound));
}

#[test]
fn remove_tree_open_file_lives_on_unnamed() {
    let disk = fresh();
    let mut fs = Fs::mount(disk, true).unwrap();
    fs.mkdir(b"/s").unwrap();
    put(&mut fs, b"/s/open", b"still readable");
    let handle = fs.open(b"/s/open", rw()).unwrap();
    assert_eq!(fs.remove_tree(b"/s", true).unwrap(), 2);
    assert_eq!(fs.fstat(handle).unwrap().links, 0);
    let mut buffer = [0u8; 14];
    assert_eq!(fs.read_at(handle, 0, &mut buffer).unwrap(), 14);
    assert_eq!(&buffer, b"still readable");
    fs.close(handle).unwrap();
    fs.check().unwrap();
}

#[test]
fn crash_during_remove_tree_exposes_all_or_nothing() {
    every_crash_point(
        |fs| {
            fs.mkdir(b"/s").unwrap();
            fs.mkdir(b"/s/d").unwrap();
            for index in 0..20 {
                put(fs, std::format!("/s/d/f{index}").as_bytes(), &pattern(index as u8, 700));
            }
            put(fs, b"/s/top", &pattern(99, 3000));
        },
        |fs| {
            fs.remove_tree(b"/s", true).unwrap();
        },
        |_, _, fs| {
            let tree = tree(fs);
            let below: Vec<_> = tree.keys().filter(|path| path.starts_with(b"/s")).collect();
            // Either the whole subtree, intact, or none of it.
            if below.is_empty() {
                return;
            }
            assert_eq!(below.len(), 1 + 1 + 20 + 1, "{below:?}");
            assert_eq!(tree[b"/s/top".as_slice()], Some(pattern(99, 3000)));
            for index in 0..20 {
                assert_eq!(tree[std::format!("/s/d/f{index}").as_bytes()], Some(pattern(index as u8, 700)));
            }
        },
    );
}

/// Repair of audit finding D4 (kernel docs/architecture-audit-20261002): a
/// reserve of the object budget that ordinary creation cannot consume, so
/// the file server can always make a session's scratch directory on a
/// full filesystem and the operator can get in to delete things.
#[test]
fn a_reserve_keeps_room_for_reserved_directories_on_a_full_filesystem() {
    let disk = fresh();
    let mut fs = Fs::mount(disk, true).unwrap();
    fs.mkdir(b"/tmp").unwrap();
    fs.mkdir(b"/home").unwrap();
    // Room for two scratch directories named like the file server's.
    let one = crate::image::record_bytes(b"session-100".len());
    fs.set_reserve(2 * one);
    let mut made = 0u32;
    loop {
        let name = std::format!("/home/{made:08}");
        match fs.open(name.as_bytes(), create_new()) {
            Ok(handle) => {
                fs.close(handle).unwrap();
                made += 1;
            }
            Err(Error::NoSpace) => break,
            Err(other) => panic!("{other:?}"),
        }
    }
    assert!(made > 0);
    // Ordinary creation is refused at the reserve, directories included.
    assert_eq!(fs.mkdir(b"/tmp/session-100"), Err(Error::NoSpace));
    assert_eq!(fs.open(b"/home/one-more", create_new()).err(), Some(Error::NoSpace));
    // Reserved creation uses the reserve, and only the reserve.
    fs.mkdir_reserved(b"/tmp/session-100").unwrap();
    fs.mkdir_reserved(b"/tmp/session-101").unwrap();
    assert_eq!(fs.mkdir_reserved(b"/tmp/session-102"), Err(Error::NoSpace));
    // Deleting frees budget for ordinary creation again (four records:
    // the reserve's two directories sit above the ordinary limit now).
    for name in [&b"/home/00000000"[..], b"/home/00000001", b"/home/00000002", b"/home/00000003"] {
        fs.unlink(name).unwrap();
    }
    let handle = fs.open(b"/home/after", create_new()).unwrap();
    fs.close(handle).unwrap();
    // The reserve is this mount's policy, not the format's: a fresh mount
    // without one sees the whole budget.
    let disk = fs.into_device();
    let mut fs = Fs::mount(disk, true).unwrap();
    assert_eq!(fs.mkdir_reserved(b"/tmp/session-102"), fs.mkdir(b"/tmp/session-103"));
}

/// A small committed image, rendered as text: a header line, then one
/// `LBA HEX` line per nonzero sector of the region. The host reader's tests
/// (`scripts/test_absd_fs.py`) decode the same files.
fn render_sectors(disk: &Disk) -> std::string::String {
    use std::fmt::Write;
    let mut device = disk.clone();
    let mut out = std::format!("absd-fs sectors {}\n", disk.sectors);
    let mut sector = [0u8; SECTOR];
    for lba in 0..disk.sectors {
        device.read(lba, &mut sector).unwrap();
        if sector.iter().any(|byte| *byte != 0) {
            write!(out, "{lba} ").unwrap();
            for byte in sector {
                write!(out, "{byte:02x}").unwrap();
            }
            out.push('\n');
        }
    }
    out
}

fn parse_sectors(text: &str) -> Disk {
    let mut lines = text.lines();
    let sectors = lines.next().unwrap().strip_prefix("absd-fs sectors ").unwrap().parse().unwrap();
    let disk = Disk::new(sectors);
    for line in lines {
        let (lba, hex) = line.split_once(' ').unwrap();
        let mut sector = [0u8; SECTOR];
        for (index, byte) in sector.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap();
        }
        disk.poke(lba.parse().unwrap(), |s| *s = sector);
    }
    disk
}

const FIXTURE_ID: u64 = 0x0123_4567_89ab_cdef;
const FIXTURE_REGION: u64 = 512;

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

/// Compares `disk` with the committed fixture `name`; with
/// `ABSD_FS_WRITE_FIXTURES=1` in the environment, rewrites it instead.
fn golden(name: &str, disk: &Disk) {
    let rendered = render_sectors(disk);
    let path = fixture_path(name);
    if std::env::var_os("ABSD_FS_WRITE_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap();
    assert!(committed == rendered, "{name} differs from what this library writes");
}

/// The fixture's namespace: a directory, a file in it, a two-sector
/// read-only file, and a removed file (so the image has a history).
fn build_fixture(fs: &mut Fs<Disk>) {
    fs.mkdir(b"/d").unwrap();
    put(fs, b"/d/f", b"hello\n");
    put(fs, b"/gone", b"x");
    put(fs, b"/g", &pattern(3, 600));
    fs.set_readonly_path(b"/g", true).unwrap();
    fs.unlink(b"/gone").unwrap();
}

fn format_one_fixture() -> Disk {
    parse_sectors(&std::fs::read_to_string(fixture_path("format1.sectors")).unwrap())
}

/// `testdata/format1.sectors` was written by the format-1 library (commit
/// a4faa35) through `build_fixture`. Format 2 never reads it, never repairs
/// it, and never formats over it.
#[test]
fn format_one_is_refused_by_name() {
    let disk = format_one_fixture();
    assert!(matches!(Fs::mount(disk.clone(), true), Err(Error::UnsupportedFormat)));
    assert!(matches!(Fs::mount(disk.clone(), false), Err(Error::UnsupportedFormat)));
    assert_eq!(inspect(&mut disk.clone()), Err(Error::UnsupportedFormat));
    let mut device = disk.clone();
    assert_eq!(format(&mut device, 9), Err(Error::NotBlank));
    assert_eq!(device.writes(), 0, "refusal wrote to the device");
}

/// Any other version is refused the same way: a later magic, or this
/// magic with another version word under a valid checksum.
#[test]
fn other_versions_are_refused_by_name() {
    let later = fresh();
    for slot in 0..2 {
        later.poke(slot, |s| {
            s[7] = b'3';
            let check = image::sha256(&s[..SECTOR - 32]);
            s[SECTOR - 32..].copy_from_slice(&check);
        });
    }
    assert!(matches!(Fs::mount(later, true), Err(Error::UnsupportedFormat)));
    let word = fresh();
    for slot in 0..2 {
        word.poke(slot, |s| {
            s[8..12].copy_from_slice(&7u32.to_le_bytes());
            let check = image::sha256(&s[..SECTOR - 32]);
            s[SECTOR - 32..].copy_from_slice(&check);
        });
    }
    assert!(matches!(Fs::mount(word, true), Err(Error::UnsupportedFormat)));
    // A damaged format-2 superblock is still corruption, not a version.
    let damaged = fresh();
    damaged.poke(1, |s| s[20] ^= 1);
    assert!(matches!(Fs::mount(damaged, true), Err(Error::Corrupt(_))));
}

#[test]
fn format_two_records_carry_mtime() {
    assert_eq!(image::VERSION, 2);
    assert_eq!(image::RECORD_BYTES, 40);
    assert_eq!(image::record_bytes(5), 45);
    let mut disk = Disk::new(FIXTURE_REGION);
    format(&mut disk, FIXTURE_ID).unwrap();
    let settled = disk.settle();
    let mut sector = [0u8; SECTOR];
    settled.clone().read(0, &mut sector).unwrap();
    assert_eq!(&sector[..12], b"ABSDFSS2\x02\0\0\0");
    settled.clone().read(Geometry::for_region(FIXTURE_REGION).unwrap().half_first(0), &mut sector).unwrap();
    assert_eq!(&sector[..12], b"ABSDFSI2\x02\0\0\0");
}

/// `testdata/format2.sectors`: the fixture namespace with a clock, so the
/// host reader's tests see real `mtime` values.
#[test]
fn format_two_fixture_is_what_the_library_writes() {
    let mut disk = Disk::new(FIXTURE_REGION);
    format(&mut disk, FIXTURE_ID).unwrap();
    let mut fs = Fs::mount(disk.settle(), true).unwrap();
    fs.set_clock(Some(1_790_000_000));
    build_fixture(&mut fs);
    fs.set_clock(Some(1_790_000_100));
    put(&mut fs, b"/d/f", b"hello, world\n");
    golden("format2.sectors", &fs.into_device().settle());
    let mut again = Fs::mount(parse_sectors(&std::fs::read_to_string(fixture_path("format2.sectors")).unwrap()), false).unwrap();
    assert_eq!(read_all(&mut again, b"/d/f").unwrap(), b"hello, world\n");
    assert_eq!(again.stat(b"/d/f").unwrap().mtime, 1_790_000_100);
    assert_eq!(again.stat(b"/g").unwrap().mtime, 1_790_000_000);
}

fn mtime<D: Device>(fs: &Fs<D>, path: &[u8]) -> u64 {
    fs.stat(path).unwrap().mtime
}

#[test]
fn mtime_is_set_at_creation_and_zero_without_a_clock() {
    let mut fs = Fs::mount(fresh(), true).unwrap();
    assert_eq!(mtime(&fs, b"/"), 0, "format has no clock");
    fs.mkdir(b"/unknown").unwrap();
    assert_eq!(mtime(&fs, b"/unknown"), 0);
    fs.set_clock(Some(1000));
    fs.mkdir(b"/d").unwrap();
    let handle = fs.open(b"/d/f", create_new()).unwrap();
    assert_eq!((mtime(&fs, b"/d"), mtime(&fs, b"/d/f"), mtime(&fs, b"/")), (1000, 1000, 1000));
    fs.close(handle).unwrap();
    // An unavailable clock records "unknown" (0), never a stale value.
    fs.set_clock(None);
    fs.open(b"/d/g", create_new()).map(|h| fs.close(h)).unwrap().unwrap();
    assert_eq!((mtime(&fs, b"/d/g"), mtime(&fs, b"/d"), mtime(&fs, b"/")), (0, 0, 1000));
    let disk = fs.into_device().settle();
    let again = Fs::mount(disk, true).unwrap();
    assert_eq!((mtime(&again, b"/d/f"), mtime(&again, b"/d/g"), mtime(&again, b"/")), (1000, 0, 1000));
}

#[test]
fn mtime_follows_changed_bytes_and_size() {
    let mut fs = Fs::mount(fresh(), true).unwrap();
    fs.set_clock(Some(10));
    let handle = fs.open(b"/f", create_new()).unwrap();
    fs.set_clock(Some(20));
    fs.write_at(handle, 0, &pattern(1, 9000)).unwrap();
    assert_eq!(mtime(&fs, b"/f"), 20, "growth");
    assert_eq!(mtime(&fs, b"/"), 10, "data writes leave the parent alone");
    fs.sync().unwrap();
    // Identical bytes, whole and partial sectors: no change, no commit.
    fs.set_clock(Some(30));
    let seq = fs.sequence();
    fs.write_at(handle, 0, &pattern(1, 9000)).unwrap();
    fs.write_at(handle, 700, &pattern(1, 9000)[700..1300]).unwrap();
    assert_eq!(mtime(&fs, b"/f"), 20, "identical bytes");
    fs.sync().unwrap();
    assert_eq!(fs.sequence(), seq, "an unchanged file needs no commit");
    // One differing byte deep in a write is a change.
    let mut changed = pattern(1, 9000);
    changed[8999] ^= 0xff;
    fs.write_at(handle, 0, &changed).unwrap();
    assert_eq!(mtime(&fs, b"/f"), 30, "last byte changed");
    // In place, same size: durable at the next commit.
    fs.set_clock(Some(40));
    fs.write_at(handle, 512, b"Z").unwrap();
    assert_eq!(mtime(&fs, b"/f"), 40, "one byte in place");
    fs.sync().unwrap();
    assert!(fs.sequence() > seq, "the new mtime is committed");
    fs.set_clock(Some(50));
    fs.set_len(handle, 9000).unwrap();
    assert_eq!(mtime(&fs, b"/f"), 40, "set_len to the same size changes nothing");
    fs.set_len(handle, 100).unwrap();
    assert_eq!(mtime(&fs, b"/f"), 50, "shrink");
    fs.set_clock(Some(60));
    fs.set_len(handle, 5000).unwrap();
    assert_eq!(mtime(&fs, b"/f"), 60, "grow");
    fs.set_clock(Some(70));
    fs.write_at(handle, 6000, b"").unwrap();
    assert_eq!(mtime(&fs, b"/f"), 60, "empty write");
    fs.close(handle).unwrap();
    fs.open(b"/f", rw()).map(|h| fs.close(h)).unwrap().unwrap();
    assert_eq!(mtime(&fs, b"/f"), 60, "open without truncate");
    let truncating = OpenFlags { truncate: true, ..rw() };
    fs.open(b"/f", truncating).map(|h| fs.close(h)).unwrap().unwrap();
    assert_eq!(mtime(&fs, b"/f"), 70, "open with truncate");
    fs.sync().unwrap();
    let again = Fs::mount(fs.into_device().settle(), true).unwrap();
    assert_eq!(mtime(&again, b"/f"), 70);
    assert_eq!(mtime(&again, b"/"), 10);
}

#[test]
fn mtime_of_parents_follows_their_entries() {
    let mut fs = Fs::mount(fresh(), true).unwrap();
    fs.set_clock(Some(1));
    fs.mkdir(b"/a").unwrap();
    fs.mkdir(b"/a/x").unwrap();
    fs.mkdir(b"/b").unwrap();
    put(&mut fs, b"/a/f", b"f");
    put(&mut fs, b"/a/x/g", b"g");
    fs.set_clock(Some(2));
    fs.mkdir(b"/a/y").unwrap();
    assert_eq!((mtime(&fs, b"/a"), mtime(&fs, b"/"), mtime(&fs, b"/a/x")), (2, 1, 1), "mkdir");
    fs.set_clock(Some(3));
    fs.rmdir(b"/a/y").unwrap();
    assert_eq!((mtime(&fs, b"/a"), mtime(&fs, b"/")), (3, 1), "rmdir");
    fs.set_clock(Some(4));
    fs.unlink(b"/a/x/g").unwrap();
    assert_eq!((mtime(&fs, b"/a/x"), mtime(&fs, b"/a")), (4, 3), "unlink");
    fs.set_clock(Some(5));
    fs.rename(b"/a/f", b"/b/f", false).unwrap();
    assert_eq!((mtime(&fs, b"/a"), mtime(&fs, b"/b"), mtime(&fs, b"/b/f")), (5, 5, 1), "rename");
    fs.set_clock(Some(6));
    fs.rename(b"/a/x", b"/a/z", true).unwrap();
    assert_eq!((mtime(&fs, b"/a"), mtime(&fs, b"/a/z"), mtime(&fs, b"/")), (6, 4, 1), "rename in place");
    fs.set_clock(Some(7));
    fs.set_readonly_path(b"/b/f", true).unwrap();
    assert_eq!((mtime(&fs, b"/b/f"), mtime(&fs, b"/b")), (1, 5), "set_readonly");
    fs.set_clock(Some(8));
    put(&mut fs, b"/a/z/h", b"h");
    fs.set_clock(Some(9));
    assert_eq!(fs.remove_tree(b"/a", false).unwrap(), 2);
    assert_eq!((mtime(&fs, b"/a"), mtime(&fs, b"/")), (9, 1), "remove_tree keeping the top");
    fs.set_clock(Some(10));
    fs.remove_tree(b"/a", true).unwrap();
    assert_eq!(mtime(&fs, b"/"), 10, "remove_tree with the top");
    let again = Fs::mount(fs.into_device().settle(), true).unwrap();
    assert_eq!((mtime(&again, b"/"), mtime(&again, b"/b"), mtime(&again, b"/b/f")), (10, 5, 1));
}

#[test]
fn a_read_only_mount_changes_no_mtime() {
    let disk = fresh();
    let mut fs = Fs::mount(disk.clone(), false).unwrap();
    fs.set_clock(Some(99));
    assert_eq!(fs.mkdir(b"/d"), Err(Error::ReadOnlyFs));
    assert_eq!(mtime(&fs, b"/"), 0);
}

/// A device that serves runs natively: every run is logged by length, and
/// a write run can be made to fail after its first `k` sectors reached the
/// device, the partial effect the kernel's multi-sector write documents.
struct RunDisk {
    disk: Disk,
    runs: Rc<RefCell<Vec<(bool, u64, usize)>>>,
    /// (first data sector, sectors that land before the error): the first
    /// write run into the data area fails after that many sectors.
    fail_run: Option<(u64, usize)>,
}

impl RunDisk {
    fn over(disk: Disk) -> Self {
        Self { disk, runs: Rc::default(), fail_run: None }
    }
}

impl Device for RunDisk {
    fn sectors(&self) -> u64 {
        self.disk.sectors()
    }
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        self.read_run(sector, buffer)
    }
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        self.write_run(sector, buffer)
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.disk.flush()
    }
    fn read_run(&mut self, sector: u64, buffer: &mut [u8]) -> Result<(), Error> {
        assert!(!buffer.is_empty() && buffer.len() <= MAX_RUN_BYTES);
        self.runs.borrow_mut().push((false, sector, buffer.len() / SECTOR));
        for (index, chunk) in buffer.chunks_exact_mut(SECTOR).enumerate() {
            self.disk.read(sector + index as u64, chunk.try_into().unwrap())?;
        }
        Ok(())
    }
    fn write_run(&mut self, sector: u64, buffer: &[u8]) -> Result<(), Error> {
        assert!(!buffer.is_empty() && buffer.len() <= MAX_RUN_BYTES);
        self.runs.borrow_mut().push((true, sector, buffer.len() / SECTOR));
        let failing = match self.fail_run {
            Some((first, landed)) if sector >= first => {
                self.fail_run = None;
                Some(landed)
            }
            _ => None,
        };
        for (index, chunk) in buffer.chunks_exact(SECTOR).enumerate() {
            if failing == Some(index) {
                return Err(Error::Device(-5));
            }
            self.disk.write(sector + index as u64, chunk.try_into().unwrap())?;
        }
        Ok(())
    }
}

#[test]
fn runs_are_bounded_by_blocks_and_equal_single_sector_writes() {
    fn workload<D: Device>(fs: &mut Fs<D>) {
        let handle = fs.open(b"/f", create_new()).unwrap();
        fs.write_at(handle, 0, &pattern(1, 4096)).unwrap();
        fs.write_at(handle, 4096, &pattern(2, 5000)).unwrap();
        fs.write_at(handle, 100, &pattern(3, 1000)).unwrap();
        fs.write_at(handle, 9000, &pattern(4, 300)).unwrap();
        fs.sync().unwrap();
        let mut back = vec![0u8; 9300];
        assert_eq!(fs.read_at(handle, 0, &mut back).unwrap(), 9300);
        let mut expected = pattern(1, 4096);
        expected.extend(pattern(2, 5000));
        expected[100..1100].copy_from_slice(&pattern(3, 1000));
        expected[9000..9096].copy_from_slice(&pattern(4, 300)[..96]);
        expected.extend(&pattern(4, 300)[96..]);
        assert_eq!(back, expected);
        fs.close(handle).unwrap();
    }
    let single = fresh();
    let runs = fresh();
    workload(&mut Fs::mount(single.clone(), true).unwrap());
    let run_disk = RunDisk::over(runs.clone());
    let log = run_disk.runs.clone();
    workload(&mut Fs::mount(run_disk, true).unwrap());
    // The same acknowledged sectors, in the same order, whichever way the
    // device takes them: every crash point of the sweeps is unchanged.
    assert_eq!(*single.log.borrow(), *runs.log.borrow());
    let log = log.borrow();
    assert!(log.iter().all(|(_, _, sectors)| (1..=MAX_RUN_SECTORS as usize).contains(sectors)));
    let geometry = Geometry::for_region(REGION).unwrap();
    for (_, sector, sectors) in log.iter() {
        if *sector >= geometry.data_first {
            let block_start = (*sector - geometry.data_first) / SECTORS_PER_BLOCK;
            let block_end = (*sector - geometry.data_first + *sectors as u64 - 1) / SECTORS_PER_BLOCK;
            assert_eq!(block_start, block_end, "run crosses a block: {sector}+{sectors}");
        }
    }
    let writes: Vec<usize> = log.iter().filter(|(w, s, _)| *w && *s >= geometry.data_first).map(|(_, _, n)| *n).collect();
    // One aligned block: one run of eight. 5000 bytes from block 1: eight
    // then two. 1000 bytes at 100: sectors 0..=2 of block 0, three. 300 at
    // 9000: sector 1 of block 2 and sectors 2..=2, i.e. two sectors.
    assert_eq!(writes, vec![8, 8, 2, 3, 2]);
    let reads: Vec<usize> = log.iter().filter(|(w, s, _)| !*w && *s >= geometry.data_first).map(|(_, _, n)| *n).collect();
    assert_eq!(reads, vec![2, 3, 2, 8, 8, 3]);
    // The metadata image travels in whole runs too: 10000 bytes are eight,
    // eight, and four sectors into the half, then the one superblock sector.
    let mut run_disk = RunDisk::over(Disk::new(REGION));
    let log = run_disk.runs.clone();
    write_image(&mut run_disk, &geometry, 1, 0, &pattern(5, 10000)).unwrap();
    let writes: Vec<(u64, usize)> = log.borrow().iter().filter(|(w, _, _)| *w).map(|(_, s, n)| (*s, *n)).collect();
    let half = geometry.half_first(0);
    assert_eq!(writes, vec![(half, 8), (half + 8, 8), (half + 16, 4), (0, 1)]);
}

#[test]
fn a_run_that_fails_part_way_is_not_atomic_and_poisons() {
    let base = fresh();
    {
        let mut fs = Fs::mount(base.clone(), true).unwrap();
        put(&mut fs, b"/old", &pattern(7, 4096));
    }
    let settled = base.settle();
    let old = pattern(7, 4096);
    let data_first = Geometry::for_region(REGION).unwrap().data_first;
    // In-place rewrite of a synced block: the device lands three sectors
    // and refuses the fourth.
    let mut run_disk = RunDisk::over(settled.clone());
    run_disk.fail_run = Some((data_first, 3));
    let mut fs = Fs::mount(run_disk, true).unwrap();
    let handle = fs.open(b"/old", rw()).unwrap();
    assert_eq!(fs.write_at(handle, 0, &pattern(9, 4096)), Err(Error::Device(-5)));
    assert!(fs.poisoned());
    assert_eq!(fs.read_at(handle, 0, &mut [0u8; 16]), Err(Error::Poisoned));
    assert_eq!(fs.sync(), Err(Error::Poisoned));
    // What a later mount sees is exactly the leading sectors, never a
    // whole new block and never the old one: the library made no atomic
    // claim, and the committed metadata is untouched.
    let mut later = Fs::mount(settled.settle(), false).unwrap();
    let mut expected = old.clone();
    expected[..3 * SECTOR].copy_from_slice(&pattern(9, 4096)[..3 * SECTOR]);
    assert_eq!(read_all(&mut later, b"/old"), Some(expected));
    assert_eq!(later.sequence(), fs.sequence());
    // A fresh block that fails part way leaves the committed tree alone.
    let settled = base.settle();
    let mut run_disk = RunDisk::over(settled.clone());
    run_disk.fail_run = Some((data_first, 5));
    let mut fs = Fs::mount(run_disk, true).unwrap();
    let handle = fs.open(b"/new", create_new()).unwrap();
    assert_eq!(fs.write_at(handle, 0, &pattern(11, 4096)), Err(Error::Device(-5)));
    assert!(fs.poisoned());
    // Creation was committed by open; the size the failed write gave the
    // object in memory never was, so the torn block is unreachable.
    let mut later = Fs::mount(settled.settle(), false).unwrap();
    assert_eq!(read_all(&mut later, b"/new"), Some(Vec::new()));
    assert_eq!(read_all(&mut later, b"/old"), Some(old));
}
