//! The exclusive-writer tripwire (docs/FILESYSTEM.md), measured: what the
//! filesystem does when more than one process mounts the same region, over
//! a file-backed device that each "process" opens separately (its own block
//! handle). `absd-fs` keeps no state outside its `Fs`, so two `Fs` values
//! over two opens of one file are exactly two processes with two handles.
//! Interleavings are deterministic; the one inside a commit uses a hook that
//! runs the other writer's whole operation just before a chosen sector write,
//! as preemption between two ABSD processes could.
//!
//! These tests assert today's behaviour, including the failures; they are
//! evidence for the tripwire, not a specification to preserve.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use absd_fs::{Device, Error, Fs, Geometry, Kind, OpenFlags, SECTOR, format, inspect};

type Hook = Box<dyn FnMut(u64, u64)>;

/// One open of the backing file: one process's block handle. `hook` runs
/// before a write (`write`, sector) or read (`read`, sector) the test names.
struct FileDevice {
    file: File,
    sectors: u64,
    on_write: Option<Hook>,
    on_read: Option<Hook>,
    written: Rc<RefCell<Vec<u64>>>,
}

impl FileDevice {
    fn open(path: &Path, writable: bool) -> Self {
        let file = OpenOptions::new().read(true).write(writable).open(path).unwrap();
        let sectors = file.metadata().unwrap().len() / SECTOR as u64;
        Self { file, sectors, on_write: None, on_read: None, written: Rc::default() }
    }
}

impl Device for FileDevice {
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        if let Some(hook) = self.on_read.as_mut() {
            hook(0, sector);
        }
        self.file.read_exact_at(buffer, sector * SECTOR as u64).map_err(|_| Error::Device(-5))
    }
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        if let Some(hook) = self.on_write.as_mut() {
            hook(1, sector);
        }
        self.written.borrow_mut().push(sector);
        // A read-only open is a read-only handle: the "kernel" refuses.
        self.file.write_all_at(buffer, sector * SECTOR as u64).map_err(|_| Error::Device(-1))
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.file.sync_data().map_err(|_| Error::Device(-5))
    }
}

struct Region(PathBuf);

impl Region {
    /// A formatted region of `sectors` in a fresh file.
    fn new(name: &str, sectors: u64) -> Self {
        let dir = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = dir.join(format!("absd-fs-multiwriter-{}-{name}.img", std::process::id()));
        let file = File::create(&path).unwrap();
        file.set_len(sectors * SECTOR as u64).unwrap();
        drop(file);
        format(&mut FileDevice::open(&path, true), 0x5eed).unwrap();
        Self(path)
    }
    fn device(&self, writable: bool) -> FileDevice {
        FileDevice::open(&self.0, writable)
    }
    fn mount(&self, writable: bool) -> Fs<FileDevice> {
        Fs::mount(self.device(writable), writable).unwrap()
    }
    /// What a fresh process (or the next boot) mounts, or why it refuses.
    fn fresh(&self) -> Result<Fs<FileDevice>, Error> {
        Fs::mount(self.device(false), false)
    }
    fn raw(&self) -> Vec<u8> {
        std::fs::read(&self.0).unwrap()
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const REGION: u64 = 4096; // 2 MiB

fn rw() -> OpenFlags {
    OpenFlags { read: true, write: true, ..OpenFlags::default() }
}

fn create() -> OpenFlags {
    OpenFlags { create: true, ..rw() }
}

fn put<D: Device>(fs: &mut Fs<D>, path: &[u8], bytes: &[u8]) {
    let handle = fs.open(path, create()).unwrap();
    fs.set_len(handle, 0).unwrap();
    fs.write_at(handle, 0, bytes).unwrap();
    fs.sync().unwrap();
    fs.close(handle).unwrap();
}

fn get<D: Device>(fs: &mut Fs<D>, path: &[u8]) -> Result<Vec<u8>, Error> {
    let handle = fs.open(path, OpenFlags { read: true, ..OpenFlags::default() })?;
    let size = fs.fstat(handle).unwrap().size as usize;
    let mut bytes = vec![0; size];
    assert_eq!(fs.read_at(handle, 0, &mut bytes).unwrap(), size);
    fs.close(handle).unwrap();
    Ok(bytes)
}

fn fill(byte: u8, len: usize) -> Vec<u8> {
    vec![byte; len]
}

fn names<D: Device>(fs: &Fs<D>, dir: &[u8]) -> Vec<String> {
    fs.read_dir(dir).unwrap().into_iter().map(|(name, _)| String::from_utf8(name).unwrap()).collect()
}

fn seq_of(region: &Region) -> Result<u64, Error> {
    inspect(&mut region.device(false)).map(|(_, seq, _)| seq)
}

/// Experiment 1a. Two writable mounts, each creating and syncing its own
/// file. Each commit is computed from the committer's private copy of the
/// namespace and sequence, and each allocation from its private free set.
#[test]
fn two_writers_lose_namespace_and_alias_blocks() {
    let region = Region::new("lost", REGION);
    let mut a = region.mount(true);
    let mut b = region.mount(true);
    assert_eq!(a.sequence(), b.sequence());
    let base = a.sequence();

    put(&mut a, b"/a", &fill(b'A', 4096));
    // B allocates block 0 too (it never saw A's image) and commits the same
    // sequence into the same half and superblock slot A just used.
    put(&mut b, b"/b", &fill(b'B', 4096));

    // A's own file now holds B's bytes: allocator double use, no error.
    let a_view = get(&mut a, b"/a").unwrap();
    assert_eq!(a_view, fill(b'B', 4096), "A reads B's data under its own name");
    a.check().unwrap(); // A's memory is self-consistent; it cannot tell
    b.check().unwrap();

    // A fresh mount sees B's history only: A's create and data are gone.
    let mut fresh = region.fresh().unwrap();
    assert_eq!(names(&fresh, b"/"), ["b"], "A's committed, synced /a is lost");
    assert_eq!(fresh.sequence(), base + 2);
    drop(fresh);

    // A commits again (mkdir) from its stale sequence: it overwrites B's
    // newest superblock with its own. The pair is still consecutive, so the
    // next mount accepts A's namespace and B's synced /b vanishes, while A's
    // /a now names the block holding B's bytes.
    a.mkdir(b"/adir").unwrap();
    fresh = region.fresh().unwrap();
    fresh.check().unwrap();
    assert_eq!(names(&fresh, b"/"), ["a", "adir"], "B's committed, synced /b is lost");
    assert_eq!(get(&mut fresh, b"/a").unwrap(), fill(b'B', 4096), "silent content corruption");
    eprintln!(
        "E1a: base seq {base}; after A+B puts fresh mount sees only /b (A lost); \
         A reads /a = B's bytes; after A's mkdir fresh mount sees [a, adir] (B lost), \
         /a = B's bytes; mount and check() accept it"
    );
}

/// Experiment 1b. Superblock ping-pong: a writer behind by an odd number of
/// commits overwrites the other's newest slot and rolls the region back to
/// an intermediate state the other already superseded; behind by an even
/// number (at least two) it leaves non-consecutive sequences, and every
/// later mount refuses the region (mount never repairs or falls back).
#[test]
fn stale_writer_rolls_back_or_bricks_the_region() {
    let region = Region::new("pingpong", REGION);
    let mut a = region.mount(true);
    let mut b = region.mount(true);
    let base = a.sequence();

    for dir in [&b"/b1"[..], b"/b2", b"/b3"] {
        b.mkdir(dir).unwrap();
    }
    assert_eq!(seq_of(&region).unwrap(), base + 3);
    // A commits base+1 into slot (base+1)%2, where B's base+3 was.
    a.mkdir(b"/a1").unwrap();
    let rolled = region.fresh().unwrap();
    assert_eq!(rolled.sequence(), base + 2, "mount picks B's superseded base+2");
    assert_eq!(names(&rolled, b"/"), ["b1", "b2"], "B's third commit and A's commit both lost");
    drop(rolled);

    let region = Region::new("brick", REGION);
    let mut a = region.mount(true);
    let mut b = region.mount(true);
    for dir in [&b"/b1"[..], b"/b2", b"/b3", b"/b4"] {
        b.mkdir(dir).unwrap();
    }
    a.mkdir(b"/a1").unwrap();
    assert_eq!(region.fresh().err(), Some(Error::Corrupt("superblock sequences are not consecutive")));
    // The writers themselves carry on without noticing.
    b.mkdir(b"/b5").unwrap();
    a.mkdir(b"/a2").unwrap();
    let after = region.fresh().err();
    eprintln!(
        "E1b: A one commit vs B three: fresh mount at base+2 = [b1, b2] (rollback). \
         A one vs B four: fresh mount refused {:?}; both writers kept committing; now {after:?}",
        Error::Corrupt("superblock sequences are not consecutive")
    );
}

/// Experiment 1c. Preemption inside a commit: A has written its image and
/// is about to write its superblock when B runs a whole commit of the same
/// sequence. A's superblock then names B's image bytes with A's digest.
#[test]
fn preempted_commit_leaves_an_unmountable_region() {
    let region = Region::new("torn", REGION);
    let a_device = region.device(true);
    let b = Rc::new(RefCell::new(region.mount(true)));
    let mut a = Fs::mount(a_device, true).unwrap();
    let slot = (a.sequence() + 1) % 2;
    let other = b.clone();
    let mut fired = false;
    a.device().on_write = Some(Box::new(move |_, sector| {
        if sector == slot && !fired {
            fired = true;
            other.borrow_mut().mkdir(b"/from-b").unwrap();
        }
    }));
    a.mkdir(b"/from-a-with-a-longer-name").unwrap();
    let refused = region.fresh().err();
    assert_eq!(refused, Some(Error::Corrupt("image digest")));
    eprintln!("E1c: A preempted before its superblock write, B commits: fresh mount {refused:?}");
}

/// Experiment 2a. One writer, one reader mounted earlier. The reader's
/// namespace is a snapshot, its data is not: blocks the writer frees after
/// a commit are reallocated and the reader reads the new owner's bytes
/// under the old name, with no error.
#[test]
fn reader_reads_reused_blocks_under_old_names() {
    let region = Region::new("reader", REGION);
    let mut w = region.mount(true);
    put(&mut w, b"/secret-old", &fill(b'O', 4096));
    put(&mut w, b"/kept", &fill(b'K', 4096));
    let mut r = Fs::mount(region.device(false), false).unwrap();
    let held = r.open(b"/secret-old", OpenFlags { read: true, ..OpenFlags::default() }).unwrap();

    // In-place overwrite, not yet committed: the reader sees it at once.
    let handle = w.open(b"/kept", rw()).unwrap();
    w.write_at(handle, 0, &fill(b'k', 100)).unwrap();
    w.close(handle).unwrap();
    let kept = get(&mut r, b"/kept").unwrap();
    assert_eq!(&kept[..100], &fill(b'k', 100)[..], "reader sees uncommitted data");

    // Unlink, commit (the block becomes free), then allocate every free block.
    w.unlink(b"/secret-old").unwrap();
    let free = w.free_blocks() as usize;
    put(&mut w, b"/new", &fill(b'N', free * 4096));
    assert_eq!(w.free_blocks(), 0);

    let mut bytes = vec![0; 4096];
    assert_eq!(r.read_at(held, 0, &mut bytes).unwrap(), 4096);
    assert_eq!(bytes, fill(b'N', 4096), "reader's open handle reads the reused block");
    assert_eq!(get(&mut r, b"/secret-old").unwrap(), fill(b'N', 4096), "and so does a fresh open");
    assert_eq!(r.stat(b"/new").err(), Some(Error::NotFound), "and never sees the new name");
    // The reader's handle cannot write: that is the only thing it is denied.
    assert_eq!(r.mkdir(b"/x").err(), Some(Error::ReadOnlyFs));
    eprintln!(
        "E2a: reader saw uncommitted in-place write; after writer unlink+commit+allocate, \
         reader's /secret-old (open handle and fresh open) returns /new's bytes; /new invisible"
    );
}

/// Experiment 2b. A reader mounting while the writer commits twice between
/// the reader's superblock read and its image read: the digest check
/// refuses the mount (fail closed, not silent).
#[test]
fn reader_mount_racing_two_commits_is_refused() {
    let region = Region::new("racing", REGION);
    let w = Rc::new(RefCell::new(region.mount(true)));
    let geometry = Geometry::for_region(REGION).unwrap();
    let seq = w.borrow().sequence();
    let half = geometry.half_first(seq % 2);
    let mut device = region.device(false);
    let writer = w.clone();
    let mut fired = false;
    device.on_read = Some(Box::new(move |_, sector| {
        if sector == half && !fired {
            fired = true;
            writer.borrow_mut().mkdir(b"/one").unwrap();
            writer.borrow_mut().mkdir(b"/two").unwrap();
        }
    }));
    let refused = Fs::mount(device, false).err();
    assert_eq!(refused, Some(Error::Corrupt("image digest")));
    assert!(region.fresh().is_ok(), "the region itself is fine");
    eprintln!("E2b: reader mount raced by two commits: {refused:?}; retry succeeds");
}

/// Experiment 3. Strict handoff is safe exactly when the previous writer
/// can no longer write: the next mount (which flushes first) sees
/// everything the previous one synced, and a writer that died unsynced
/// leaves the old namespace (its unsynced lengths lost, its created names
/// kept, because create commits). A "handed-off" writer that still holds
/// its handle and writes once more reproduces experiment 1.
#[test]
fn serialized_handoff_is_safe_only_if_the_old_writer_is_gone() {
    let region = Region::new("handoff", REGION);
    {
        let mut a = region.mount(true);
        put(&mut a, b"/a", &fill(b'A', 5000));
    } // A exits: its handle is gone.
    {
        let mut b = region.mount(true);
        assert_eq!(get(&mut b, b"/a").unwrap(), fill(b'A', 5000));
        put(&mut b, b"/b", &fill(b'B', 5000));
        // B dies mid-write: created (committed), written, never synced.
        let handle = b.open(b"/partial", create()).unwrap();
        b.write_at(handle, 0, &fill(b'P', 9000)).unwrap();
    }
    let mut c = region.mount(true);
    assert_eq!(get(&mut c, b"/b").unwrap(), fill(b'B', 5000));
    assert_eq!(get(&mut c, b"/partial").unwrap(), Vec::<u8>::new(), "name durable, data not");
    c.check().unwrap();
    put(&mut c, b"/c", &fill(b'C', 5000));

    // Handoff by agreement only: C syncs and "hands over" but keeps its
    // handle; D mounts and works; C writes once more.
    let mut d = region.mount(true);
    put(&mut d, b"/d", &fill(b'D', 5000));
    put(&mut c, b"/late", &fill(b'L', 5000));
    let fresh = region.fresh().unwrap();
    let visible = names(&fresh, b"/");
    assert!(!visible.contains(&"d".to_string()), "D's synced /d lost to the late writer");
    let d_view = get(&mut d, b"/d").unwrap();
    assert_eq!(d_view, fill(b'L', 5000), "D's /d blocks were reallocated by C");
    eprintln!(
        "E3: sequential exit-then-mount safe (partial file = committed name, empty data); \
         late write by a handed-off writer: fresh mount {visible:?} (/d lost); \
         D reads its /d as C's bytes"
    );
}

/// Experiment 4. Authority is the whole device. A process with a read right
/// on the block handle reads any file's bytes without the library; a
/// writer's every commit rewrites every record, including ones outside any
/// subtree it might be "limited" to; and a write right lets it replace any
/// file's content in place, which the next mount accepts.
#[test]
fn a_block_handle_has_no_subtree_authority() {
    let region = Region::new("subtree", REGION);
    let mut w = region.mount(true);
    w.mkdir(b"/ssh").unwrap();
    w.mkdir(b"/home").unwrap();
    w.mkdir(b"/home/operator").unwrap();
    let seed: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
    put(&mut w, b"/ssh/host_ed25519_seed", &seed);

    // Read right, no mount: the seed is in the raw device bytes.
    let raw = region.raw();
    let at = raw.windows(seed.len()).position(|window| window == seed.as_slice());
    assert!(at.is_some(), "seed readable from raw sectors");

    // A commit confined in intent to /home/operator writes every record.
    let geometry = w.geometry();
    let written = w.device().written.clone();
    written.borrow_mut().clear();
    let handle = w.open(b"/home/operator/notes", create()).unwrap();
    w.close(handle).unwrap();
    let half = w.sequence() % 2;
    let first = geometry.half_first(half);
    let image_sectors: Vec<u64> =
        written.borrow().iter().copied().filter(|s| *s >= first && *s < first + geometry.half_sectors).collect();
    let mut image = Vec::new();
    for sector in &image_sectors {
        let offset = (*sector as usize) * SECTOR;
        image.extend_from_slice(&region.raw()[offset..offset + SECTOR]);
    }
    let needle = b"host_ed25519_seed";
    assert!(image.windows(needle.len()).any(|window| window == needle), "commit rewrote /ssh records");

    // Write right, no library: replace the seed's bytes in place.
    let forged = vec![0x42u8; 32];
    let device = region.device(true);
    device.file.write_all_at(&forged, at.unwrap() as u64).unwrap();
    let mut fresh = region.fresh().unwrap();
    fresh.check().unwrap();
    assert_eq!(get(&mut fresh, b"/ssh/host_ed25519_seed").unwrap(), forged);
    let kind = fresh.stat(b"/ssh").unwrap().kind;
    assert_eq!(kind, Kind::Dir);
    eprintln!(
        "E4: seed found at raw byte {}; a /home/operator create rewrote {} image sectors \
         including /ssh records; raw overwrite of the seed accepted by the next mount",
        at.unwrap(),
        image_sectors.len()
    );
}
