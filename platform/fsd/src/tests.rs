//! Host tests of the dispatcher: what a binding lets a channel see and
//! change, isolation between channels, the binding checks, and durability.

use alloc::format;
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use absd_fs::{Device, Error, Fs, OpenFlags, SECTOR};

use crate::proto::{self, Frame, Mount, Reader, derive, op, status};
use crate::{CONTROL, Inbox, PipeState, Server, Taken};

#[derive(Clone)]
struct Disk(Rc<RefCell<BTreeMap<u64, [u8; SECTOR]>>>);

impl Device for Disk {
    fn sectors(&self) -> u64 {
        16384
    }
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        *buffer = self.0.borrow().get(&sector).copied().unwrap_or([0; SECTOR]);
        Ok(())
    }
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        self.0.borrow_mut().insert(sector, *buffer);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

const SEED: &[u8] = b"0123456789abcdef0123456789abcdef";

fn put(fs: &mut Fs<Disk>, path: &[u8], data: &[u8]) {
    let flags = OpenFlags {
        read: true,
        write: true,
        create: true,
        create_new: false,
        truncate: true,
    };
    let handle = fs.open(path, flags).unwrap();
    fs.write_at(handle, 0, data).unwrap();
    fs.close(handle).unwrap();
}

fn image() -> Disk {
    let disk = Disk(Rc::new(RefCell::new(BTreeMap::new())));
    absd_fs::format(&mut disk.clone(), 7).unwrap();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    for dir in [&b"/bin"[..], b"/etc", b"/ssh", b"/home"] {
        fs.mkdir(dir).unwrap();
    }
    put(&mut fs, b"/bin/ls", b"ELF ls");
    put(&mut fs, b"/etc/motd", b"hello\n");
    put(&mut fs, b"/ssh/host_ed25519_seed", SEED);
    fs.sync().unwrap();
    disk
}

#[test]
fn network_sample_day_count_is_bounded_and_preserves_startup_history() {
    use crate::net_status::{BYTES, Carrier, Listener, Origin, PERIOD_TICKS, Record, PATH};
    let disk=image();
    let mut fs=Fs::mount(disk.clone(),true).unwrap();
    fs.mkdir(b"/var").unwrap();fs.mkdir(b"/var/log").unwrap();
    let startup=b"- sshd: network 10.0.2.15/24 gateway 10.0.2.2\n- sshd: host key public fixture\n";
    put(&mut fs,b"/var/log/sshd",startup);
    put(&mut fs,PATH.as_bytes(),&[0;BYTES]);
    let handle=fs.open(PATH.as_bytes(),OpenFlags {read:true,write:true,..Default::default()}).unwrap();
    let objects=fs.object_count();let blocks=fs.free_blocks();
    let mut record=Record {boot:*b"0123456789abcdef0123456789abcdef",recovery:7,start:0,end:0,
        address:[10,0,2,15],prefix:24,gateway:Some([10,0,2,2]),carrier:Carrier::Up,
        disabled:Some(false),origin:Origin::Defaults,listener:Listener::Listening,port:22};
    let mut read=[0;BYTES];
    // 18,000 periodic writes plus readiness conservatively exceed 24h at
    // the pinned PIT divisor 1193 / 1193181.67 Hz. This is a publication-count
    // fixture, not native elapsed duration or timer-accuracy qualification.
    for publication in 0..=18_000 {
        let tick=publication*PERIOD_TICKS;
        record.start=tick;record.end=tick;
        let bytes=record.encode().unwrap();
        fs.write_at(handle,0,&bytes[..256]).unwrap();
        assert_eq!(fs.read_at(handle,0,&mut read).unwrap(),BYTES);
        assert!(Record::parse(&read).is_none(),"mixed version must refuse at tick {tick}");
        fs.write_at(handle,256,&bytes[256..]).unwrap();
        assert_eq!(fs.read_at(handle,0,&mut read).unwrap(),BYTES);
        assert_eq!(Record::parse(&read),Some(record));
        assert_eq!(fs.fstat(handle).unwrap().size,BYTES as u64);
        assert_eq!(fs.object_count(),objects);assert_eq!(fs.free_blocks(),blocks);
    }
    fs.close(handle).unwrap();fs.sync().unwrap();
    let mut h=Harness {server:Server::new(fs,6,vec![Mount::new(b"/var/log",true)]),pipes:quiet,now:1};
    assert_eq!(h.bind(1,&[],&[Mount::new(b"/var/log",false)]),0);
    assert_eq!(h.read_all(1,b"/var/log/sshd").unwrap(),startup);
    assert_eq!(Record::parse(&h.read_all(1,PATH.as_bytes()).unwrap()),Some(record));
    assert_eq!(h.open(1,2,PATH.as_bytes()),status::READ_ONLY);
    assert!(h.open(CONTROL,2,PATH.as_bytes())>0);
    assert_eq!(h.server.fs.stat(b"/var/log/sshd.0"),Err(Error::NotFound));
}

#[test]
fn sessions_can_read_the_recovery_projection_but_cannot_write_it_or_read_the_ledger() {
    let disk = image();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    fs.mkdir(b"/var").unwrap();
    fs.mkdir(b"/var/log").unwrap();
    let boot = *b"0123456789abcdef0123456789abcdef";
    let (ledger, _) = crate::recovery::charge(&mut fs, &boot).unwrap();
    crate::recovery::publish_projection(&mut fs, &ledger).unwrap();
    let mut h = Harness {
        server: Server::new(fs, 6, vec![Mount::new(b"/var/log", true)]),
        pipes: quiet, now: 1,
    };
    assert_eq!(h.bind(1, &[], &[Mount::new(b"/var/log", false)]), 0);
    let path = crate::recovery::PROJECTION.as_bytes();
    let bytes = h.read_all(1, path).unwrap();
    assert_eq!(bytes.len(), crate::recovery::LEDGER_BYTES);
    assert_eq!(crate::recovery::parse_ledger(&bytes), Some(ledger));
    assert_eq!(h.open(1, 2, path), status::READ_ONLY);
    assert!(h.read_all(1, crate::recovery::LEDGER).is_err());
    assert!(h.open(CONTROL, 2, path) > 0);
}

fn server(disk: &Disk) -> Server<Disk> {
    let fs = Fs::mount(disk.clone(), true).unwrap();
    Server::new(
        fs,
        6,
        vec![Mount::new(b"/ssh", false), Mount::new(b"/bin", false)],
    )
}

fn session_mounts(name: &[u8]) -> Vec<Mount> {
    let mut tmp = b"/tmp/".to_vec();
    tmp.extend_from_slice(name);
    vec![
        Mount::new(b"/home/operator", true),
        Mount::new(&tmp, true),
        Mount::new(b"/bin", false),
        Mount::new(b"/etc", false),
    ]
}

/// Pipes as a quiet system shows them: only the keeper holds client ends.
fn quiet(_: usize) -> Option<PipeState> {
    Some(PipeState {
        request_available: 0,
        request_writers: 1,
        reply_available: 0,
        reply_readers: 1,
    })
}

struct Harness {
    server: Server<Disk>,
    pipes: fn(usize) -> Option<PipeState>,
    now: u64,
}

impl Harness {
    fn new(disk: &Disk) -> Self {
        Self {
            server: server(disk),
            pipes: quiet,
            now: 1,
        }
    }
    fn call(&mut self, channel: usize, request: Vec<u8>) -> (i64, Vec<u8>) {
        let pipes = self.pipes;
        let reply = self
            .server
            .dispatch(channel, body(&request), &pipes, self.now);
        let mut reader = Reader(body(&reply));
        let status = reader.i64().unwrap();
        (status, reader.rest().to_vec())
    }
    fn status(&mut self, channel: usize, request: Vec<u8>) -> i64 {
        self.call(channel, request).0
    }
    fn bind(&mut self, slot: u8, spares: &[u8], mounts: &[Mount]) -> i64 {
        let mut frame = Frame::request(op::BIND).u8(slot).u8(spares.len() as u8);
        for spare in spares {
            frame = frame.u8(*spare);
        }
        self.status(CONTROL, frame.mounts(mounts).finish())
    }
    fn open(&mut self, channel: usize, flags: u32, path: &[u8]) -> i64 {
        self.status(
            channel,
            Frame::request(op::OPEN).u32(flags).bytes(path).finish(),
        )
    }
    fn read_all(&mut self, channel: usize, path: &[u8]) -> Result<Vec<u8>, i64> {
        let handle = self.open(channel, 1, path);
        if handle < 0 {
            return Err(handle);
        }
        let (count, data) = self.call(
            channel,
            Frame::request(op::READ_AT)
                .u64(handle as u64)
                .u64(0)
                .u32(65536)
                .finish(),
        );
        assert!(count >= 0);
        assert_eq!(
            self.status(
                channel,
                Frame::request(op::CLOSE).u64(handle as u64).finish()
            ),
            0
        );
        Ok(data)
    }
    fn write_file(&mut self, channel: usize, path: &[u8], data: &[u8]) -> i64 {
        let handle = self.open(channel, 2 | 8 | 32, path);
        if handle < 0 {
            return handle;
        }
        let written = self.status(
            channel,
            Frame::request(op::WRITE_AT)
                .u64(handle as u64)
                .u64(0)
                .bytes(data)
                .finish(),
        );
        assert_eq!(written, data.len() as i64);
        self.status(
            channel,
            Frame::request(op::CLOSE).u64(handle as u64).finish(),
        )
    }
    fn names(&mut self, channel: usize, path: &[u8]) -> Result<Vec<Vec<u8>>, i64> {
        let (count, payload) =
            self.call(channel, Frame::request(op::READ_DIR).bytes(path).finish());
        if count < 0 {
            return Err(count);
        }
        let mut reader = Reader(&payload);
        let mut names = Vec::new();
        for _ in 0..count {
            let length = reader.u16().unwrap() as usize;
            names.push(reader.take(length).unwrap().to_vec());
            reader.take(crate::proto::ATTR_BYTES).unwrap();
        }
        Ok(names)
    }
    fn path_op(&mut self, channel: usize, code: u8, path: &[u8]) -> i64 {
        self.status(channel, Frame::request(code).bytes(path).finish())
    }
    fn rename(&mut self, channel: usize, from: &[u8], to: &[u8], noreplace: bool) -> i64 {
        let frame = Frame::request(op::RENAME)
            .u8(noreplace as u8)
            .u16(from.len() as u16)
            .bytes(from)
            .bytes(to);
        self.status(channel, frame.finish())
    }
}

fn names(list: &[&[u8]]) -> Vec<Vec<u8>> {
    list.iter().map(|name| name.to_vec()).collect()
}

/// A finished frame's body: what `dispatch` takes.
fn body(frame: &[u8]) -> &[u8] {
    &frame[proto::HEADER..frame.len() - proto::TRAILER]
}

#[test]
fn control_reads_the_host_key_and_sessions_never_see_it() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(
        h.read_all(CONTROL, b"/ssh/host_ed25519_seed").unwrap(),
        SEED
    );
    // The control channel cannot write even its own mounts.
    assert_eq!(
        h.open(CONTROL, 2, b"/ssh/host_ed25519_seed"),
        status::READ_ONLY
    );
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    for path in [
        &b"/ssh/host_ed25519_seed"[..],
        b"/home/operator/../../ssh/host_ed25519_seed",
        b"/tmp/s1/../../ssh/host_ed25519_seed",
        b"//ssh///host_ed25519_seed",
        b"/ssh",
    ] {
        assert_eq!(h.open(1, 1, path), status::NOT_FOUND, "{path:?}");
        assert_eq!(h.path_op(1, op::STAT, path), status::NOT_FOUND);
    }
    assert_eq!(h.names(1, b"/ssh"), Err(status::NOT_FOUND));
    assert_eq!(
        h.names(1, b"/").unwrap(),
        names(&[b"bin", b"etc", b"home", b"tmp"])
    );
    assert_eq!(h.names(1, b"/tmp").unwrap(), names(&[b"s1"]));
    assert_eq!(h.read_all(1, b"/etc/motd").unwrap(), b"hello\n");
    // A binding naming the reserved subtree, or all of `/`, is refused.
    for mounts in [
        vec![Mount::new(b"/ssh", false)],
        vec![Mount::new(b"/ssh/x", true)],
        vec![Mount::new(b"/", false)],
        vec![Mount::new(b"relative", true)],
        vec![Mount::new(b"/home/../ssh", false)],
    ] {
        assert_eq!(h.bind(2, &[], &mounts), status::INVALID);
    }
}

#[test]
fn a_session_writes_only_its_read_write_mounts() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    assert_eq!(h.write_file(1, b"/home/operator/notes", b"mine"), 0);
    assert_eq!(h.write_file(1, b"/tmp/s1/scratch", b"tmp"), 0);
    assert_eq!(h.path_op(1, op::MKDIR, b"/home/operator/dir"), 0);
    assert_eq!(
        h.rename(
            1,
            b"/home/operator/notes",
            b"/home/operator/dir/notes",
            true
        ),
        0
    );
    assert_eq!(h.read_all(1, b"/home/operator/dir/notes").unwrap(), b"mine");
    // Everything else is refused, and nothing changed.
    assert_eq!(h.write_file(1, b"/bin/ls", b"evil"), status::READ_ONLY);
    assert_eq!(h.write_file(1, b"/bin/new", b"evil"), status::READ_ONLY);
    assert_eq!(h.write_file(1, b"/etc/motd", b"evil"), status::READ_ONLY);
    // Outside every mount nothing exists, even beside a mount point.
    assert_eq!(h.write_file(1, b"/home/other", b"evil"), status::NOT_FOUND);
    assert_eq!(h.write_file(1, b"/rootfile", b"evil"), status::NOT_FOUND);
    assert_eq!(h.write_file(1, b"/tmp", b"evil"), status::READ_ONLY);
    assert_eq!(
        h.write_file(1, b"/ssh/host_ed25519_seed", b"evil"),
        status::NOT_FOUND
    );
    assert_eq!(h.path_op(1, op::UNLINK, b"/bin/ls"), status::READ_ONLY);
    assert_eq!(h.path_op(1, op::MKDIR, b"/var"), status::NOT_FOUND);
    assert_eq!(h.path_op(1, op::RMDIR, b"/home"), status::READ_ONLY);
    assert_eq!(h.path_op(1, op::RMDIR, b"/home/operator"), status::BUSY);
    assert_eq!(h.path_op(1, op::RMDIR, b"/tmp/s1"), status::BUSY);
    assert_eq!(
        h.rename(1, b"/home/operator/dir/notes", b"/bin/notes", false),
        status::READ_ONLY
    );
    assert_eq!(
        h.rename(1, b"/bin/ls", b"/home/operator/ls", false),
        status::READ_ONLY
    );
    assert_eq!(
        h.rename(1, b"/home/operator", b"/tmp/s1/op", false),
        status::BUSY
    );
    let set_ro = Frame::request(op::SET_READONLY_PATH)
        .u8(1)
        .bytes(b"/bin/ls")
        .finish();
    assert_eq!(h.status(1, set_ro), status::READ_ONLY);
    let ls = h.open(1, 1, b"/bin/ls");
    let write = Frame::request(op::WRITE_AT)
        .u64(ls as u64)
        .u64(0)
        .bytes(b"x")
        .finish();
    assert_eq!(h.status(1, write), status::DENIED);
    assert_eq!(h.read_all(1, b"/bin/ls").unwrap(), b"ELF ls");
    let mut fs = Fs::mount(disk.clone(), false).unwrap();
    let mut buffer = [0u8; 16];
    let handle = fs
        .open(
            b"/ssh/host_ed25519_seed",
            OpenFlags {
                read: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(fs.read_at(handle, 0, &mut buffer).unwrap(), 16);
    assert_eq!(&buffer, &SEED[..16]);
}

#[test]
fn two_sessions_share_one_coherent_namespace_with_separate_tables() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    assert_eq!(h.bind(2, &[], &session_mounts(b"s2")), 0);
    // Each session's tmp is its own.
    assert_eq!(h.names(1, b"/tmp").unwrap(), names(&[b"s1"]));
    assert_eq!(h.names(2, b"/tmp").unwrap(), names(&[b"s2"]));
    assert_eq!(h.write_file(2, b"/tmp/s1/intrude", b"x"), status::NOT_FOUND);
    // A write is visible to the other session at once.
    let handle = h.open(1, 2 | 8, b"/home/operator/shared");
    let write = |offset: u64, data: &[u8]| {
        Frame::request(op::WRITE_AT)
            .u64(handle as u64)
            .u64(offset)
            .bytes(data)
            .finish()
    };
    assert_eq!(h.status(1, write(0, b"aaaa")), 4);
    assert_eq!(h.read_all(2, b"/home/operator/shared").unwrap(), b"aaaa");
    // Overlapping writes: the later request wins for the bytes both cover.
    let other = h.open(2, 2, b"/home/operator/shared");
    let theirs = Frame::request(op::WRITE_AT)
        .u64(other as u64)
        .u64(2)
        .bytes(b"bbbb")
        .finish();
    assert_eq!(h.status(2, theirs), 4);
    assert_eq!(h.status(1, write(4, b"cc")), 2);
    assert_eq!(h.read_all(1, b"/home/operator/shared").unwrap(), b"aabbcc");
    // Handles are per channel: session 2 cannot use session 1's number.
    assert!(handle != other || handle == 1);
    let probe = Frame::request(op::READ_AT).u64(5).u64(0).u32(16).finish();
    assert_eq!(h.status(2, probe), status::BAD_HANDLE);
    // Competing create-new: exactly one wins.
    assert!(h.open(1, 2 | 16, b"/home/operator/race") > 0);
    assert_eq!(h.open(2, 2 | 16, b"/home/operator/race"), -17);
    // Competing rename onto one name: both succeed in order; the name ends
    // with the later one's file, and neither source remains.
    assert_eq!(h.write_file(1, b"/home/operator/one", b"from one"), 0);
    assert_eq!(h.write_file(2, b"/home/operator/two", b"from two"), 0);
    assert_eq!(
        h.rename(1, b"/home/operator/one", b"/home/operator/target", false),
        0
    );
    assert_eq!(
        h.rename(2, b"/home/operator/two", b"/home/operator/target", false),
        0
    );
    assert_eq!(
        h.read_all(1, b"/home/operator/target").unwrap(),
        b"from two"
    );
    assert_eq!(h.open(2, 1, b"/home/operator/one"), status::NOT_FOUND);
    // No-clobber rename refuses deterministically.
    assert_eq!(h.write_file(1, b"/home/operator/three", b"3"), 0);
    assert_eq!(
        h.rename(1, b"/home/operator/three", b"/home/operator/target", true),
        -17
    );
}

#[test]
fn bindings_need_quiescent_channels_and_release_withdraws_authority() {
    let disk = image();
    let mut h = Harness::new(&disk);
    // Before binding, a slot is served nothing.
    assert_eq!(h.open(1, 1, b"/bin/ls"), status::DENIED);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), status::BUSY);
    // Only the control channel binds.
    let frame = Frame::request(op::BIND)
        .u8(2)
        .u8(0)
        .mounts(&session_mounts(b"x"))
        .finish();
    assert_eq!(h.status(1, frame), status::DENIED);
    assert_eq!(h.bind(0, &[], &session_mounts(b"x")), status::INVALID);
    assert_eq!(h.bind(7, &[], &session_mounts(b"x")), status::INVALID);
    // A slot some earlier holder still holds, or with a reply unread, is
    // refused.
    h.pipes = |_| {
        Some(PipeState {
            request_available: 0,
            request_writers: 2,
            reply_available: 0,
            reply_readers: 1,
        })
    };
    assert_eq!(h.bind(2, &[], &session_mounts(b"s2")), status::BUSY);
    h.pipes = |_| {
        Some(PipeState {
            request_available: 0,
            request_writers: 1,
            reply_available: 3,
            reply_readers: 1,
        })
    };
    assert_eq!(h.bind(2, &[], &session_mounts(b"s2")), status::BUSY);
    h.pipes = quiet;
    // Release closes the session's files (committing them) and leaves the
    // slot answering nothing.
    let handle = h.open(1, 2 | 8, b"/home/operator/kept");
    let write = Frame::request(op::WRITE_AT)
        .u64(handle as u64)
        .u64(0)
        .bytes(b"kept")
        .finish();
    assert_eq!(h.status(1, write), 4);
    h.server.resets.clear();
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        1
    );
    // Nothing already sent on the channel is discarded by the release.
    assert!(h.server.resets.is_empty());
    assert_eq!(h.open(1, 1, b"/home/operator/kept"), status::DENIED);
    // Still read (and refused) while an earlier holder may be writing, until
    // only the keeper holds it.
    assert!(h.server.active(1) && h.server.draining(1));
    h.server.settle(
        1,
        Some(PipeState {
            request_available: 0,
            request_writers: 2,
            reply_available: 0,
            reply_readers: 2,
        }),
    );
    assert!(h.server.draining(1));
    h.server.settle(1, quiet(1));
    assert!(!h.server.active(1));
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        status::INVALID
    );
    let fs = Fs::mount(disk.clone(), false).unwrap();
    assert_eq!(fs.stat(b"/home/operator/kept").unwrap().size, 4);
    // The slot binds again; what predates the new binding is discarded.
    assert_eq!(h.bind(1, &[], &session_mounts(b"s3")), 0);
    assert_eq!(h.server.resets, vec![1]);
    assert_eq!(h.read_all(1, b"/home/operator/kept").unwrap(), b"kept");
}

#[test]
fn production_channel_table_refuses_full_and_out_of_range_bind_then_reuses_slot() {
    let disk = image();
    // Production has one control channel and ten client channels.
    let mut h = Harness {
        server: Server::new(
            Fs::mount(disk.clone(), true).unwrap(),
            10,
            vec![Mount::new(b"/ssh", false), Mount::new(b"/bin", false)],
        ),
        pipes: quiet,
        now: 1,
    };
    assert_eq!(h.server.channels(), 11);
    for slot in 1..=10 {
        let name = format!("slot-{slot}");
        assert_eq!(h.bind(slot, &[], &session_mounts(name.as_bytes())), 0);
    }
    assert_eq!(h.server.capacity(), (10, 0, 0));

    let before = h.server.capacity();
    let resets = h.server.resets.clone();
    let objects = h.server.fs.object_count();
    let events = h.server.events.len();
    assert_eq!(h.bind(1, &[], &session_mounts(b"occupied")), status::BUSY);
    assert_eq!(h.server.events.len(), events + 1);
    assert_eq!(
        h.server.events.last(),
        Some(&crate::Event::BindRefused {
            slot: 1,
            status: status::BUSY,
        })
    );
    assert_eq!(
        h.bind(11, &[], &session_mounts(b"out-of-range")),
        status::INVALID
    );
    assert_eq!(h.server.events.len(), events + 1);
    assert_eq!(h.server.capacity(), before);
    assert_eq!(h.server.resets, resets);
    assert_eq!(h.server.fs.object_count(), objects);
    assert!((1..=10).all(|slot| h.server.active(slot)));

    h.server.resets.clear();
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(10).finish()),
        0
    );
    assert!(h.server.draining(10));
    assert_eq!(h.server.capacity(), (9, 0, 1));
    assert!(h.server.settle(10, quiet(10)));
    assert!(!h.server.active(10));
    assert_eq!(h.bind(10, &[], &session_mounts(b"reused")), 0);
    assert_eq!(h.server.resets, vec![10]);
    assert_eq!(h.server.capacity(), (10, 0, 0));
}

#[derive(Clone)]
struct ReleaseWriteFailureDisk {
    disk: Disk,
    fail_next_write: Rc<Cell<bool>>,
    failures: Rc<Cell<usize>>,
}

impl Device for ReleaseWriteFailureDisk {
    fn sectors(&self) -> u64 {
        self.disk.sectors()
    }
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        self.disk.read(sector, buffer)
    }
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        if self.fail_next_write.replace(false) {
            self.failures.set(self.failures.get() + 1);
            return Err(Error::Device(status::IO));
        }
        self.disk.write(sector, buffer)
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.disk.flush()
    }
}

#[test]
fn release_cleanup_write_failure_is_reported_before_success_event() {
    let disk = image();
    let fail_next_write = Rc::new(Cell::new(false));
    let failures = Rc::new(Cell::new(0));
    let device = ReleaseWriteFailureDisk {
        disk: disk.clone(),
        fail_next_write: fail_next_write.clone(),
        failures: failures.clone(),
    };
    let fs = Fs::mount(device, true).unwrap();
    let mut server = Server::new(fs, 6, vec![Mount::new(b"/ssh", false)]);
    let bind = Frame::request(op::BIND)
        .u8(1)
        .u8(0)
        .mounts(&session_mounts(b"release-error"))
        .finish();
    let reply = server.dispatch(CONTROL, body(&bind), &quiet, 1);
    assert_eq!(Reader(&reply[proto::HEADER..]).i64(), Some(0));
    assert!(
        Fs::mount(disk.clone(), false)
            .unwrap()
            .stat(b"/tmp/release-error")
            .is_ok()
    );

    server.events.clear();
    fail_next_write.set(true);
    let release = Frame::request(op::RELEASE).u8(1).finish();
    let reply = server.dispatch(CONTROL, body(&release), &quiet, 2);
    assert_eq!(Reader(&reply[proto::HEADER..]).i64(), Some(status::IO));
    assert_eq!(failures.get(), 1, "cleanup commit reached the device");
    assert!(server.events.is_empty(), "no successful RELEASE event");
    assert!(server.draining(1), "the old channel is not newly bound");
    assert!(
        Fs::mount(disk, false)
            .unwrap()
            .stat(b"/tmp/release-error")
            .is_ok(),
        "failed cleanup was not committed"
    );
}

#[test]
fn release_with_already_absent_scratch_completes_successfully() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"release-absent")), 0);
    // This local substitution removes the declared scratch directory
    // before RELEASE, exercising its NotFound-as-already-clean branch.
    assert_eq!(h.server.fs.remove_tree(b"/tmp/release-absent", true), Ok(1));
    assert_eq!(
        h.server.fs.stat(b"/tmp/release-absent"),
        Err(Error::NotFound)
    );
    h.server.events.clear();
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        0
    );
    assert_eq!(
        h.server.events,
        vec![crate::Event::Released {
            slot: 1,
            closed: 0,
            scratch: 0
        }]
    );
}

#[test]
fn a_session_mount_list_naming_the_recovery_state_is_refused_at_bind() {
    let disk = image();
    let mut server = server(&disk);
    for state in [b"/var/state".as_slice(), b"/var/state/recovery", b"/var/state/facts", b"/var/state.new", b"/var"] {
        let mut mounts = session_mounts(b"one");
        mounts.push(Mount::new(state, false));
        let frame = Frame::request(op::BIND).u8(1).u8(0).mounts(&mounts).finish();
        let reply = server.dispatch(CONTROL, body(&frame), &quiet, 1);
        assert_eq!(Reader(&reply[proto::HEADER..]).i64(), Some(status::INVALID), "{}", core::str::from_utf8(state).unwrap());
        assert!(!server.active(1));
    }
}

#[test]
fn queued_bind_refuses_departed_keeper_before_any_slot_sample() {
    let disk = image();
    let mut server = server(&disk);
    let reads = Cell::new(0);
    let pipes = |channel: usize| {
        reads.set(reads.get() + 1);
        Some(PipeState {
            request_available: 0,
            request_writers: u64::from(channel != CONTROL),
            reply_available: 0,
            reply_readers: 1,
        })
    };
    let frame = Frame::request(op::BIND)
        .u8(1)
        .u8(0)
        .mounts(&session_mounts(b"old-sole"))
        .finish();
    let reply = server.dispatch(CONTROL, body(&frame), &pipes, 1);
    assert_eq!(Reader(&reply[proto::HEADER..]).i64(), Some(status::BUSY));
    assert_eq!(
        reads.get(),
        1,
        "a dead keeper must fail before slot sampling"
    );
    assert!(!server.active(1));
    assert!(server.resets.is_empty());
}

#[test]
fn queued_bind_refuses_old_holder_if_keeper_departs_during_samples() {
    let disk = image();
    let mut server = server(&disk);
    let control_reads = Cell::new(0);
    let pipes = |channel: usize| {
        if channel == CONTROL {
            let previous = control_reads.get();
            control_reads.set(previous + 1);
            return Some(PipeState {
                request_available: 0,
                request_writers: u64::from(previous == 0),
                reply_available: 0,
                reply_readers: 1,
            });
        }
        // The first control sample saw sshd alive. It departs just before
        // this slot sample, leaving an older process as the sole endpoint
        // holder. Count one no longer identifies the keeper.
        Some(PipeState {
            request_available: 0,
            request_writers: 1,
            reply_available: 0,
            reply_readers: 1,
        })
    };
    let frame = Frame::request(op::BIND)
        .u8(1)
        .u8(0)
        .mounts(&session_mounts(b"old-holder"))
        .finish();
    let reply = server.dispatch(CONTROL, body(&frame), &pipes, 1);
    assert_eq!(Reader(&reply[proto::HEADER..]).i64(), Some(status::BUSY));
    assert_eq!(control_reads.get(), 2, "the final writer check must run");
    assert!(!server.active(1));
    assert!(server.resets.is_empty());
    assert_eq!(
        server.events,
        vec![crate::Event::BindRefused {
            slot: 1,
            status: status::BUSY,
        }]
    );
    let open = Frame::request(op::OPEN)
        .u32(1)
        .bytes(b"/home/operator/file")
        .finish();
    let denied = server.dispatch(1, body(&open), &pipes, 2);
    assert_eq!(Reader(&denied[proto::HEADER..]).i64(), Some(status::DENIED));
}

#[test]
fn bind_accepts_live_keeper_without_old_holder() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"live-keeper")), 0);
    assert!(h.server.active(1));
    assert!(matches!(
        h.server.events[..],
        [crate::Event::Bound { slot: 1, .. }]
    ));
    assert!(h.read_all(1, b"/bin/ls").is_ok());
}

#[derive(Clone)]
struct KeeperDepartureDisk {
    disk: Disk,
    keeper_alive: Rc<Cell<bool>>,
    prep_writes: Rc<Cell<usize>>,
}

impl Device for KeeperDepartureDisk {
    fn sectors(&self) -> u64 {
        self.disk.sectors()
    }
    fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
        self.disk.read(sector, buffer)
    }
    fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
        self.prep_writes.set(self.prep_writes.get() + 1);
        self.keeper_alive.set(false);
        self.disk.write(sector, buffer)
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.disk.flush()
    }
}

#[test]
fn bind_rechecks_keeper_after_directory_preparation() {
    let disk = image();
    let keeper_alive = Rc::new(Cell::new(true));
    let prep_writes = Rc::new(Cell::new(0));
    let device = KeeperDepartureDisk {
        disk,
        keeper_alive: keeper_alive.clone(),
        prep_writes: prep_writes.clone(),
    };
    let fs = Fs::mount(device, true).unwrap();
    let mut server = Server::new(fs, 6, vec![Mount::new(b"/ssh", false)]);
    // Ignore any initialization I/O. The first directory-preparation write
    // after the initial pipe samples terminates the keeper in this fixture.
    prep_writes.set(0);
    keeper_alive.set(true);
    let control_reads = Cell::new(0);
    let pipes = |channel: usize| {
        if channel == CONTROL {
            control_reads.set(control_reads.get() + 1);
            Some(PipeState {
                request_available: 0,
                request_writers: u64::from(keeper_alive.get()),
                reply_available: 0,
                reply_readers: 1,
            })
        } else {
            Some(PipeState {
                request_available: 0,
                request_writers: 1,
                reply_available: 0,
                reply_readers: 1,
            })
        }
    };
    let frame = Frame::request(op::BIND)
        .u8(1)
        .u8(0)
        .mounts(&session_mounts(b"during-prep"))
        .finish();
    let reply = server.dispatch(CONTROL, body(&frame), &pipes, 1);
    assert!(
        prep_writes.get() > 0,
        "directory preparation was not exercised"
    );
    assert_eq!(Reader(&reply[proto::HEADER..]).i64(), Some(status::BUSY));
    assert_eq!(control_reads.get(), 2, "the final writer check must run");
    assert!(!server.active(1));
    assert!(server.resets.is_empty());
    assert_eq!(
        server.events,
        vec![crate::Event::BindRefused {
            slot: 1,
            status: status::BUSY,
        }]
    );
}

#[test]
fn nested_mounts_pin_rename_endpoints_and_rmdir() {
    // A mount can name a currently absent subtree. Its namespace anchor
    // remains pinned, whether the nested mount is read-only or writable.
    // Writable bindings create their mount paths; absent mounts are read-only.
    for (writable, exists) in [(false, false), (false, true), (true, true)] {
        let disk = image();
        let mut h = Harness::new(&disk);
        assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
        assert_eq!(h.path_op(1, op::MKDIR, b"/home/operator/a"), 0);
        assert_eq!(h.path_op(1, op::MKDIR, b"/home/operator/z"), 0);
        if exists {
            assert_eq!(h.path_op(1, op::MKDIR, b"/home/operator/a/b"), 0);
        }
        assert_eq!(h.bind(2, &[], &[
            Mount::new(b"/home/operator", true),
            Mount::new(b"/home/operator/a/b", writable),
        ]), 0);
        for noreplace in [false, true] {
            assert_eq!(h.rename(2, b"/home/operator/a", b"/home/operator/moved", noreplace), status::BUSY);
            assert_eq!(h.rename(2, b"/home/operator/z", b"/home/operator/a", noreplace), status::BUSY);
            // Both endpoints are normalized before checking ancestry.
            assert_eq!(h.rename(2, b"/home/operator/z/../a/.", b"/home/operator/moved", noreplace), status::BUSY);
            assert_eq!(h.rename(2, b"/home/operator/z", b"/home/operator/z/../a/.", noreplace), status::BUSY);
        }
        assert_eq!(h.path_op(2, op::RMDIR, b"/home/operator/a"), status::BUSY);
        assert_eq!(h.names(2, b"/home/operator").unwrap(), names(&[b"a", b"z"]));
    }
}

#[test]
fn nested_readonly_mount_does_not_freeze_writable_siblings() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    for path in [b"/home/operator/a".as_slice(), b"/home/operator/a/b", b"/home/operator/a/beside"] {
        assert_eq!(h.path_op(1, op::MKDIR, path), 0);
    }
    assert_eq!(h.write_file(1, b"/home/operator/a/b/secret", b"orig"), 0);
    assert_eq!(h.bind(2, &[], &[
        Mount::new(b"/home/operator", true),
        Mount::new(b"/home/operator/a/b", false),
    ]), 0);
    assert_eq!(h.write_file(2, b"/home/operator/a/b/secret", b"changed"), status::READ_ONLY);
    assert_eq!(h.rename(2, b"/home/operator/a/b", b"/home/operator/b", false), status::READ_ONLY);
    assert_eq!(h.path_op(2, op::RMDIR, b"/home/operator/a/b"), status::READ_ONLY);
    // A byte prefix is not a path ancestor; ordinary siblings still move.
    assert_eq!(h.rename(2, b"/home/operator/a/beside", b"/home/operator/a/beside2", false), 0);
    assert_eq!(h.path_op(2, op::RMDIR, b"/home/operator/a/beside2"), 0);
    assert_eq!(h.write_file(2, b"/home/operator/a/sibling", b"ok"), 0);
    assert_eq!(h.rename(2, b"/home/operator/a/sibling", b"/home/operator/a/other", false), 0);
    assert_eq!(h.read_all(2, b"/home/operator/a/other").unwrap(), b"ok");
    assert_eq!(h.read_all(2, b"/home/operator/a/b/secret").unwrap(), b"orig");
}

#[test]
fn deep_mount_ancestors_and_absent_destinations_stay_pinned() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    for path in [b"/home/operator/a".as_slice(), b"/home/operator/a/b", b"/home/operator/a/b/c", b"/home/operator/z"] {
        assert_eq!(h.path_op(1, op::MKDIR, path), 0);
    }
    assert_eq!(h.bind(2, &[], &[
        Mount::new(b"/home/operator", true),
        Mount::new(b"/home/operator/a/b/c", false),
        Mount::new(b"/home/operator/q/r", false),
    ]), 0);
    for from in [b"/home/operator/a".as_slice(), b"/home/operator/a/b", b"//home//operator/a/", b"//home//operator/a//b//"] {
        assert_eq!(h.rename(2, from, b"/home/operator/moved", false), status::BUSY);
        assert_eq!(h.path_op(2, op::RMDIR, from), status::BUSY);
    }
    for to in [b"/home/operator/q".as_slice(), b"//home//operator//q//"] {
        assert_eq!(h.rename(2, b"/home/operator/z", to, false), status::BUSY);
    }
    assert_eq!(h.names(2, b"/home/operator").unwrap(), names(&[b"a", b"z"]));
}

#[test]
fn a_derived_list_cannot_drop_a_parents_readonly_carveout() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"seed")), 0);
    assert_eq!(h.path_op(1, op::MKDIR, b"/home/operator/a"), 0);
    assert_eq!(h.path_op(1, op::MKDIR, b"/home/operator/a/b"), 0);
    assert_eq!(h.write_file(1, b"/home/operator/a/b/secret", b"orig"), 0);
    assert_eq!(h.bind(3, &[4], &[
        Mount::new(b"/home/operator", true),
        Mount::new(b"/home/operator/a/b", false),
    ]), 0);
    assert_eq!(h.write_file(3, b"/home/operator/a/b/secret", b"parent"), status::READ_ONLY);
    h.pipes = |_| Some(PipeState {
        request_available: 0, request_writers: 2, reply_available: 0, reply_readers: 2,
    });
    let derive = |mounts: &[Mount]| Frame::request(op::DERIVE)
        .u8(1).u8(derive::LIST).mounts(mounts).finish();
    assert_eq!(h.status(3, derive(&[Mount::new(b"/home/operator", true)])), status::DENIED);
    assert_eq!(h.write_file(4, b"/home/operator/a/b/secret", b"child"), status::DENIED);
    assert_eq!(h.read_all(3, b"/home/operator/a/b/secret").unwrap(), b"orig");
}

#[test]
fn derived_lists_compare_effective_access_across_nested_mounts() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[3], &[
        Mount::new(b"/home/operator", true),
        Mount::new(b"/home/operator/a/b", false),
        Mount::new(b"/home/operator/a/b/write", true),
    ]), 0);
    h.pipes = |_| Some(PipeState {
        request_available: 0, request_writers: 2, reply_available: 0, reply_readers: 2,
    });
    let derive = |mounts: &[Mount]| Frame::request(op::DERIVE)
        .u8(1).u8(derive::LIST).mounts(mounts).finish();
    // A wider read-only overlay may replace the exact carve-out. A child
    // may retain a nested writable island the parent really has.
    let narrowed = [
        Mount::new(b"/home/operator", true),
        Mount::new(b"/home/operator/a", false),
        Mount::new(b"/home/operator/a/b/write", true),
    ];
    assert_eq!(h.status(1, derive(&narrowed)), 0);
    assert_eq!(h.write_file(3, b"/home/operator/a/b/write/ok", b"ok"), 0);
    assert_eq!(h.write_file(3, b"/home/operator/a/b/secret", b"no"), status::READ_ONLY);
    for wider in [
        vec![Mount::new(b"/home/operator", true)],
        vec![Mount::new(b"/home/operator/a", true)],
        vec![Mount::new(b"/home/operator/a/b/secret", true)],
        vec![Mount::new(b"/home/operator", false), Mount::new(b"/home/operator/a/b", true)],
        vec![Mount::new(b"/home", false)],
    ] {
        assert_eq!(h.status(1, derive(&wider)), status::DENIED);
        // A refused replacement must not reset the old binding.
        assert_eq!(h.read_all(3, b"/home/operator/a/b/write/ok").unwrap(), b"ok");
        assert_eq!(h.write_file(3, b"/home/operator/a/b/secret", b"no"), status::READ_ONLY);
    }
    for allowed in [
        vec![Mount::new(b"/home/operator", false)],
        vec![Mount::new(b"/home/operator/a/b/write", true)],
        vec![Mount::new(b"/home/operator/a/beside", true)],
        vec![Mount::new(b"/home/operator/a/b", false), Mount::new(b"/home/operator", true)],
        vec![],
    ] {
        assert_eq!(h.status(1, derive(&allowed)), 0);
    }
}

#[test]
fn a_child_binding_only_narrows_the_session() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[3, 4], &session_mounts(b"s1")), 0);
    assert_eq!(h.write_file(1, b"/home/operator/a", b"a"), 0);
    assert_eq!(h.path_op(1, op::MKDIR, b"/home/operator/sub"), 0);
    // A spare serves nothing until the session derives it.
    assert_eq!(h.open(3, 1, b"/home/operator/a"), status::DENIED);
    // Spares of one session are not another's, and are not free slots.
    assert_eq!(h.bind(3, &[], &session_mounts(b"x")), status::BUSY);
    let derive_ro = Frame::request(op::DERIVE)
        .u8(1)
        .u8(derive::READ_ONLY)
        .finish();
    assert_eq!(h.status(1, derive_ro.clone()), 0);
    assert_eq!(h.read_all(3, b"/home/operator/a").unwrap(), b"a");
    assert_eq!(
        h.write_file(3, b"/home/operator/a", b"b"),
        status::READ_ONLY
    );
    assert_eq!(
        h.write_file(3, b"/home/operator/other", b"b"),
        status::READ_ONLY
    );
    // An explicit list inside the session's, never wider.
    let list = |mounts: &[Mount]| {
        Frame::request(op::DERIVE)
            .u8(2)
            .u8(derive::LIST)
            .mounts(mounts)
            .finish()
    };
    assert_eq!(
        h.status(1, list(&[Mount::new(b"/home/operator/sub", true)])),
        0
    );
    assert_eq!(h.write_file(4, b"/home/operator/sub/f", b"f"), 0);
    assert_eq!(
        h.write_file(4, b"/home/operator/a", b"no"),
        status::NOT_FOUND
    );
    assert_eq!(h.read_all(4, b"/etc/motd"), Err(status::NOT_FOUND));
    for wider in [
        vec![Mount::new(b"/bin", true)],
        vec![Mount::new(b"/tmp", false)],
        vec![Mount::new(b"/home", true)],
    ] {
        assert_eq!(h.status(1, list(&wider)), status::DENIED);
    }
    assert_eq!(
        h.status(1, list(&[Mount::new(b"/ssh", false)])),
        status::INVALID
    );
    // The recovery state and anything above it is never a session path,
    // however it is asked for.
    for state in [b"/var/state".as_slice(), b"/var/state/facts", b"/var/state.new", b"/var"] {
        assert_eq!(h.status(1, list(&[Mount::new(state, false)])), status::INVALID, "{}", core::str::from_utf8(state).unwrap());
    }
    // A spare still held by an earlier child's tree is refused.
    h.pipes = |_| {
        Some(PipeState {
            request_available: 0,
            request_writers: 3,
            reply_available: 0,
            reply_readers: 2,
        })
    };
    assert_eq!(h.status(1, derive_ro.clone()), status::BUSY);
    h.pipes = quiet;
    // Nothing but the owning session derives, and a spare cannot derive.
    assert_eq!(h.bind(2, &[], &session_mounts(b"s2")), 0);
    assert_eq!(h.status(2, derive_ro.clone()), status::INVALID);
    assert_eq!(h.status(3, derive_ro.clone()), status::DENIED);
    // Release of the session withdraws its spares too.
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        0
    );
    assert_eq!(h.open(3, 1, b"/home/operator/a"), status::DENIED);
    assert_eq!(h.open(4, 1, b"/home/operator/sub/f"), status::DENIED);
}

#[test]
fn written_data_is_committed_on_close_or_after_the_idle_bound() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    let handle = h.open(1, 2 | 8, b"/home/operator/log");
    let write = Frame::request(op::WRITE_AT)
        .u64(handle as u64)
        .u64(0)
        .bytes(b"line\n")
        .finish();
    assert_eq!(h.status(1, write), 5);
    // Created (a namespace change, committed at once) but its length not yet.
    assert_eq!(
        Fs::mount(disk.clone(), false)
            .unwrap()
            .stat(b"/home/operator/log")
            .unwrap()
            .size,
        0
    );
    assert!(!h.server.idle_commit(h.now + 10).unwrap());
    assert!(
        h.server
            .idle_commit(h.now + crate::server::COMMIT_TICKS)
            .unwrap()
    );
    assert_eq!(
        Fs::mount(disk.clone(), false)
            .unwrap()
            .stat(b"/home/operator/log")
            .unwrap()
            .size,
        5
    );
    let write = Frame::request(op::WRITE_AT)
        .u64(handle as u64)
        .u64(5)
        .bytes(b"more\n")
        .finish();
    assert_eq!(h.status(1, write), 5);
    assert_eq!(
        h.status(1, Frame::request(op::CLOSE).u64(handle as u64).finish()),
        0
    );
    assert_eq!(
        Fs::mount(disk.clone(), false)
            .unwrap()
            .stat(b"/home/operator/log")
            .unwrap()
            .size,
        10
    );
}

#[test]
fn normalization_is_lexical_and_bounded() {
    use crate::proto::{normalize, within};
    assert_eq!(normalize(b"/a/./b//../c").unwrap(), b"/a/c");
    assert_eq!(normalize(b"/../..").unwrap(), b"/");
    assert_eq!(normalize(b"a/b"), None);
    assert_eq!(normalize(b"/a\0b"), None);
    assert!(within(b"/home/operator/x", b"/home/operator"));
    assert!(within(b"/home/operator", b"/home/operator"));
    assert!(!within(b"/home/operatorx", b"/home/operator"));
    assert!(within(b"/anything", b"/"));
}

#[test]
fn session_scratch_starts_empty_and_home_persists() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    assert_eq!(h.path_op(1, op::MKDIR, b"/tmp/s1/deep"), 0);
    assert_eq!(h.write_file(1, b"/tmp/s1/deep/f", b"scratch"), 0);
    assert_eq!(h.write_file(1, b"/home/operator/kept", b"home"), 0);
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        0
    );
    // Released: the session's scratch is gone; a later session sees only its own.
    assert_eq!(h.bind(2, &[], &session_mounts(b"s2")), 0);
    assert_eq!(h.names(2, b"/tmp").unwrap(), names(&[b"s2"]));
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(2).finish()),
        0
    );
    // A new server (a reboot) and a new session of the same name.
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(2, &[], &session_mounts(b"s1")), 0);
    assert_eq!(h.names(2, b"/tmp/s1").unwrap(), Vec::<Vec<u8>>::new());
    assert_eq!(h.read_all(2, b"/home/operator/kept").unwrap(), b"home");
}

#[test]
fn releasing_a_full_scratch_tree_is_one_commit() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    // Many empty files and a nested chain, as a session's tools leave them.
    for index in 0..800 {
        let path = std::format!("/tmp/s1/f{index}");
        let handle = h.open(1, 2 | 8, path.as_bytes());
        assert!(handle > 0, "{path}: {handle}");
        assert_eq!(
            h.status(1, Frame::request(op::CLOSE).u64(handle as u64).finish()),
            0
        );
    }
    let mut deep = b"/tmp/s1".to_vec();
    for _ in 0..100 {
        deep.extend_from_slice(b"/d");
        assert_eq!(h.path_op(1, op::MKDIR, &deep), 0);
    }
    let commits = h.server.fs.write_stats().commits;
    h.server.events.clear();
    h.server.resets.clear();
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        0
    );
    assert!(h.server.resets.is_empty());
    assert_eq!(h.server.fs.write_stats().commits, commits + 1);
    assert_eq!(
        h.server.events,
        vec![crate::Event::Released {
            slot: 1,
            closed: 0,
            scratch: 1 + 800 + 100
        }]
    );
    assert_eq!(h.server.fs.stat(b"/tmp/s1"), Err(Error::NotFound));
    // Binding a name whose scratch an earlier boot left: emptied the same way.
    assert_eq!(h.bind(2, &[], &session_mounts(b"s2")), 0);
    for index in 0..50 {
        assert_eq!(
            h.write_file(2, std::format!("/tmp/s2/g{index}").as_bytes(), b"x"),
            0
        );
    }
    let mut h = Harness::new(&disk);
    let commits = h.server.fs.write_stats().commits;
    assert_eq!(h.bind(2, &[], &session_mounts(b"s2")), 0);
    assert_eq!(h.server.fs.write_stats().commits, commits + 1);
    assert_eq!(h.names(2, b"/tmp/s2").unwrap(), Vec::<Vec<u8>>::new());
}

#[test]
fn space_reports_the_format_and_commit_makes_accepted_writes_durable() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    // Unbound channels are refused like every other request.
    assert_eq!(
        h.status(2, Frame::request(op::SPACE).finish()),
        status::DENIED
    );
    assert_eq!(
        h.status(2, Frame::request(op::COMMIT).finish()),
        status::DENIED
    );
    let space = |h: &mut Harness| {
        let (code, payload) = h.call(1, Frame::request(op::SPACE).finish());
        assert_eq!((code, payload.len()), (0, proto::SPACE_BYTES));
        let mut reader = Reader(&payload);
        let block = reader.u32().unwrap();
        let blocks = reader.u32().unwrap();
        let free = reader.u32().unwrap();
        assert_eq!(reader.u32(), Some(0));
        let _fs_id = reader.u64().unwrap();
        (block, blocks, free, reader.u64().unwrap())
    };
    let (block, blocks, free, _) = space(&mut h);
    let fresh = Fs::mount(disk.clone(), false).unwrap();
    assert_eq!(
        (block as usize, blocks, free),
        (
            absd_fs::BLOCK,
            fresh.geometry().data_blocks,
            fresh.free_blocks()
        )
    );
    let handle = h.open(1, 2 | 8, b"/home/operator/log");
    let data = vec![7u8; 3 * absd_fs::BLOCK];
    let write = Frame::request(op::WRITE_AT)
        .u64(handle as u64)
        .u64(0)
        .bytes(&data)
        .finish();
    assert_eq!(h.status(1, write), data.len() as i64);
    // Accepted, not yet durable (open, and inside the idle bound).
    assert_eq!(
        Fs::mount(disk.clone(), false)
            .unwrap()
            .stat(b"/home/operator/log")
            .unwrap()
            .size,
        0
    );
    let (_, _, used_free, _) = space(&mut h);
    assert_eq!(used_free, free - 3);
    let (code, payload) = h.call(1, Frame::request(op::COMMIT).finish());
    assert_eq!(code, 0);
    let sequence = u64::from_le_bytes(payload.as_slice().try_into().unwrap());
    let durable = Fs::mount(disk.clone(), false).unwrap();
    assert_eq!(
        durable.stat(b"/home/operator/log").unwrap().size,
        data.len() as u64
    );
    assert_eq!(durable.sequence(), sequence);
    assert_eq!(space(&mut h).3, sequence);
    assert_eq!(
        h.status(1, Frame::request(op::CLOSE).u64(handle as u64).finish()),
        0
    );
}

#[test]
fn notices_come_from_the_control_channel_only_and_are_made_printable() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    h.server.events.clear();
    let notice = |text: &[u8]| Frame::request(op::NOTICE).bytes(text).finish();
    assert_eq!(h.status(1, notice(b"from a session")), status::DENIED);
    assert!(h.server.events.is_empty());
    assert_eq!(
        h.status(CONTROL, notice(b"host key 256 SHA256:x\x1b[2J\n")),
        0
    );
    assert_eq!(
        h.server.events,
        vec![crate::Event::Notice(b"host key 256 SHA256:x?[2J?".to_vec())]
    );
    assert_eq!(
        h.status(CONTROL, notice(&vec![b'a'; proto::MAX_NOTICE + 1])),
        status::INVALID
    );
}

#[test]
fn civil_time_matches_known_instants() {
    use crate::civil::Utc;
    let text = |s: u64| std::format!("{} | {}", Utc::from_unix(s), Utc::from_unix(s).iso());
    assert_eq!(
        text(0),
        "Thu Jan  1 00:00:00 UTC 1970 | 1970-01-01T00:00:00Z"
    );
    // 2000-02-29 (a leap day of a century leap year), 2100-03-01 (2100 is
    // not a leap year), and the day this was written.
    assert_eq!(
        text(951_782_400),
        "Tue Feb 29 00:00:00 UTC 2000 | 2000-02-29T00:00:00Z"
    );
    assert_eq!(
        text(4_107_542_400),
        "Mon Mar  1 00:00:00 UTC 2100 | 2100-03-01T00:00:00Z"
    );
    assert_eq!(
        text(1_790_487_252),
        "Sun Sep 27 05:34:12 UTC 2026 | 2026-09-27T05:34:12Z"
    );
    assert_eq!(
        text(1_790_553_599),
        "Sun Sep 27 23:59:59 UTC 2026 | 2026-09-27T23:59:59Z"
    );
}

#[test]
fn logs_are_bounded_by_rotation_and_count_dropped_lines() {
    use crate::log::{LIMIT, LogFile, MAX_LINE, line, must_rotate};
    assert_eq!(
        line(Some(0), "fsd", "ready"),
        b"1970-01-01T00:00:00Z fsd: ready\n"
    );
    assert_eq!(line(None, "sshd", "a\x07b"), b"- sshd: a?b\n");
    assert_eq!(line(None, "sshd", &"x".repeat(2000)).len(), MAX_LINE);
    assert!(
        !must_rotate(0, 100) && !must_rotate(LIMIT - 100, 100) && must_rotate(LIMIT - 100, 101)
    );

    let disk = image();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    fs.mkdir(b"/var").unwrap();
    fs.mkdir(b"/var/log").unwrap();
    let mut log = LogFile::new(b"/var/log/fsd", "fsd");
    let one = line(Some(0), "fsd", &"y".repeat(100));
    let per_file = (LIMIT / one.len() as u64) as usize;
    for _ in 0..per_file * 2 + 3 {
        log.append(&mut fs, Some(0), &one).unwrap();
    }
    let size = |fs: &Fs<Disk>, path: &[u8]| fs.stat(path).unwrap().size;
    // Two rotations: the current log holds the last three lines, `.0` a
    // full file; never more than 2 * LIMIT in all.
    assert_eq!(size(&fs, b"/var/log/fsd"), 3 * one.len() as u64);
    assert_eq!(size(&fs, b"/var/log/fsd.0"), (per_file * one.len()) as u64);
    // A refused write drops the line and says so with the next one.
    fs.set_readonly_path(b"/var/log/fsd", true).unwrap();
    assert!(log.append(&mut fs, Some(0), &one).is_err());
    assert!(log.append(&mut fs, Some(0), &one).is_err());
    assert_eq!(log.dropped, 2);
    fs.set_readonly_path(b"/var/log/fsd", false).unwrap();
    log.append(&mut fs, Some(0), &one).unwrap();
    assert_eq!(log.dropped, 0);
    let handle = fs
        .open(
            b"/var/log/fsd",
            OpenFlags {
                read: true,
                write: false,
                create: false,
                create_new: false,
                truncate: false,
            },
        )
        .unwrap();
    let mut data = vec![0u8; 4 * one.len() + 64];
    let count = fs.read_at(handle, 0, &mut data).unwrap();
    let mut want = one.repeat(3);
    want.extend_from_slice(b"1970-01-01T00:00:00Z fsd: log: 2 lines dropped\n");
    want.extend_from_slice(&one);
    assert_eq!(&data[..count], &want[..]);
}

/// What one look at a channel came to, as the loop would log or reply it.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Not read: unbound and quiet.
    Skipped,
    /// Read, but no whole request there.
    Nothing,
    /// A request served, with the status replied.
    Replied(i64),
}

/// The loop of `ssh/src/fsd_server.rs` over fake pipes: a request queue,
/// a reply queue, and the loop's inbox per channel, taking the same
/// decisions in the same order. What no guest run can force, the order in
/// which the control channel's `RELEASE` and a released channel's bytes
/// are read, is fixed here by calling `serve` in that order.
struct Pipes {
    request: Vec<Vec<u8>>,
    reply: Vec<Vec<u8>>,
    inbox: Vec<Inbox>,
}

impl Pipes {
    fn new(channels: usize) -> Self {
        Self {
            request: vec![Vec::new(); channels],
            reply: vec![Vec::new(); channels],
            inbox: (0..channels).map(|_| Inbox::new()).collect(),
        }
    }
    /// A client writes `bytes` on its channel; nothing reads them yet.
    fn queue(&mut self, channel: usize, bytes: &[u8]) {
        self.request[channel].extend_from_slice(bytes);
    }
    /// The kernel's view (with the loop's own buffer counted as waiting,
    /// as the loop reports it): only the keeper holds client ends.
    fn state(&self, channel: usize) -> Option<PipeState> {
        Some(PipeState {
            request_available: (self.request[channel].len() + self.inbox[channel].len()) as u64,
            request_writers: 1,
            reply_available: self.reply[channel].len() as u64,
            reply_readers: 1,
        })
    }
    /// sshd, before a bind: a reply an earlier holder never read.
    fn drain_reply(&mut self, channel: usize) -> Vec<u8> {
        core::mem::take(&mut self.reply[channel])
    }
    fn replied_status(&self, channel: usize) -> Option<i64> {
        let reply = &self.reply[channel];
        (reply.len() >= proto::HEADER + 8 + proto::TRAILER)
            .then(|| Reader(&reply[proto::HEADER..]).i64().unwrap())
    }
    /// One look at `channel`, as the loop takes it.
    fn serve(&mut self, h: &mut Harness, channel: usize) -> Step {
        if !h.server.active(channel) {
            return Step::Skipped;
        }
        // Read what waits, up to a whole request (the loop reads in
        // transfers; the count does not matter here).
        while self.inbox[channel].wants_more() && !self.request[channel].is_empty() {
            let chunk: Vec<u8> = self.request[channel].drain(..).collect();
            self.inbox[channel].push(&chunk);
        }
        let mut taken = self.inbox[channel].take();
        if taken == Taken::Nothing && self.request[channel].is_empty() {
            // The pipe is quiet: a head that cannot complete is given up
            // for a whole frame behind it, as the loop does on a timeout.
            self.inbox[channel].idle();
            taken = self.inbox[channel].take();
        }
        match taken {
            Taken::Nothing => {
                if h.server.draining(channel) && self.request[channel].is_empty() {
                    // Quiet and released: what is left can never complete.
                    self.inbox[channel].discard();
                    h.server.settle(channel, self.state(channel));
                }
                Step::Nothing
            }
            Taken::Frame { seq, body } => {
                let lookup = |index: usize| self.state(index);
                let mut reply = h.server.dispatch(channel, &body, &lookup, h.now);
                proto::stamp_seq(&mut reply, seq);
                let status = Reader(&reply[proto::HEADER..]).i64().unwrap();
                for index in core::mem::take(&mut h.server.resets) {
                    self.inbox[index].discard();
                    self.request[index].clear();
                }
                // A live client reads its reply at once; a released
                // channel's client may be gone, and its reply waits.
                if h.server.draining(channel) {
                    self.reply[channel].extend_from_slice(&reply);
                }
                Step::Replied(status)
            }
        }
    }
}

/// The owner's rule for a released channel against a rebound one. A
/// release ends a binding and closes its files, but bytes accepted while
/// the binding was live are still consumed: a whole request is refused
/// (`-13`), bytes that are no frame are dropped, and the channel quiesces
/// after that. A bind discards everything that predates it, so no request of an
/// earlier binding runs under the new one; and a bind that arrives before
/// the released work is consumed (the request not yet read, or its
/// refusal not yet drained) waits (BUSY, `FSD BIND DEFERRED`) rather than
/// discard it. The bytes here are written before the `RELEASE` is served
/// and read only after it, the order a loaded guest produces sometimes
/// and this test always.
#[test]
fn release_answers_what_was_sent_and_bind_discards_what_predates_it() {
    let disk = image();
    let mut h = Harness::new(&disk);
    let mut pipes = Pipes::new(h.server.channels());
    let garbage = [0xffu8; 4]; // what `fsd-probe garbage` writes
    let mkdir = |path: &[u8]| Frame::request(op::MKDIR).bytes(path).finish();

    // A session on slot 1 with spare 2 (a child's channel) and a file open.
    pipes.queue(
        CONTROL,
        &Frame::request(op::BIND)
            .u8(1)
            .u8(1)
            .u8(2)
            .mounts(&session_mounts(b"s1"))
            .finish(),
    );
    assert_eq!(pipes.serve(&mut h, CONTROL), Step::Replied(0));
    pipes.queue(
        1,
        &Frame::request(op::DERIVE).u8(1).u8(derive::SAME).finish(),
    );
    assert_eq!(pipes.serve(&mut h, 1), Step::Replied(0));
    pipes.queue(
        1,
        &Frame::request(op::OPEN)
            .u32(2 | 8)
            .bytes(b"/home/operator/held")
            .finish(),
    );
    assert!(matches!(pipes.serve(&mut h, 1), Step::Replied(handle) if handle > 0));

    // The session writes on both channels and exits: four garbage bytes on
    // its own channel, a whole valid request on the child's, of which the
    // loop has read the first three bytes. Then sshd releases the slot,
    // and the release is served before either channel is read further.
    pipes.queue(1, &garbage);
    let late = mkdir(b"/home/operator/late");
    pipes.inbox[2].push(&late[..3]);
    pipes.queue(2, &late[3..]);
    pipes.queue(CONTROL, &Frame::request(op::RELEASE).u8(1).finish());
    h.server.events.clear();
    assert_eq!(pipes.serve(&mut h, CONTROL), Step::Replied(1));
    assert_eq!(
        h.server.events,
        vec![crate::Event::Released {
            slot: 1,
            closed: 1,
            scratch: 1
        }]
    );
    // Nothing was discarded: the bytes wait where they were.
    assert_eq!(pipes.request[1], garbage);
    assert_eq!(pipes.request[2], late[3..]);
    assert!(!pipes.inbox[2].is_empty());
    assert!(h.server.active(1) && h.server.active(2));
    // A bind for the slot arriving now, before that work is consumed,
    // waits rather than discard it: BUSY, deferred (not a leak), and the
    // bytes still where they were. The same for the spare alone.
    let rebind = Frame::request(op::BIND)
        .u8(1)
        .u8(1)
        .u8(2)
        .mounts(&session_mounts(b"s2"))
        .finish();
    h.server.events.clear();
    pipes.queue(CONTROL, &rebind);
    assert_eq!(pipes.serve(&mut h, CONTROL), Step::Replied(status::BUSY));
    assert_eq!(
        h.server.events,
        vec![crate::Event::BindDeferred { slot: 1 }]
    );
    assert_eq!(pipes.request[1], garbage);
    assert!(!pipes.inbox[2].is_empty() && pipes.request[2] == late[3..]);
    h.server.events.clear();
    pipes.queue(
        CONTROL,
        &Frame::request(op::BIND)
            .u8(2)
            .u8(0)
            .mounts(&session_mounts(b"s2"))
            .finish(),
    );
    assert_eq!(pipes.serve(&mut h, CONTROL), Step::Replied(status::BUSY));
    assert_eq!(
        h.server.events,
        vec![crate::Event::BindDeferred { slot: 2 }]
    );

    // Read after the release: the garbage is dropped and that channel is
    // quiet at once (the files were already closed), the request is
    // refused, not run, and the other channel quiesces only after its
    // bytes were consumed.
    assert_eq!(pipes.serve(&mut h, 1), Step::Nothing);
    assert!(pipes.request[1].is_empty() && pipes.inbox[1].is_empty());
    assert!(!h.server.active(1));
    assert_eq!(pipes.serve(&mut h, 2), Step::Replied(status::DENIED));
    assert_eq!(pipes.replied_status(2), Some(status::DENIED));
    assert_eq!(
        h.server.fs.stat(b"/home/operator/late"),
        Err(Error::NotFound)
    );
    assert!(pipes.request[2].is_empty());
    assert!(h.server.draining(2));
    assert_eq!(pipes.serve(&mut h, 2), Step::Nothing);
    // Its reply is unread: the channel is not quiet until sshd drains it,
    // and a bind before that drain is deferred too, not refused as a leak.
    assert!(h.server.draining(2));
    h.server.events.clear();
    pipes.queue(CONTROL, &rebind);
    assert_eq!(pipes.serve(&mut h, CONTROL), Step::Replied(status::BUSY));
    assert_eq!(
        h.server.events,
        vec![crate::Event::BindDeferred { slot: 1 }]
    );
    // A holder other than sshd, by contrast, is a leak and says so.
    h.server.events.clear();
    h.server.resets.clear();
    let dispatch = Frame::request(op::BIND)
        .u8(3)
        .u8(0)
        .mounts(&session_mounts(b"x"))
        .finish();
    let held = |_: usize| {
        Some(PipeState {
            request_available: 0,
            request_writers: 2,
            reply_available: 0,
            reply_readers: 1,
        })
    };
    assert_eq!(
        Reader(&h.server.dispatch(CONTROL, body(&dispatch), &held, 1)[proto::HEADER..]).i64(),
        Some(status::BUSY)
    );
    assert_eq!(
        h.server.events,
        vec![crate::Event::BindRefused {
            slot: 3,
            status: status::BUSY
        }]
    );
    pipes.drain_reply(2);
    assert_eq!(pipes.serve(&mut h, 2), Step::Nothing);
    assert!(!h.server.active(2));
    assert_eq!(pipes.serve(&mut h, 1), Step::Skipped);

    // Before the next binding, more arrives from nowhere good: a valid
    // request on the slot, garbage on the spare. The bind discards both
    // and runs nothing from before it.
    pipes.queue(1, &mkdir(b"/home/operator/stale"));
    pipes.queue(2, &garbage);
    h.server.events.clear();
    pipes.queue(CONTROL, &rebind);
    assert_eq!(pipes.serve(&mut h, CONTROL), Step::Replied(0));
    assert!(matches!(
        h.server.events[..],
        [crate::Event::Bound { slot: 1, .. }]
    ));
    assert!(pipes.request[1].is_empty() && pipes.request[2].is_empty());
    assert!(pipes.inbox[1].is_empty() && pipes.inbox[2].is_empty());
    assert_eq!(pipes.serve(&mut h, 1), Step::Nothing);
    assert_eq!(pipes.serve(&mut h, 2), Step::Skipped); // a spare not yet derived
    assert_eq!(
        h.server.fs.stat(b"/home/operator/stale"),
        Err(Error::NotFound)
    );
    // The new binding is served as usual.
    pipes.queue(1, &mkdir(b"/home/operator/fresh"));
    assert_eq!(pipes.serve(&mut h, 1), Step::Replied(0));
    assert!(h.server.fs.stat(b"/home/operator/fresh").is_ok());
}

/// Audit probe (2026-10-02, lane/architecture-audit-20261002): a session's
/// scratch is removed at RELEASE and emptied at the next BIND of the same
/// name, but a session that was bound when the machine reset (the served
/// recovery path) is never released. Its scratch tree survives the reboot
/// under a per-boot name (`/tmp/session-N`, N restarting at 1), counted in
/// the next boot's `fs_objects` baseline, invisible to every session, and
/// removed only if a later boot happens to bind the same name.
#[test]
fn scratch_of_an_unreleased_session_survives_a_reboot_until_its_name_is_rebound() {
    let disk = image();
    let mut h = Harness::new(&disk);
    let fresh = h.server.fs.object_count();
    assert_eq!(h.bind(1, &[], &session_mounts(b"session-3")), 0);
    assert_eq!(h.path_op(1, op::MKDIR, b"/tmp/session-3/deep"), 0);
    assert_eq!(h.write_file(1, b"/tmp/session-3/deep/f", b"residue"), 0);
    // The machine resets with the session still bound: no RELEASE. The next
    // boot mounts the same committed image.
    let mut h = Harness::new(&disk);
    let after_reset = h.server.fs.object_count();
    assert!(after_reset > fresh, "residue is in the new boot's baseline");
    let listed = h.server.fs.read_dir(b"/tmp").unwrap();
    assert!(listed.iter().any(|(name, _)| name == b"session-3"));
    // A new session of another name neither sees nor reaches it.
    assert_eq!(h.bind(1, &[], &session_mounts(b"session-1")), 0);
    assert_eq!(h.names(1, b"/tmp").unwrap(), names(&[b"session-1"]));
    assert_eq!(h.read_all(1, b"/tmp/session-3/deep/f"), Err(status::NOT_FOUND));
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        0
    );
    // Releasing an unrelated session does not reclaim it either.
    assert!(h.server.fs.object_count() > fresh);
    // Only a later binding of the same name empties it.
    assert_eq!(h.bind(2, &[], &session_mounts(b"session-3")), 0);
    assert_eq!(h.names(2, b"/tmp/session-3").unwrap(), Vec::<Vec<u8>>::new());
}

// -- Framing v2: a frame is bound to the holder that sent it ----------------
//
// Repair of audit findings D5 and D6 (docs/architecture-audit-20261002 in
// the kernel): a request carries a magic, its holder's sequence word, and a
// check over the whole frame, so bytes a dead holder left behind can never
// be completed by the next holder's bytes, and the next holder's first
// whole request is found from a clean boundary.

fn body_of(frame: &[u8]) -> Vec<u8> {
    frame[proto::HEADER..frame.len() - proto::TRAILER].to_vec()
}

fn drain(inbox: &mut Inbox) -> Vec<(u64, Vec<u8>)> {
    let mut got = Vec::new();
    loop {
        match inbox.take() {
            Taken::Frame { seq, body } => got.push((seq, body)),
            Taken::Nothing => return got,
        }
    }
}

#[test]
fn frames_carry_magic_sequence_and_check() {
    let frame = Frame::request(op::STAT).bytes(b"/etc/motd").finish_seq(7);
    assert_eq!(&frame[..4], &proto::MAGIC);
    let (length, seq) = proto::parse_header(&frame[..proto::HEADER]).unwrap();
    assert_eq!(seq, 7);
    assert_eq!(length, frame.len() - proto::HEADER - proto::TRAILER);
    assert!(proto::verify(&frame));
    let mut flipped = frame.clone();
    flipped[proto::HEADER] ^= 1;
    assert!(!proto::verify(&flipped));
    let mut restamped = frame.clone();
    proto::stamp_seq(&mut restamped, 9);
    assert!(proto::verify(&restamped));
    assert_eq!(proto::parse_header(&restamped[..proto::HEADER]).unwrap().1, 9);
    // `finish` is `finish_seq(0)`.
    assert_eq!(Frame::request(op::STAT).bytes(b"/x").finish(), Frame::request(op::STAT).bytes(b"/x").finish_seq(0));
    // A header without the magic, a zero length, or a length over the
    // largest body is no header at all.
    let mut bad = frame[..proto::HEADER].to_vec();
    bad[0] ^= 1;
    assert_eq!(proto::parse_header(&bad), None);
    let zero = Frame::request(op::STAT).finish_seq(1);
    let mut zero_len = zero[..proto::HEADER].to_vec();
    zero_len[4..8].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(proto::parse_header(&zero_len), None);
    let mut huge = zero[..proto::HEADER].to_vec();
    huge[4..8].copy_from_slice(&((proto::MAX_BODY + 1) as u32).to_le_bytes());
    assert_eq!(proto::parse_header(&huge), None);
}

#[test]
fn a_dead_holders_partial_frame_never_completes_from_the_next_holders_bytes() {
    // Holder A (a child) is killed after `n` bytes of a 300-byte write; B
    // (its parent, the same channel) then sends a whole request. Whatever
    // `n`, A's request never surfaces and B's is taken exactly, from the
    // boundary B wrote it at, with B's sequence word.
    let a = Frame::request(op::WRITE_AT).u64(1).u64(0).bytes(&[b'A'; 300]).finish_seq(0x1_0000_0001);
    let b = Frame::request(op::STAT).bytes(b"/etc/motd").finish_seq(0x2_0000_0001);
    for n in 1..a.len() {
        let mut inbox = Inbox::new();
        inbox.push(&a[..n]);
        inbox.push(&b);
        let mut got = drain(&mut inbox);
        // The pipe went quiet (B waits for its reply): a head that can never
        // complete is given up and B is found behind it.
        inbox.idle();
        got.extend(drain(&mut inbox));
        assert_eq!(got, vec![(0x2_0000_0001, body_of(&b))], "prefix {n}");
        assert!(inbox.is_empty(), "prefix {n}");
    }
}

#[test]
fn a_slow_holder_is_never_given_up_on() {
    // The same prefixes, but the holder is merely slow: the pipe goes quiet
    // and nothing else arrives. Nothing is taken, nothing is dropped, and
    // the rest of the frame completes it.
    let a = Frame::request(op::WRITE_AT).u64(1).u64(0).bytes(&[b'A'; 300]).finish_seq(0x1_0000_0001);
    for n in 1..a.len() {
        let mut inbox = Inbox::new();
        inbox.push(&a[..n]);
        assert_eq!(drain(&mut inbox), vec![], "prefix {n}");
        inbox.idle();
        assert_eq!(drain(&mut inbox), vec![], "prefix {n}");
        assert_eq!(inbox.len(), n, "prefix {n}");
        inbox.push(&a[n..]);
        assert_eq!(drain(&mut inbox), vec![(0x1_0000_0001, body_of(&a))], "prefix {n}");
    }
}

#[test]
fn whole_frames_are_taken_in_order_and_garbage_between_them_is_dropped() {
    let a = Frame::request(op::STAT).bytes(b"/a").finish_seq(1);
    let b = Frame::request(op::STAT).bytes(b"/b").finish_seq(2);
    let mut inbox = Inbox::new();
    inbox.push(&a);
    inbox.push(&b);
    assert_eq!(drain(&mut inbox), vec![(1, body_of(&a)), (2, body_of(&b))]);
    // `fsd-probe garbage` writes four 0xff bytes; a zero length and a body
    // over the largest frame are garbage too. Each is dropped and the next
    // whole frame is taken, even when its magic is split across two reads.
    inbox.push(&[0xff; 4]);
    inbox.push(&[0, 0, 0, 0]);
    inbox.push(&((proto::MAX_BODY as u32 + 1).to_le_bytes()));
    inbox.push(&a[..2]);
    assert_eq!(drain(&mut inbox), vec![]);
    inbox.push(&a[2..]);
    assert_eq!(drain(&mut inbox), vec![(1, body_of(&a))]);
    assert!(inbox.is_empty());
    // A frame whose check fails (a hybrid of two holders' bytes) is dropped
    // and the whole frame inside it is found.
    let mut hybrid = a.clone();
    hybrid.truncate(a.len() - 3);
    hybrid.extend_from_slice(&b);
    inbox.push(&hybrid);
    inbox.push(&a[..3]);
    assert_eq!(drain(&mut inbox), vec![(2, body_of(&b))]);
    inbox.push(&a[3..]);
    assert_eq!(drain(&mut inbox), vec![(1, body_of(&a))]);
}

#[test]
fn a_reader_skips_replies_addressed_to_an_earlier_holder() {
    // The reply side: whole frames always, in order (the loop finishes one
    // reply before it reads the next request), but the first may be a dead
    // child's. The reader waits for its own sequence word.
    let stale = Frame::reply(0).bytes(b"old").finish_seq(0x1_0000_0003);
    let mine = Frame::reply(0).bytes(b"new").finish_seq(0x2_0000_0001);
    let mut inbox = Inbox::new();
    inbox.push(&stale);
    assert_eq!(inbox.take_for(0x2_0000_0001), None);
    inbox.push(&mine[..7]);
    assert_eq!(inbox.take_for(0x2_0000_0001), None);
    inbox.push(&mine[7..]);
    assert_eq!(inbox.take_for(0x2_0000_0001), Some(body_of(&mine)));
    assert!(inbox.is_empty());
}

/// Repair of audit finding C1: the file server sweeps `/tmp` before it
/// serves, so a session that was bound when the machine reset leaves
/// nothing for the next boot to count, and nothing that a later session
/// of the same per-boot name could meet.
#[test]
fn a_new_server_sweeps_stale_scratch_before_serving() {
    let disk = image();
    let mut h = Harness::new(&disk);
    let fresh = h.server.fs.object_count();
    assert_eq!(h.bind(1, &[], &session_mounts(b"session-3")), 0);
    assert_eq!(h.path_op(1, op::MKDIR, b"/tmp/session-3/deep"), 0);
    assert_eq!(h.write_file(1, b"/tmp/session-3/deep/f", b"residue"), 0);
    assert_eq!(h.write_file(1, b"/home/operator/kept", b"home"), 0);
    // The machine resets with the session still bound: no RELEASE.
    let mut h = Harness::new(&disk);
    assert!(h.server.fs.object_count() > fresh + 1);
    let swept = h.server.sweep_scratch().unwrap();
    assert_eq!(swept, 3, "the directory, its subdirectory, and the file");
    assert_eq!(h.server.fs.read_dir(b"/tmp").unwrap(), vec![]);
    // Left: `/tmp` and `/home/operator` (made at the first bind) and `kept`.
    assert_eq!(h.server.fs.object_count(), fresh + 3);
    assert_eq!(h.read_all(CONTROL, b"/home/operator/kept").err(), Some(status::NOT_FOUND));
    // Nothing to sweep is not an error, and home is untouched.
    assert_eq!(h.server.sweep_scratch().unwrap(), 0);
    assert_eq!(h.bind(1, &[], &session_mounts(b"session-1")), 0);
    assert_eq!(h.read_all(1, b"/home/operator/kept").unwrap(), b"home");
}

/// Repair of audit finding D4: a session fills the object budget and the
/// machine resets. The next boot still binds a session (the scratch
/// directory comes out of the reserve) and that session can delete.
#[test]
fn a_full_filesystem_still_binds_a_session_after_a_reboot() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[], &session_mounts(b"session-1")), 0);
    let mut made = 0u32;
    loop {
        let name = format!("/home/operator/{made:012}");
        let handle = h.open(1, 2 | 16, name.as_bytes());
        if handle < 0 {
            assert_eq!(handle, -28, "no space, by name");
            break;
        }
        assert_eq!(h.status(1, Frame::request(op::CLOSE).u64(handle as u64).finish()), 0);
        made += 1;
    }
    assert!(made > 0);
    // Full: not even a directory of its own (a name longer than the slack
    // a few deleted records leave: three 52-byte records and the rest).
    let probe = [&b"/home/operator/"[..], &[b'd'; 200][..]].concat();
    assert_eq!(h.path_op(1, op::MKDIR, &probe), -28);
    // The machine resets with the session bound; the next boot sweeps and
    // then serves. Several sessions in a row bind, through more than one
    // scratch name.
    let mut h = Harness::new(&disk);
    h.server.sweep_scratch().unwrap();
    for id in 1..=3u32 {
        let name = format!("session-{id}");
        assert_eq!(h.bind(1, &[], &session_mounts(name.as_bytes())), 0, "session {id}");
        // Still full for ordinary creation...
        assert_eq!(h.path_op(1, op::MKDIR, &probe), -28);
        // ...but the session can delete, which is how the operator recovers.
        let victim = format!("/home/operator/{:012}", id - 1);
        assert_eq!(h.path_op(1, op::UNLINK, victim.as_bytes()), 0);
        assert_eq!(h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()), 0);
    }
}

/// First publication after an upgrade is diagnostic: a full disk must
/// still let the operator bind and delete, then allow publication again.
#[test]
fn missing_recovery_projection_on_a_full_disk_does_not_prevent_session_repair() {
    let disk = image();
    let mut h = Harness::new(&disk);
    h.server.fs.mkdir(b"/var").unwrap();
    h.server.fs.mkdir(b"/var/log").unwrap();
    crate::recovery::charge(&mut h.server.fs, b"00000000000000000000000000000001").unwrap();
    assert_eq!(h.bind(1, &[], &session_mounts(b"session-fill")), 0);
    let handle = h.server.fs.open(b"/home/operator/filler", OpenFlags {
        write: true, create: true, create_new: true, ..OpenFlags::default()
    }).unwrap();
    let mut offset = 0;
    loop {
        match h.server.fs.write_at(handle, offset, &[0xa5; 4096]) {
            Ok(n) => offset += n as u64,
            Err(Error::NoSpace) => break,
            Err(error) => panic!("{error:?}"),
        }
    }
    h.server.fs.close(handle).unwrap();
    h.server.fs.sync().unwrap();
    assert_eq!(h.server.fs.free_blocks(), 0);
    drop(h);
    let mut h = Harness::new(&disk);
    h.server.sweep_scratch().unwrap();
    let (ledger, _) = crate::recovery::charge(&mut h.server.fs, b"00000000000000000000000000000002").unwrap();
    assert_eq!(crate::recovery::publish_projection(&mut h.server.fs, &ledger), Err(Error::NoSpace));
    assert_eq!(h.server.fs.stat(crate::recovery::PROJECTION.as_bytes()), Err(Error::NotFound));
    assert_eq!(h.bind(1, &[], &session_mounts(b"session-repair")), 0);
    assert_eq!(h.read_all(1, b"/bin/ls").unwrap(), b"ELF ls");
    assert_eq!(h.path_op(1, op::UNLINK, b"/home/operator/filler"), 0);
    assert!(h.server.fs.free_blocks() > 0);
    crate::recovery::publish_projection(&mut h.server.fs, &ledger).unwrap();
    let path = crate::recovery::PROJECTION.as_bytes();
    let handle = h.server.fs.open(path, OpenFlags { read: true, ..OpenFlags::default() }).unwrap();
    let mut bytes = [0; crate::recovery::LEDGER_BYTES];
    assert_eq!(h.server.fs.read_at(handle, 0, &mut bytes).unwrap(), bytes.len());
    h.server.fs.close(handle).unwrap();
    assert_eq!(crate::recovery::parse_ledger(&bytes), Some(ledger));
}

/// Heap attribution from the repair's 300-cycle churn (kernel
/// docs/architecture-audit-20261002/REPAIR.md): a channel's receive buffer
/// doubled from 64 KiB to 128 KiB the first time it carried a frame over
/// 64 KiB, one 33-page step per channel, as late as the channel's first
/// such frame. The inbox now grows to exactly what the head's header
/// announces and lets the buffer go once it is empty.
#[test]
fn an_inbox_holds_at_most_one_largest_frame_and_lets_the_buffer_go() {
    let frame = Frame::request(op::WRITE_AT).u64(1).u64(0).bytes(&[7u8; proto::MAX_IO]).finish_seq(1);
    assert!(frame.len() > 64 * 1024);
    let mut inbox = Inbox::new();
    for chunk in frame.chunks(256) {
        inbox.push(chunk);
        assert!(inbox.capacity() <= proto::MAX_FRAME, "capacity {}", inbox.capacity());
    }
    assert_eq!(inbox.capacity(), frame.len());
    assert!(matches!(inbox.take(), Taken::Frame { seq: 1, .. }));
    assert!(inbox.is_empty());
    assert!(inbox.capacity() < 4096, "the buffer is released once empty: {}", inbox.capacity());
    // Two frames in one read: the second stays buffered, within one frame.
    let small = Frame::request(op::STAT).bytes(b"/x").finish_seq(2);
    let mut both = frame.clone();
    both.extend_from_slice(&small);
    inbox.push(&both);
    assert!(matches!(inbox.take(), Taken::Frame { seq: 1, .. }));
    assert!(inbox.capacity() <= both.len());
    assert!(matches!(inbox.take(), Taken::Frame { seq: 2, .. }));
    assert!(inbox.capacity() < 4096);
}

/// The same attribution, second source: a 64 KiB `read_at` reply built by
/// doubling reached a 128 KiB buffer, and the loop kept each channel's
/// last reply until the next replaced it. Frames now reserve exactly what
/// they append (the loop releases a sent reply; `ssh/src/fsd_server.rs`).
#[test]
fn a_frame_reserves_exactly_what_it_carries() {
    let reply = Frame::reply(proto::MAX_IO as i64).bytes(&[9u8; proto::MAX_IO]).finish_seq(3);
    assert_eq!(reply.capacity(), reply.len(), "no doubling: {} for {}", reply.capacity(), reply.len());
    let request = Frame::request(op::WRITE_AT).u64(1).u64(0).bytes(&[9u8; proto::MAX_IO]).finish_seq(3);
    assert_eq!(request.capacity(), request.len());
    assert!(proto::verify(&reply) && proto::verify(&request));
}

// -- release identity (docs/RELEASE.md sections 2 and 3) ----------------------

fn mkdirs(fs: &mut Fs<Disk>, path: &[u8]) {
    let mut at = Vec::new();
    for part in path.split(|b| *b == b'/').filter(|p| !p.is_empty()) {
        at.push(b'/');
        at.extend_from_slice(part);
        if fs.stat(&at).is_err() {
            fs.mkdir(&at).unwrap();
        }
    }
}

/// The release layout: the commands and the manual only under
/// `/releases/<id>/`, the selection, and site state outside it.
fn release_image(id: &[u8], record: Option<&[u8]>, selected: Option<&[u8]>) -> Disk {
    let disk = Disk(Rc::new(RefCell::new(BTreeMap::new())));
    absd_fs::format(&mut disk.clone(), 7).unwrap();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    let mut tree = b"/releases/".to_vec();
    tree.extend_from_slice(id);
    for dir in [&b"/etc"[..], b"/ssh", b"/home", b"/absd"] {
        fs.mkdir(dir).unwrap();
    }
    for below in [&b"/bin"[..], b"/share/man/man1"] {
        let mut path = tree.clone();
        path.extend_from_slice(below);
        mkdirs(&mut fs, &path);
    }
    let file = |below: &[u8]| {
        let mut path = tree.clone();
        path.extend_from_slice(below);
        path
    };
    put(&mut fs, &file(b"/bin/ls"), b"ELF release ls");
    put(&mut fs, &file(b"/share/man/man1/ls.1"), b".Dd ls");
    put(&mut fs, b"/etc/motd", b"hello\n");
    put(&mut fs, b"/ssh/host_ed25519_seed", SEED);
    if let Some(record) = record {
        put(&mut fs, &file(b"/release"), record);
    }
    if let Some(selected) = selected {
        put(&mut fs, b"/absd/selected", selected);
    }
    fs.sync().unwrap();
    disk
}

fn mine() -> absd_release::Record {
    absd_release::compiled()
}

fn select(disk: &Disk) -> Result<Vec<u8>, absd_release::Refusal> {
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    crate::release::select(&mut fs, &mine())
}

#[test]
fn the_release_record_check_names_each_reason() {
    use absd_release::Refusal;
    let id = mine().release;
    let mut selected = id.clone();
    selected.push(b'\n');
    let good = absd_release::encode(&mine());
    assert_eq!(select(&release_image(&id, Some(&good), Some(&selected))), Ok(id.clone()));
    // Without the trailing newline too.
    assert_eq!(select(&release_image(&id, Some(&good), Some(&id))), Ok(id.clone()));
    assert_eq!(
        select(&release_image(&id, Some(&good), None)),
        Err(Refusal::NoSelectedRelease)
    );
    for bad in [&b""[..], b"Dev\n", b"a\n\n", b"../etc\n", b"a b\n"] {
        assert_eq!(
            select(&release_image(&id, Some(&good), Some(bad))),
            Err(Refusal::MalformedSelected),
            "{bad:?}"
        );
    }
    // The selection names a release whose record is not on the disk.
    assert_eq!(
        select(&release_image(&id, Some(&good), Some(b"other\n"))),
        Err(Refusal::NoReleaseTree)
    );
    assert_eq!(
        select(&release_image(&id, None, Some(&selected))),
        Err(Refusal::NoReleaseTree)
    );
    let mut truncated = good.clone();
    truncated.pop();
    assert_eq!(
        select(&release_image(&id, Some(&truncated), Some(&selected))),
        Err(Refusal::MalformedRecord)
    );
    let mut damaged = good.clone();
    let at = damaged.iter().position(|b| *b == b'=').unwrap() + 1;
    damaged[at] = if damaged[at] == b'x' { b'y' } else { b'x' };
    assert_eq!(
        select(&release_image(&id, Some(&damaged), Some(&selected))),
        Err(Refusal::CheckMismatch)
    );
    // An oversized record is malformed, not read without bound.
    let mut huge = good.clone();
    huge.extend_from_slice(&[b'#'; 8192]);
    assert_eq!(
        select(&release_image(&id, Some(&huge), Some(&selected))),
        Err(Refusal::MalformedRecord)
    );
    let fields: [(fn(&mut absd_release::Record), Refusal); 5] = [
        (|r| r.release = b"other".to_vec(), Refusal::ReleaseMismatch),
        (|r| r.kernel_abi += 1, Refusal::KernelAbiMismatch),
        (|r| r.fsd_protocol += 1, Refusal::FsdProtocolMismatch),
        (|r| r.fs_format -= 1, Refusal::FsFormatMismatch),
        (|r| r.app_abi += 1, Refusal::AppAbiMismatch),
    ];
    for (change, refusal) in fields {
        let mut theirs = mine();
        change(&mut theirs);
        // The tree is where the selection says, whatever the record claims.
        let record = absd_release::encode(&theirs);
        assert_eq!(
            select(&release_image(&id, Some(&record), Some(&selected))),
            Err(refusal)
        );
    }
}

fn bound_harness(disk: &Disk) -> Harness {
    let mut h = Harness::new(disk);
    let id = select(disk).unwrap();
    assert!(h.server.bind_release(&id));
    // Once per boot: a second binding is refused and changes nothing.
    assert!(!h.server.bind_release(b"other"));
    h
}

#[test]
fn bin_and_share_are_served_from_the_selected_release_and_releases_is_unreachable() {
    let id = mine().release;
    let mut selected = id.clone();
    selected.push(b'\n');
    let disk = release_image(&id, Some(&absd_release::encode(&mine())), Some(&selected));
    let mut h = bound_harness(&disk);
    // The control channel (sshd: /ssh and /bin read-only).
    assert_eq!(h.read_all(CONTROL, b"/bin/ls").unwrap(), b"ELF release ls");
    assert_eq!(h.names(CONTROL, b"/").unwrap(), names(&[b"bin", b"ssh"]));
    assert_eq!(h.names(CONTROL, b"/bin").unwrap(), names(&[b"ls"]));
    let mut mounts = session_mounts(b"s1");
    mounts.push(Mount::new(b"/share", false));
    assert_eq!(h.bind(1, &[], &mounts), 0);
    assert_eq!(h.read_all(1, b"/bin/ls").unwrap(), b"ELF release ls");
    assert_eq!(h.read_all(1, b"/share/man/man1/ls.1").unwrap(), b".Dd ls");
    assert_eq!(
        h.names(1, b"/").unwrap(),
        names(&[b"bin", b"etc", b"home", b"share", b"tmp"])
    );
    assert_eq!(h.path_op(1, op::STAT, b"/bin/ls"), 0);
    let (code, path) = h.call(1, Frame::request(op::CANONICAL).bytes(b"/bin/../bin/ls").finish());
    assert_eq!((code, path.as_slice()), (7, &b"/bin/ls"[..]));
    // The tree itself, by any spelling, on any channel.
    let mut tree = b"/releases/".to_vec();
    tree.extend_from_slice(&id);
    let mut tree_ls = tree.clone();
    tree_ls.extend_from_slice(b"/bin/ls");
    for channel in [CONTROL, 1] {
        for path in [
            &b"/releases"[..],
            &tree,
            &tree_ls,
            b"/home/operator/../../releases",
            b"/bin/../releases",
        ] {
            assert_eq!(h.open(channel, 1, path), status::NOT_FOUND, "{path:?}");
            assert_eq!(h.path_op(channel, op::STAT, path), status::NOT_FOUND);
            assert_eq!(h.names(channel, path), Err(status::NOT_FOUND));
            assert_eq!(
                h.status(channel, Frame::request(op::CANONICAL).bytes(path).finish()),
                status::NOT_FOUND
            );
        }
    }
    // Read-only, and nothing writes through a binding into /releases.
    assert_eq!(h.open(1, 2 | 8, b"/bin/new"), status::READ_ONLY);
    assert_eq!(h.path_op(1, op::UNLINK, b"/bin/ls"), status::READ_ONLY);
    assert_eq!(
        h.rename(1, b"/home/operator/x", b"/releases/x", false),
        status::NOT_FOUND
    );
    // No binding may name the tree, and no child narrows into it.
    for mounts in [
        vec![Mount::new(b"/releases", false)],
        vec![Mount::new(&tree, true)],
        vec![Mount::new(b"/releases/x/bin", false)],
    ] {
        assert_eq!(h.bind(2, &[], &mounts), status::INVALID);
    }
    assert_eq!(h.bind(3, &[4], &session_mounts(b"s3")), 0);
    let derive = Frame::request(op::DERIVE)
        .u8(1)
        .u8(derive::LIST)
        .mounts(&[Mount::new(&tree, false)])
        .finish();
    assert_eq!(h.status(3, derive), status::INVALID);
    // What the session writes lands in site state, outside the tree.
    assert_eq!(h.write_file(1, b"/home/operator/note", b"kept"), 0);
    let fs = Fs::mount(disk.clone(), false).unwrap();
    assert!(fs.stat(b"/home/operator/note").is_ok());
    assert!(fs.stat(b"/bin").is_err() && fs.stat(b"/share").is_err());
}

#[test]
fn the_selection_is_neither_visible_nor_writable_on_any_channel() {
    let id = mine().release;
    let mut selected = id.clone();
    selected.push(b'\n');
    let disk = release_image(&id, Some(&absd_release::encode(&mine())), Some(&selected));
    let mut h = bound_harness(&disk);
    let mut mounts = session_mounts(b"s1");
    mounts.push(Mount::new(b"/share", false));
    assert_eq!(h.bind(1, &[], &mounts), 0);
    for channel in [CONTROL, 1] {
        for path in [
            &b"/absd"[..],
            b"/absd/selected",
            b"/home/operator/../../absd/selected",
            b"/bin/../absd",
        ] {
            assert_eq!(h.open(channel, 1, path), status::NOT_FOUND, "{path:?}");
            assert_eq!(h.path_op(channel, op::STAT, path), status::NOT_FOUND);
            assert_eq!(h.names(channel, path), Err(status::NOT_FOUND));
            assert_eq!(
                h.status(channel, Frame::request(op::CANONICAL).bytes(path).finish()),
                status::NOT_FOUND
            );
        }
        let root = h.names(channel, b"/").unwrap();
        assert!(!root.iter().any(|name| name.as_slice() == b"absd"), "{root:?}");
    }
    // No write reaches it: not by creating, unlinking, or renaming onto it.
    assert_eq!(h.open(1, 2 | 8, b"/absd/selected"), status::NOT_FOUND);
    assert_eq!(h.path_op(1, op::UNLINK, b"/absd/selected"), status::NOT_FOUND);
    assert_eq!(h.write_file(1, b"/home/operator/sel", b"other\n"), 0);
    assert_eq!(
        h.rename(1, b"/home/operator/sel", b"/absd/selected", false),
        status::NOT_FOUND
    );
    // No binding or derived child may name it.
    for mounts in [
        vec![Mount::new(b"/absd", true)],
        vec![Mount::new(b"/absd", false)],
        vec![Mount::new(b"/absd/x", true)],
    ] {
        assert_eq!(h.bind(2, &[], &mounts), status::INVALID);
    }
    assert_eq!(h.bind(3, &[4], &session_mounts(b"s3")), 0);
    let derive = Frame::request(op::DERIVE)
        .u8(1)
        .u8(derive::LIST)
        .mounts(&[Mount::new(b"/absd", false)])
        .finish();
    assert_eq!(h.status(3, derive), status::INVALID);
    // The selection on the disk is untouched.
    let mut fs = Fs::mount(disk.clone(), false).unwrap();
    let handle = fs
        .open(b"/absd/selected", OpenFlags { read: true, write: false, create: false, create_new: false, truncate: false })
        .unwrap();
    let mut bytes = vec![0u8; 64];
    let count = fs.read_at(handle, 0, &mut bytes).unwrap();
    assert_eq!(&bytes[..count], &selected[..]);
}

#[test]
fn without_a_bound_release_paths_are_as_stored_and_releases_is_still_hidden() {
    let disk = image();
    let mut fs = Fs::mount(disk.clone(), true).unwrap();
    mkdirs(&mut fs, b"/releases/x/bin");
    put(&mut fs, b"/releases/x/bin/ls", b"hidden");
    fs.sync().unwrap();
    let mut h = Harness::new(&disk);
    assert_eq!(h.read_all(CONTROL, b"/bin/ls").unwrap(), b"ELF ls");
    assert_eq!(h.open(CONTROL, 1, b"/releases/x/bin/ls"), status::NOT_FOUND);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    assert_eq!(
        h.names(1, b"/").unwrap(),
        names(&[b"bin", b"etc", b"home", b"tmp"])
    );
}

#[test]
fn version_answers_on_every_channel_with_the_compiled_identity() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.bind(1, &[2], &session_mounts(b"s1")), 0);
    // Control, a bound session, its unbound spare, a never-bound slot.
    for channel in [CONTROL, 1, 2, 5] {
        let (code, payload) = h.call(channel, Frame::request(op::VERSION).finish());
        assert_eq!(code, 0, "channel {channel}");
        let mut expected = Vec::new();
        expected.extend_from_slice(&absd_release::FSD_PROTOCOL.to_le_bytes());
        expected.extend_from_slice(&absd_release::FS_FORMAT.to_le_bytes());
        expected.extend_from_slice(&(absd_release::RELEASE_ID.len() as u16).to_le_bytes());
        expected.extend_from_slice(absd_release::RELEASE_ID.as_bytes());
        assert_eq!(payload, expected);
        let version = crate::version::decode(&payload).unwrap();
        assert_eq!(
            (version.fsd_protocol, version.fs_format, version.release.as_slice()),
            (2, 2, absd_release::RELEASE_ID.as_bytes())
        );
    }
    // A request with fields after the op is not a VERSION request.
    assert_eq!(
        h.status(1, Frame::request(op::VERSION).u8(0).finish()),
        status::INVALID
    );
    // The protocol generation is the frame magic's digit.
    assert_eq!(proto::MAGIC[3], b'0' + absd_release::FSD_PROTOCOL as u8);
}

#[test]
fn the_client_check_refuses_every_wrong_answer_with_one_line() {
    use crate::version::{Refusal, check};
    let answer = |protocol: u32, release: &[u8]| {
        let mut payload = Vec::new();
        payload.extend_from_slice(&protocol.to_le_bytes());
        payload.extend_from_slice(&absd_release::FS_FORMAT.to_le_bytes());
        payload.extend_from_slice(&(release.len() as u16).to_le_bytes());
        payload.extend_from_slice(release);
        Ok((0i64, payload))
    };
    let me = absd_release::RELEASE_ID.as_bytes();
    assert!(check(answer(2, me), false).is_ok());
    assert!(check(answer(2, me), true).is_ok());
    // A client that does not ask for the release ignores it; sshd does.
    assert!(check(answer(2, b"other"), false).is_ok());
    let cases: [(Result<(i64, Vec<u8>), i64>, bool, Refusal, &str); 7] = [
        (answer(3, me), false, Refusal::Protocol { server: 3 }, "FSD PROTOCOL REFUSED server=3 required=2"),
        (Err(-110), false, Refusal::NoAnswer, "FSD PROTOCOL REFUSED reason=no_answer"),
        (Err(-5), false, Refusal::NoServer(-5), "FSD PROTOCOL REFUSED reason=no_server status=-5"),
        (Ok((-95, Vec::new())), false, Refusal::Refused(-95), "FSD PROTOCOL REFUSED reason=refused status=-95"),
        (Ok((0, vec![2, 0, 0])), false, Refusal::Malformed, "FSD PROTOCOL REFUSED reason=malformed_answer"),
        (answer(2, b"Bad Id"), false, Refusal::Malformed, "FSD PROTOCOL REFUSED reason=malformed_answer"),
        (
            answer(2, b"other"),
            true,
            Refusal::Release { server: b"other".to_vec() },
            "",
        ),
    ];
    for (given, require_release, refusal, line) in cases {
        let refused = check(given, require_release).unwrap_err();
        assert_eq!(refused, refusal);
        if !line.is_empty() {
            assert_eq!(refused.line(), line);
        }
    }
    assert_eq!(
        Refusal::Release { server: b"other".to_vec() }.line(),
        format!("FSD PROTOCOL REFUSED server_release=other required_release={}", absd_release::RELEASE_ID)
    );
}

#[test]
fn an_unsupported_format_has_its_own_errno() {
    use crate::server::errno;
    assert_eq!(errno(Error::UnsupportedFormat), status::UNSUPPORTED);
    let others = [
        Error::NotFound, Error::Exists, Error::NotDir, Error::IsDir, Error::NotEmpty,
        Error::NoSpace, Error::ReadOnlyFs, Error::Denied, Error::Invalid, Error::WouldBlock,
        Error::BadHandle, Error::Device(-1), Error::Device(-5), Error::Poisoned,
        Error::Unformatted, Error::NotBlank, Error::Corrupt("x"),
    ];
    for other in others {
        assert_ne!(errno(other), status::UNSUPPORTED, "{other:?}");
    }
}

fn mtime_of(payload: &[u8]) -> u64 {
    assert_eq!(payload.len(), proto::ATTR_BYTES);
    u64::from_le_bytes(payload[40..48].try_into().unwrap())
}

#[test]
fn stat_carries_mtime_from_the_server_clock() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(proto::ATTR_BYTES, 48);
    assert_eq!(h.bind(1, &[], &session_mounts(b"s1")), 0);
    let (code, payload) = h.call(1, Frame::request(op::STAT).bytes(b"/etc/motd").finish());
    assert_eq!(code, 0);
    assert_eq!(mtime_of(&payload), 0, "the image was written without a clock");
    h.server.clock(5000, || Some(1_800_000_000));
    assert_eq!(h.write_file(1, b"/home/operator/f", b"one"), 0);
    let (_, payload) = h.call(1, Frame::request(op::STAT).bytes(b"/home/operator/f").finish());
    assert_eq!(mtime_of(&payload), 1_800_000_000);
    let handle = h.open(1, 1, b"/home/operator/f");
    let (_, payload) = h.call(1, Frame::request(op::FSTAT).u64(handle as u64).finish());
    assert_eq!(mtime_of(&payload), 1_800_000_000);
    let (count, payload) = h.call(1, Frame::request(op::READ_DIR).bytes(b"/home/operator").finish());
    assert_eq!(count, 1);
    assert_eq!(mtime_of(&payload[2 + 1..]), 1_800_000_000);
}

#[test]
fn the_server_clock_reads_the_wall_clock_at_most_every_bound() {
    let disk = image();
    let mut h = Harness::new(&disk);
    let reads = Cell::new(0);
    let read = |value: Option<u64>| {
        let reads = &reads;
        move || {
            reads.set(reads.get() + 1);
            value
        }
    };
    h.server.clock(1000, read(Some(100)));
    h.server.clock(1000 + crate::server::CLOCK_TICKS - 1, read(Some(999)));
    assert_eq!(reads.get(), 1, "a recent reading is reused");
    h.server.fs.mkdir(b"/a").unwrap();
    assert_eq!(h.server.fs.stat(b"/a").unwrap().mtime, 100);
    h.server.clock(1000 + crate::server::CLOCK_TICKS, read(None));
    assert_eq!(reads.get(), 2);
    h.server.fs.mkdir(b"/b").unwrap();
    assert_eq!(h.server.fs.stat(b"/b").unwrap().mtime, 0, "a refused reading is unknown");
    // Ticks that go backwards (a new boot's server) read again.
    h.server.clock(10, read(Some(200)));
    assert_eq!(reads.get(), 3);
}

#[test]
fn an_mtime_shows_as_a_minute_or_unknown() {
    use crate::civil::mtime_column;
    assert_eq!(mtime_column(0), "-", "0 is unknown, not 1970");
    assert_eq!(mtime_column(1), "1970-01-01 00:00");
    assert_eq!(mtime_column(1_790_487_252), "2026-09-27 05:34");
    assert_eq!(mtime_column(951_782_399), "2000-02-28 23:59");
}

/// A released channel leaves draining exactly once, counted, whichever way
/// it leaves: the loop seeing it quiet (`settle`) or a BIND taking it over
/// while it is already quiet. Found under KVM: the churn column's 300 shell
/// sessions settled 899 of 900 channels because a BIND for the next session
/// cleared a quiet spare's draining flag before the loop's quiet read.
#[test]
fn a_bind_that_takes_over_a_quiet_draining_channel_counts_its_settlement() {
    let disk = image();
    let mut h = Harness::new(&disk);
    assert_eq!(h.server.settled(), 0);
    // A shell session: its slot and two spares.
    assert_eq!(h.bind(1, &[2, 3], &session_mounts(b"first")), 0);
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        0
    );
    assert!(h.server.draining(1) && h.server.draining(2) && h.server.draining(3));
    // The loop sees the slot quiet and settles it.
    assert!(h.server.settle(1, quiet(1)));
    assert_eq!(h.server.settled(), 1);
    // The next session's BIND arrives before the loop reaches the spares,
    // which are already quiet: the bind succeeds and takes them over.
    assert_eq!(h.bind(1, &[2, 3], &session_mounts(b"second")), 0);
    assert!(!h.server.draining(2) && !h.server.draining(3));
    // Every channel the first session released is counted once.
    assert_eq!(h.server.settled(), 3);
    // A settle after the takeover finds nothing to settle and counts nothing.
    assert!(!h.server.settle(2, quiet(2)));
    assert_eq!(h.server.settled(), 3);
    // Releasing the second session and settling each channel counts three more.
    assert_eq!(
        h.status(CONTROL, Frame::request(op::RELEASE).u8(1).finish()),
        0
    );
    for channel in [1, 2, 3] {
        assert!(h.server.settle(channel, quiet(channel)));
    }
    assert_eq!(h.server.settled(), 6);
}

/// N6: on the server route `canonical` answers -22 only for a component over
/// `MAX_NAME` (255) bytes or a path over `MAX_PATH` (4096) bytes (as for an
/// empty path or a NUL, which `realpath` never sends); dot components are
/// normalized, not refused. The runtime adds -22 for a result over the
/// caller's capacity (storage.rs, not reachable on the host).
#[test]
fn canonical_refuses_invalid_only_for_long_names_and_long_paths() {
    let disk = image();
    let mut h = Harness::new(&disk);
    let mut canonical =
        |path: &[u8]| h.call(CONTROL, Frame::request(op::CANONICAL).bytes(path).finish());
    let mut name = b"/bin/".to_vec();
    name.extend(core::iter::repeat_n(b'a', 256));
    assert_eq!(canonical(&name).0, status::INVALID);
    name.pop();
    assert_eq!(canonical(&name).0, status::NOT_FOUND, "255 bytes is a valid name");
    let mut deep = b"/bin".to_vec();
    while deep.len() <= proto::MAX_PATH {
        deep.push(b'/');
        deep.extend(core::iter::repeat_n(b'b', 200));
    }
    assert_eq!(canonical(&deep).0, status::INVALID);
    assert_eq!(canonical(b"").0, status::INVALID);
    assert_eq!(canonical(b"/bin/./../bin//ls"), (7, b"/bin/ls".to_vec()));
}

#[test]
fn health_reads_this_boots_recovery_line_and_nothing_else() {
    use crate::log::{Generation, Unknown, generation, line};
    let a = "aa".repeat(16);
    let b = "bb".repeat(16);
    let log = |lines: &[(&str, &str)]| -> Vec<u8> {
        lines.iter().flat_map(|(program, text)| line(Some(1_792_052_576), program, text)).collect()
    };
    let boot_a = log(&[
        ("fsd", &format!("started: boot {a}, uptime 412 ms")),
        ("fsd", "FSD HOST KEY ed25519 path=/ssh/host_ed25519_seed"),
        ("fsd", "FSD RECOVERY seq=7 streak=0 previous=ended"),
        ("fsd", "FSD READY channels=11 slots=10 fs_seq=90 formatted=false fs_objects=84"),
    ]);
    let boot_b = log(&[
        ("fsd", &format!("started: boot {b}, uptime 405 ms")),
        ("fsd", "FSD RECOVERY seq=8 streak=1 previous=failed"),
    ]);
    let both: Vec<u8> = [boot_a.clone(), boot_b.clone()].concat();
    // This boot's line, never the other boot's.
    assert_eq!(generation(b"", &both, &b), Ok(Generation { seq: 8, streak: 1, previous: "failed" }));
    assert_eq!(generation(b"", &both, &a), Ok(Generation { seq: 7, streak: 0, previous: "ended" }));
    // Rotated between the start and the recovery line: still found.
    let (head, tail) = boot_b.split_at(boot_b.iter().position(|&c| c == b'\n').unwrap() + 1);
    assert_eq!(generation(head, tail, &b), Ok(Generation { seq: 8, streak: 1, previous: "failed" }));
    // Rotated out entirely, or never written.
    assert_eq!(generation(b"", &boot_a, &b), Err(Unknown::NoBootLine));
    assert_eq!(generation(b"", b"", &b), Err(Unknown::NoBootLine));
    // Started, but the recovery line was dropped; a later start does not lend its line.
    let dropped = log(&[("fsd", &format!("started: boot {b}, uptime 1 ms")), ("fsd", "log: 1 lines dropped")]);
    assert_eq!(generation(b"", &dropped, &b), Err(Unknown::NoRecoveryLine));
    let restarted = [dropped.clone(), log(&[("fsd", &format!("started: boot {b}, uptime 9 ms")),
                                            ("fsd", "FSD RECOVERY seq=9 streak=0 previous=none")])].concat();
    assert_eq!(generation(b"", &restarted, &b), Err(Unknown::NoRecoveryLine));
    // Malformed recovery lines are refused, not read.
    for bad in ["seq=8 streak=1 previous=maybe", "seq=8 streak=x previous=failed", "seq=8 streak=1",
                "seq=8 streak=1 previous=failed extra", "streak=1 seq=8 previous=failed", "seq= streak=1 previous=none"] {
        let text = log(&[("fsd", &format!("started: boot {b}, uptime 1 ms")), ("fsd", &format!("FSD RECOVERY {bad}"))]);
        assert_eq!(generation(b"", &text, &b), Err(Unknown::Malformed), "{bad}");
    }
    // Another program's lines and an unstamped line are not the file server's.
    let foreign = log(&[("sshd", &format!("started: boot {b}, uptime 1 ms")), ("sshd", "FSD RECOVERY seq=1 streak=0 previous=none")]);
    assert_eq!(generation(b"", &foreign, &b), Err(Unknown::NoBootLine));
    assert_eq!(generation(b"", format!("started: boot {b}, x\n").as_bytes(), &b), Err(Unknown::NoBootLine));
}
