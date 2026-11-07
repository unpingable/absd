use super::serve;
use std::io::{self, Read, Write};
use std::path::Path;

struct Fragments<'a>(&'a [u8]);
impl Read for Fragments<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = out.len().min(self.0.len()).min(1);
        out[..count].copy_from_slice(&self.0[..count]);
        self.0 = &self.0[count..];
        Ok(count)
    }
}
struct ShortWrites(Vec<u8>);
impl Write for ShortWrites {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(2);
        self.0.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn fragmented_init_and_short_writes_return_wire_version_three() {
    // Hand-derived SFTP INIT/version3, independent of the production codec.
    let input = [0, 0, 0, 5, 1, 0, 0, 0, 3];
    let mut output = ShortWrites(Vec::new());
    serve(&mut Fragments(&input), &mut output, Path::new("/")).unwrap();
    assert_eq!(output.0, [0, 0, 0, 5, 2, 0, 0, 0, 3]);
}

#[test]
fn wire_fields_append_to_existing_response_bytes() {
    let mut output = vec![103];
    super::wire::encode(&mut output, &0x0102_0304u32);
    super::wire::string(&mut output, &[0, 255]);
    assert_eq!(output, [103, 1, 2, 3, 4, 0, 0, 0, 2, 0, 255]);
}

use std::fs;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Client {
    socket: UnixStream,
    thread: Option<JoinHandle<io::Result<()>>>,
    home: PathBuf,
}
fn u32_field(out: &mut Vec<u8>, x: u32) {
    out.extend_from_slice(&x.to_be_bytes());
}
fn u64_field(out: &mut Vec<u8>, x: u64) {
    out.extend_from_slice(&x.to_be_bytes());
}
fn string(out: &mut Vec<u8>, x: &[u8]) {
    u32_field(out, x.len() as u32);
    out.extend_from_slice(x);
}
fn number(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes[..4].try_into().unwrap())
}
fn string_result(body: &[u8]) -> Vec<u8> {
    let size = number(&body[5..]) as usize;
    assert_eq!(body.len(), 9 + size);
    body[9..].to_vec()
}
fn status(body: &[u8], id: u32, code: u32) {
    assert_eq!(body[0], 101, "{body:?}");
    assert_eq!(number(&body[1..]), id);
    assert_eq!(number(&body[5..]), code, "{body:?}");
}
impl Client {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!(
            "absd-sftp-test-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&home).unwrap();
        let (socket, mut server) = UnixStream::pair().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut output = server.try_clone().unwrap();
        let root = home.clone();
        let thread = thread::spawn(move || serve(&mut server, &mut output, &root));
        let mut client = Self {
            socket,
            thread: Some(thread),
            home,
        };
        assert_eq!(client.exchange(&[1, 0, 0, 0, 3]), [2, 0, 0, 0, 3]);
        client
    }
    fn exchange(&mut self, body: &[u8]) -> Vec<u8> {
        self.socket
            .write_all(&(body.len() as u32).to_be_bytes())
            .unwrap();
        self.socket.write_all(body).unwrap();
        let mut header = [0; 4];
        self.socket
            .read_exact(&mut header)
            .expect("server reply header");
        let size = number(&header) as usize;
        assert!(size <= 256 * 1024);
        let mut response = vec![0; size];
        self.socket.read_exact(&mut response).unwrap();
        response
    }
    fn request(&mut self, kind: u8, id: u32, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![kind];
        u32_field(&mut body, id);
        body.extend_from_slice(payload);
        self.exchange(&body)
    }
    fn path_request(&mut self, kind: u8, id: u32, path: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        string(&mut payload, path);
        self.request(kind, id, &payload)
    }
    fn open(&mut self, path: &[u8], flags: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        string(&mut payload, path);
        u32_field(&mut payload, flags);
        u32_field(&mut payload, 0);
        let reply = self.request(3, 10, &payload);
        assert_eq!(reply[0], 102, "{reply:?}");
        string_result(&reply)
    }
    fn read(&mut self, handle: &[u8], offset: u64, size: u32) -> Vec<u8> {
        let mut p = Vec::new();
        string(&mut p, handle);
        u64_field(&mut p, offset);
        u32_field(&mut p, size);
        self.request(5, 11, &p)
    }
    fn write(&mut self, handle: &[u8], offset: u64, data: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        string(&mut p, handle);
        u64_field(&mut p, offset);
        string(&mut p, data);
        self.request(6, 12, &p)
    }
    fn handle_request(&mut self, kind: u8, id: u32, handle: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        string(&mut p, handle);
        self.request(kind, id, &p)
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        fs::remove_dir_all(&self.home).unwrap();
    }
}

#[test]
fn unsupported_operation_preserves_request_id_and_session_continues() {
    let mut c = Client::new();
    status(&c.request(222, 47, &[]), 47, 8);
    status(&c.request(200, 48, &[0, 0, 0, 0]), 48, 8);
}
#[test]
fn binary_positional_io_close_and_eof() {
    let mut c = Client::new();
    let h = c.open(b"bytes", 1 | 2 | 8 | 16);
    status(&c.write(&h, 0, b"a\0b\xff"), 12, 0);
    status(&c.write(&h, 1, b"X"), 12, 0);
    let r = c.read(&h, 0, 64);
    assert_eq!(r[0], 103);
    assert_eq!(string_result(&r), b"aXb\xff");
    let r = c.read(&h, 0, 0);
    assert_eq!(r[0], 103);
    assert_eq!(string_result(&r), b"");
    status(&c.read(&h, 4, 2), 11, 1);
    status(&c.handle_request(4, 13, &h), 13, 0);
    assert_eq!(fs::read(c.home.join("bytes")).unwrap(), b"aXb\xff");
}
#[test]
fn ordinary_scp_size_update_truncates_longer_and_empty_destinations() {
    let mut c = Client::new();
    fs::write(c.home.join("x"), b"old trailing bytes").unwrap();
    let h = c.open(b"x", 2 | 8);
    status(&c.write(&h, 0, b"new"), 12, 0);
    let mut p = Vec::new();
    string(&mut p, &h);
    u32_field(&mut p, 1);
    u64_field(&mut p, 3);
    status(&c.request(10, 31, &p), 31, 0);
    status(&c.handle_request(4, 13, &h), 13, 0);
    assert_eq!(fs::read(c.home.join("x")).unwrap(), b"new");
    let h = c.open(b"x", 2 | 8);
    let mut p = Vec::new();
    string(&mut p, &h);
    u32_field(&mut p, 1);
    u64_field(&mut p, 0);
    status(&c.request(10, 32, &p), 32, 0);
    status(&c.handle_request(4, 13, &h), 13, 0);
    assert!(fs::read(c.home.join("x")).unwrap().is_empty());
}
#[test]
fn unsupported_attributes_and_trailing_bytes_do_not_mutate_files() {
    let mut c = Client::new();
    fs::write(c.home.join("x"), b"original").unwrap();
    let h = c.open(b"x", 2);
    let mut p = Vec::new();
    string(&mut p, &h);
    u32_field(&mut p, 1 | 4);
    u64_field(&mut p, 0);
    u32_field(&mut p, 0o600);
    status(&c.request(10, 33, &p), 33, 8);
    assert_eq!(fs::read(c.home.join("x")).unwrap(), b"original");
    let mut p = Vec::new();
    string(&mut p, b"x");
    u32_field(&mut p, 2 | 16);
    u32_field(&mut p, 0);
    p.push(99);
    status(&c.request(3, 34, &p), 34, 5);
    assert_eq!(fs::read(c.home.join("x")).unwrap(), b"original");
    let mut p = Vec::new();
    string(&mut p, b"new");
    u32_field(&mut p, 2 | 8);
    u32_field(&mut p, 0x80000000);
    status(&c.request(3, 35, &p), 35, 5);
    assert!(!c.home.join("new").exists());
}
#[test]
fn stale_and_wrong_kind_handles_are_refused_without_reusing_authority() {
    let mut c = Client::new();
    let old = c.open(b"old", 1 | 2 | 8);
    status(&c.handle_request(4, 13, &old), 13, 0);
    let _new = c.open(b"new", 1 | 2 | 8);
    status(&c.write(&old, 0, b"bad"), 12, 4);
    assert!(fs::read(c.home.join("new")).unwrap().is_empty());
    status(&c.handle_request(4, 13, &old), 13, 4);
    let d = c.path_request(11, 51, b".");
    assert_eq!(d[0], 102);
    let d = string_result(&d);
    status(&c.read(&d, 0, 3), 11, 4);
}
#[test]
fn handle_limit_refuses_more_opens_and_closed_slot_is_available() {
    let mut c = Client::new();
    let mut handles = Vec::new();
    for _ in 0..16 {
        handles.push(c.open(b"x", 1 | 2 | 8));
    }
    let mut p = Vec::new();
    string(&mut p, b"y");
    u32_field(&mut p, 2 | 8);
    u32_field(&mut p, 0);
    status(&c.request(3, 17, &p), 17, 4);
    assert!(!c.home.join("y").exists());
    status(&c.handle_request(4, 13, &handles[0]), 13, 0);
    let _ = c.open(b"y", 2 | 8);
}
#[test]
fn rename_never_replaces_existing_target() {
    let mut c = Client::new();
    fs::write(c.home.join("a"), b"first").unwrap();
    fs::write(c.home.join("b"), b"second").unwrap();
    let mut p = Vec::new();
    string(&mut p, b"a");
    string(&mut p, b"b");
    status(&c.request(18, 60, &p), 60, 4);
    assert_eq!(fs::read(c.home.join("a")).unwrap(), b"first");
    assert_eq!(fs::read(c.home.join("b")).unwrap(), b"second");
    let mut p = Vec::new();
    string(&mut p, b"a");
    string(&mut p, b"c");
    status(&c.request(18, 61, &p), 61, 0);
    assert!(!c.home.join("a").exists());
    assert_eq!(fs::read(c.home.join("c")).unwrap(), b"first");
}
#[test]
fn realpath_resolves_home_and_missing_leaf_but_not_missing_parent() {
    let mut c = Client::new();
    let r = c.path_request(16, 70, b"");
    assert_eq!(r[0], 104);
    assert_eq!(number(&r[5..]), 1);
    let size = number(&r[9..]) as usize;
    assert_eq!(&r[13..13 + size], c.home.to_str().unwrap().as_bytes());
    let r = c.path_request(16, 71, b"new");
    assert_eq!(r[0], 104);
    let size = number(&r[9..]) as usize;
    assert_eq!(
        &r[13..13 + size],
        c.home.join("new").to_str().unwrap().as_bytes()
    );
    status(&c.path_request(16, 72, b"absent/child"), 72, 2);
}
#[test]
fn directory_listing_stat_and_removal_use_real_filesystem() {
    let mut c = Client::new();
    let mut p = Vec::new();
    string(&mut p, b"d");
    u32_field(&mut p, 4);
    u32_field(&mut p, 0o700);
    status(&c.request(14, 80, &p), 80, 0);
    fs::write(c.home.join("d/x"), b"data").unwrap();
    let r = c.path_request(17, 81, b"d/x");
    assert_eq!(r[0], 105);
    let r = c.path_request(11, 82, b"d");
    assert_eq!(r[0], 102);
    let d = string_result(&r);
    let r = c.handle_request(12, 83, &d);
    assert_eq!(r[0], 104);
    assert_eq!(number(&r[5..]), 1);
    assert_eq!(&r[13..14], b"x");
    status(&c.handle_request(12, 84, &d), 84, 1);
    status(&c.handle_request(4, 13, &d), 13, 0);
    status(&c.path_request(15, 85, b"d"), 85, 4);
    status(&c.path_request(13, 86, b"d/x"), 86, 0);
    status(&c.path_request(15, 87, b"d"), 87, 0);
}
#[test]
fn oversized_data_and_offset_overflow_leave_file_unchanged() {
    let mut c = Client::new();
    let h = c.open(b"x", 1 | 2 | 8);
    status(&c.write(&h, 0, &vec![7; 65537]), 12, 5);
    status(&c.write(&h, u64::MAX, b"x"), 12, 4);
    status(&c.write(&h, 67_108_864, b"x"), 12, 4);
    status(&c.write(&h, 67_108_863, b"xx"), 12, 4);
    status(&c.read(&h, 0, 65537), 11, 5);
    assert!(fs::read(c.home.join("x")).unwrap().is_empty());
}

#[test]
fn reads_at_and_beyond_write_limit_report_eof() {
    let mut c = Client::new();
    fs::write(c.home.join("x"), b"small").unwrap();
    let h = c.open(b"x", 1);
    for offset in [67_108_863, 67_108_864, 67_108_865] {
        status(&c.read(&h, offset, 65_536), 11, 1);
    }
}

#[test]
fn read_ahead_across_write_limit_returns_final_bytes_then_eof() {
    use std::io::{Seek, SeekFrom};

    let mut c = Client::new();
    let mut file = fs::File::create(c.home.join("x")).unwrap();
    file.set_len(67_108_864).unwrap();
    file.seek(SeekFrom::Start(67_108_861)).unwrap();
    file.write_all(b"end").unwrap();
    drop(file);
    let h = c.open(b"x", 1);
    let reply = c.read(&h, 67_108_861, 65_536);
    assert_eq!(reply[0], 103, "{reply:?}");
    assert_eq!(string_result(&reply), b"end");
    status(&c.read(&h, 67_108_864, 65_536), 11, 1);
}
#[test]
fn malformed_paths_and_unknown_open_flags_do_not_create_entries() {
    let mut c = Client::new();
    for name in [b"bad\0name".to_vec(), vec![b'x'; 4097], vec![0xff]] {
        let mut p = Vec::new();
        string(&mut p, &name);
        u32_field(&mut p, 2 | 8);
        u32_field(&mut p, 0);
        status(&c.request(3, 90, &p), 90, 5);
    }
    let mut p = Vec::new();
    string(&mut p, b"x");
    u32_field(&mut p, 0x80 | 2 | 8);
    u32_field(&mut p, 0);
    status(&c.request(3, 91, &p), 91, 5);
    assert!(!c.home.join("x").exists());
}
#[test]
fn truncated_and_oversized_framing_fail_closed() {
    for data in [
        vec![0, 0],
        vec![0, 0, 0, 5, 1, 0],
        vec![0, 0, 0, 0],
        vec![0, 4, 0, 1],
    ] {
        assert!(serve(&mut &data[..], &mut Vec::new(), Path::new("/")).is_err());
    }
}

#[test]
fn oversized_frame_reports_recoverable_id_without_reading_its_body() {
    let mut input = vec![0, 0, 0, 5, 1, 0, 0, 0, 3, 0, 4, 0, 1, 5, 0, 0, 0, 55];
    input.extend_from_slice(b"unread oversized body");
    let mut input = io::Cursor::new(input);
    let mut output = Vec::new();
    assert!(serve(&mut input, &mut output, Path::new("/")).is_err());
    assert_eq!(&output[..9], &[0, 0, 0, 5, 2, 0, 0, 0, 3]);
    assert!(
        output.len() > 13,
        "oversized frame must return BAD_MESSAGE before close"
    );
    status(&output[13..], 55, 5);
    assert_eq!(input.position(), 18);
}
#[test]
fn exclusive_create_and_readonly_handle_refusals() {
    let mut c = Client::new();
    fs::write(c.home.join("x"), b"old").unwrap();
    let mut p = Vec::new();
    string(&mut p, b"x");
    u32_field(&mut p, 2 | 8 | 32);
    u32_field(&mut p, 0);
    status(&c.request(3, 95, &p), 95, 4);
    assert_eq!(fs::read(c.home.join("x")).unwrap(), b"old");
    let h = c.open(b"x", 1);
    status(&c.write(&h, 0, b"bad"), 12, 4);
    let mut p = Vec::new();
    string(&mut p, &h);
    u32_field(&mut p, 1);
    u64_field(&mut p, 0);
    status(&c.request(10, 96, &p), 96, 3);
    assert_eq!(fs::read(c.home.join("x")).unwrap(), b"old");
}

#[test]
fn append_is_refused_before_creation_without_an_atomic_append_primitive() {
    let mut c = Client::new();
    let mut p = Vec::new();
    string(&mut p, b"new");
    u32_field(&mut p, 2 | 4 | 8);
    u32_field(&mut p, 0);
    status(&c.request(3, 113, &p), 113, 8);
    assert!(!c.home.join("new").exists());
}
#[test]
fn malformed_close_keeps_the_valid_handle_and_fstat_reports_file_size() {
    let mut c = Client::new();
    let h = c.open(b"x", 1 | 2 | 8);
    status(&c.write(&h, 0, b"abc"), 12, 0);
    let mut p = Vec::new();
    string(&mut p, &h);
    p.push(99);
    status(&c.request(4, 97, &p), 97, 5);
    let r = c.handle_request(8, 98, &h);
    assert_eq!(r[0], 105);
    assert_eq!(number(&r[5..]) & 5, 5);
    assert_eq!(u64::from_be_bytes(r[9..17].try_into().unwrap()), 3);
    assert_eq!(number(&r[17..]) & 0o170000, 0o100000);
    status(&c.handle_request(4, 13, &h), 13, 0);
}
#[test]
fn directory_pages_return_all_entries_before_eof() {
    let mut c = Client::new();
    for n in 0..129 {
        fs::write(c.home.join(format!("entry-{n:03}")), b"").unwrap();
    }
    let r = c.path_request(11, 100, b".");
    assert_eq!(r[0], 102);
    let h = string_result(&r);
    let mut names = std::collections::BTreeSet::new();
    let mut sizes = Vec::new();
    loop {
        let r = c.handle_request(12, 101, &h);
        if r[0] == 101 {
            status(&r, 101, 1);
            break;
        }
        assert_eq!(r[0], 104);
        let count = number(&r[5..]);
        assert!(r.len() <= 65536);
        sizes.push(count);
        let mut at = 9;
        for _ in 0..count {
            let len = number(&r[at..]) as usize;
            at += 4;
            names.insert(String::from_utf8(r[at..at + len].to_vec()).unwrap());
            at += len;
            let len = number(&r[at..]) as usize;
            at += 4 + len;
            let flags = number(&r[at..]);
            assert_eq!(flags, 5);
            at += 4 + 8 + 4;
        }
        assert_eq!(at, r.len());
    }
    assert_eq!(sizes, [64, 64, 1]);
    assert_eq!(names.len(), 129);
    assert!(names.contains("entry-000") && names.contains("entry-128"));
}
#[test]
fn setstat_size_requires_existing_path_and_unsupported_attrs_leave_it_unchanged() {
    let mut c = Client::new();
    fs::write(c.home.join("x"), b"abcdef").unwrap();
    let mut p = Vec::new();
    string(&mut p, b"x");
    u32_field(&mut p, 1 | 8);
    u64_field(&mut p, 0);
    u32_field(&mut p, 0);
    u32_field(&mut p, 0);
    status(&c.request(9, 110, &p), 110, 8);
    assert_eq!(fs::read(c.home.join("x")).unwrap(), b"abcdef");
    let mut p = Vec::new();
    string(&mut p, b"x");
    u32_field(&mut p, 1);
    u64_field(&mut p, 2);
    status(&c.request(9, 111, &p), 111, 0);
    assert_eq!(fs::read(c.home.join("x")).unwrap(), b"ab");
    let mut p = Vec::new();
    string(&mut p, b"absent");
    u32_field(&mut p, 1);
    u64_field(&mut p, 0);
    status(&c.request(9, 112, &p), 112, 2);
}
