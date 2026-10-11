#![feature(restricted_std)]
//! The exclusive-writer tripwire on ABSD (docs/FILESYSTEM.md): two live
//! processes that each mount the filesystem writable. Started by init as
//! the durable worker, the parent holds the read-write block handle and the
//! spawn right; it starts its own image (`/bin/fsx-probe`) with a raw
//! `spawn_image` whose block copy keeps the write right, in the durable
//! worker's four-handle shape, which `Command` never does. The kernel checks
//! only that the parent holds the rights it copies.
//!
//! Sequence: both mount (same sequence); the parent creates and syncs
//! `/parent`; the child, still holding its earlier mount, creates and syncs
//! `/child`; the parent reads `/parent` back and makes one more commit. The
//! host then reads the device with its own reader. An experiment, not a
//! qualification: it reports what happens and exits 0 unless a step fails
//! outright.

use std::io::{Read, Write};

use absd_runtime::process::spawn_image_raw;
use absd_runtime::storage;

const CHILD_STEP: u64 = 77;
const SYS_WAIT: u64 = 6;
const SYS_CLOSE: u64 = 9;
const SYS_CELL_CREATE: u64 = 10;
const SYS_DUPLICATE: u64 = 13;
const SYS_READ: u64 = 15;
const SYS_PIPE_CREATE: u64 = 16;
const SYS_WRITE: u64 = 1;
const RIGHT_WRITE: u64 = 1;
const RIGHT_READ: u64 = 1 << 2;
const COPY_CONSOLE: u64 = 1;

fn sys(number: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let raw: i64;
    unsafe {
        core::arch::asm!(
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

fn ok(raw: i64, what: &str) -> Result<u64, String> {
    if raw < 0 { Err(format!("{what}: {raw}")) } else { Ok(raw as u64) }
}

fn pipe() -> Result<(u64, u64), String> {
    let both = ok(sys(SYS_PIPE_CREATE, 0, 0, 0), "pipe")?;
    let reader = ok(sys(SYS_DUPLICATE, both, RIGHT_READ, 0), "pipe reader")?;
    let writer = ok(sys(SYS_DUPLICATE, both, RIGHT_WRITE, 0), "pipe writer")?;
    sys(SYS_CLOSE, both, 0, 0);
    Ok((reader, writer))
}

/// Echoes the child's output until a line starting with `until` (or EOF
/// when `until` is empty).
fn relay(reader: u64, pending: &mut Vec<u8>, until: &str) -> Result<(), String> {
    loop {
        while let Some(end) = pending.iter().position(|&byte| byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let text = String::from_utf8_lossy(&line);
            print!("  child| {text}");
            if !until.is_empty() && text.starts_with(until) {
                return Ok(());
            }
        }
        let mut chunk = [0u8; 256];
        let count = sys(SYS_READ, reader, chunk.as_mut_ptr() as u64, chunk.len() as u64);
        if count <= 0 {
            return if until.is_empty() { Ok(()) } else { Err(format!("child output ended ({count})")) };
        }
        pending.extend_from_slice(&chunk[..count as usize]);
    }
}

fn put(path: &str, byte: u8) -> Result<(), String> {
    let mut file = std::fs::File::create(path).map_err(|error| format!("create {path}: {error}"))?;
    file.write_all(&[byte; 4096]).map_err(|error| format!("write {path}: {error}"))?;
    file.sync_all().map_err(|error| format!("sync {path}: {error}"))
}

fn describe(path: &str) -> String {
    match std::fs::read(path) {
        Ok(bytes) => {
            let first = bytes.first().copied().unwrap_or(b'-') as char;
            let uniform = bytes.iter().all(|&byte| byte == bytes[0]);
            format!("len={} bytes={first}{}", bytes.len(), if uniform { "" } else { "(mixed)" })
        }
        Err(error) => format!("{:?}", error.kind()),
    }
}

fn listing() -> String {
    let mut names: Vec<String> = match std::fs::read_dir("/") {
        Ok(entries) => entries.filter_map(|entry| entry.ok()).map(|entry| entry.file_name().to_string_lossy().into_owned()).collect(),
        Err(error) => return format!("{error}"),
    };
    names.sort();
    names.join(",")
}

fn parent() -> Result<(), String> {
    let mounted = storage::mount(false, true).map_err(|error| format!("mount {error:?}"))?;
    println!("FSX PARENT mounted writable seq={}", mounted.sequence);
    let image = std::fs::read("/bin/fsx-probe").map_err(|error| format!("read image: {error}"))?;
    let (child_in, parent_out) = pipe()?;
    let (parent_in, child_out) = pipe()?;
    let cell = ok(sys(SYS_CELL_CREATE, CHILD_STEP, 0, 0), "cell")?;
    let block = absd_runtime::block_handle();
    let copies: [[u64; 3]; 4] = [
        [child_in, RIGHT_READ, 0],
        [block, RIGHT_READ | RIGHT_WRITE, 0],
        [cell, RIGHT_READ, 0],
        [child_out, RIGHT_WRITE, COPY_CONSOLE],
    ];
    let request = [image.as_ptr() as u64, image.len() as u64, copies.as_ptr() as u64, 4];
    let child = ok(spawn_image_raw(request.as_ptr() as u64, 0, 0), "spawn_image with a writable block copy")?;
    println!("FSX PARENT spawn_image block-rights=read|write accepted");
    drop(image);
    for handle in [child_in, child_out, cell] {
        sys(SYS_CLOSE, handle, 0, 0);
    }
    let mut pending = Vec::new();
    relay(parent_in, &mut pending, "FSX CHILD mounted")?;

    put("/parent", b'P')?;
    println!("FSX PARENT synced /parent ({})", describe("/parent"));
    ok(sys(SYS_WRITE, parent_out, b"g".as_ptr() as u64, 1), "go")?;
    relay(parent_in, &mut pending, "")?;
    let mut record = [0u64; 4];
    ok(sys(SYS_WAIT, child, record.as_mut_ptr() as u64, 0), "wait")?;
    println!("FSX PARENT child outcome kind={} status={}", record[0], record[1]);

    println!("FSX PARENT reads /parent: {}", describe("/parent"));
    println!("FSX PARENT sees /: {}", listing());
    std::fs::create_dir("/parent-late").map_err(|error| format!("mkdir: {error}"))?;
    println!("FSX PARENT committed /parent-late");
    Ok(())
}

fn child() -> Result<(), String> {
    let mounted = storage::mount(false, true).map_err(|error| format!("mount {error:?}"))?;
    println!("FSX CHILD mounted writable seq={}", mounted.sequence);
    let _ = std::io::stdout().flush();
    let mut go = [0u8; 1];
    std::io::stdin().read_exact(&mut go).map_err(|error| format!("go: {error}"))?;
    put("/child", b'C')?;
    println!("FSX CHILD synced /child ({})", describe("/child"));
    println!("FSX CHILD sees /: {}", listing());
    Ok(())
}

fn main() {
    absd_runtime::link_anchor();
    let (role, result) = if absd_runtime::step() == CHILD_STEP { ("CHILD", child()) } else { ("PARENT", parent()) };
    let status = match result {
        Ok(()) => {
            println!("FSX {role} done");
            0
        }
        Err(error) => {
            println!("FSX {role} FAILED {error}");
            1
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(status);
}
