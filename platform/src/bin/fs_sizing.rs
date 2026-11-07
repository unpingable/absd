#![feature(restricted_std)]
//! Measurement worker for filesystem region sizing
//! (docs/storage-sizing-20261102). Built only with the `fs-sizing` feature
//! and run as the workload of a durable boot, it holds the block device
//! and the same `absd_fs` library, runtime storage path and 32 MiB heap
//! window the file server has, without serving anything. Every line it
//! prints starts with `SIZING`; ticks are PIT ticks (about 1 ms).
//!
//! The step word is `mode * 10_000 + permille`:
//! - mode 1, fill: mount (formatting a blank device, as the file server's
//!   first boot does), then add 64 MiB files under `/fill` until
//!   `permille` of the data blocks are used, committing after each file.
//!   Each boot measures the previous boot's fill at mount, fresh. 1001
//!   asks for more than the region holds, to meet the allocator's refusal.
//! - mode 2, small files: mount, then create 64-byte files under `/small`
//!   until the object budget refuses one.
//! - mode 3, format split: on a blank device, time the layout format's
//!   whole-device scan and the filesystem format's region scan apart (the
//!   normal first mount skips the second scan; this is the path of a
//!   device whose layout exists but whose region was never formatted).
//! - mode 4, append: grow one file by a block and commit, `permille`
//!   times (the count), reporting the heap: a long-lived server's commits.
//! - mode 5, client: in an `fsd` durable boot, write `permille` 64 MiB
//!   files and then 100 one-block appends through the file server, timing
//!   each commit from the client side; the server's own figures are its
//!   `FSD STATS phase=stop` line when this worker exits.

use absd_fs::{Error, Fs, OpenFlags};
use absd_runtime::storage::{self, RegionDevice};

const FILE_BLOCKS: u32 = 16_384; // 64 MiB
const CHUNK: usize = 256 * 1024;

fn heap() -> String {
    format!(
        "heap_pages={} heap_peak_pages={} heap_free_pages={}",
        absd_runtime::heap_mapped_pages(),
        absd_runtime::heap_mapped_pages_peak(),
        absd_runtime::heap_free_pooled_pages()
    )
}

fn blocks(fs: &Fs<RegionDevice>) -> String {
    let data = fs.geometry().data_blocks;
    let free = fs.free_blocks();
    format!("data_blocks={data} free_blocks={free} used_blocks={} fs_objects={}", data - free, fs.object_count())
}

fn mount() -> Fs<RegionDevice> {
    let start = absd_runtime::ticks();
    let mounted = storage::mount(true, true).unwrap_or_else(|e| {
        println!("SIZING FAILED mount error={e:?} ticks={} {}", absd_runtime::ticks() - start, heap());
        std::process::exit(3);
    });
    let ticks = absd_runtime::ticks() - start;
    let fs = storage::take_mounted().unwrap_or_else(|| {
        println!("SIZING FAILED mount vanished");
        std::process::exit(3);
    });
    let geometry = fs.geometry();
    println!(
        "SIZING MOUNT formatted={} fs_seq={} mount_ticks={ticks} region_sectors={} half_sectors={} {} {}",
        mounted.formatted,
        mounted.sequence,
        geometry.region_sectors,
        geometry.half_sectors,
        blocks(&fs),
        heap()
    );
    fs
}

/// One timed commit; the image bytes it wrote come from `WriteStats`.
fn commit(fs: &mut Fs<RegionDevice>, label: &str) -> Result<(), Error> {
    let before = fs.write_stats();
    // The peak of everything since the last commit (the file's writes).
    let before_peak = absd_runtime::heap_peak_reset();
    let start = absd_runtime::ticks();
    let result = fs.sync();
    let ticks = absd_runtime::ticks() - start;
    let after = fs.write_stats();
    println!(
        "SIZING COMMIT {label} result={result:?} commit_ticks={ticks} image_bytes={} commits={} peak_before_commit_pages={before_peak} {} {}",
        after.image_bytes - before.image_bytes,
        after.commits - before.commits,
        blocks(fs),
        heap()
    );
    result
}

fn ensure_dir(fs: &mut Fs<RegionDevice>, path: &[u8]) {
    match fs.mkdir(path) {
        Ok(()) | Err(Error::Exists) => {}
        Err(e) => {
            println!("SIZING FAILED mkdir error={e:?}");
            std::process::exit(3);
        }
    }
}

fn create(fs: &mut Fs<RegionDevice>, path: &[u8]) -> Result<u64, Error> {
    let flags = OpenFlags { read: false, write: true, create: false, create_new: true, truncate: false };
    fs.open(path, flags)
}

fn fill(permille: u64) {
    let mut fs = mount();
    let data = u64::from(fs.geometry().data_blocks);
    let goal = data * permille / 1000;
    ensure_dir(&mut fs, b"/fill");
    let mut index = fs.read_dir(b"/fill").map(|entries| entries.len()).unwrap_or(0);
    let mut chunk = vec![0u8; CHUNK];
    let start = absd_runtime::ticks();
    let mut outcome = "goal";
    loop {
        let used = data - u64::from(fs.free_blocks());
        if used >= goal {
            break;
        }
        let want = (goal - used).min(u64::from(FILE_BLOCKS)) * 4096;
        let path = format!("/fill/f{index:05}");
        chunk.fill(index as u8 | 1);
        println!("SIZING FILE begin file={index} bytes={want}");
        let file_start = absd_runtime::ticks();
        let handle = match create(&mut fs, path.as_bytes()) {
            Ok(handle) => handle,
            Err(e) => {
                println!("SIZING REFUSED phase=create file={index} error={e:?} {} {}", blocks(&fs), heap());
                outcome = "refused";
                break;
            }
        };
        let mut written = 0u64;
        let mut failed = None;
        while written < want {
            let take = (want - written).min(CHUNK as u64) as usize;
            match fs.write_at(handle, written, &chunk[..take]) {
                Ok(count) => written += count as u64,
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        let _ = fs.close(handle);
        let write_ticks = absd_runtime::ticks() - file_start;
        println!("SIZING FILE written file={index} bytes={written} write_ticks={write_ticks}");
        if let Some(e) = failed {
            println!("SIZING REFUSED phase=write file={index} written={written} error={e:?} {} {}", blocks(&fs), heap());
            outcome = "refused";
            let _ = commit(&mut fs, &format!("file={index} after_refusal=1"));
            break;
        }
        if commit(&mut fs, &format!("file={index}")).is_err() {
            outcome = "commit-failed";
            break;
        }
        index += 1;
    }
    println!(
        "SIZING DONE mode=fill permille={permille} outcome={outcome} files={index} fill_ticks={} {} {}",
        absd_runtime::ticks() - start,
        blocks(&fs),
        heap()
    );
}

fn small() {
    let mut fs = mount();
    ensure_dir(&mut fs, b"/small");
    let start = absd_runtime::ticks();
    let mut window = start;
    let mut window_bytes = fs.write_stats().image_bytes;
    let mut count = 0u32;
    let outcome = loop {
        let path = format!("/small/s{count:05}");
        let handle = match create(&mut fs, path.as_bytes()) {
            Ok(handle) => handle,
            Err(e) => break format!("{e:?}"),
        };
        if let Err(e) = fs.write_at(handle, 0, &[0x5a; 64]) {
            break format!("write {e:?}");
        }
        let _ = fs.close(handle);
        count += 1;
        if count.is_multiple_of(100) {
            let now = absd_runtime::ticks();
            let bytes = fs.write_stats().image_bytes;
            println!(
                "SIZING SMALL progress files={count} ticks_last_100={} image_bytes_last_100={} {}",
                now - window,
                bytes - window_bytes,
                heap()
            );
            window = now;
            window_bytes = bytes;
        }
    };
    let total = absd_runtime::ticks() - start;
    let _ = commit(&mut fs, "small-final");
    let stats = fs.write_stats();
    println!(
        "SIZING DONE mode=small files={count} refusal={outcome} small_ticks={total} commits={} image_bytes={} {} {}",
        stats.commits,
        stats.image_bytes,
        blocks(&fs),
        heap()
    );
}

fn format_split() {
    let block = absd_runtime::block_handle();
    let start = absd_runtime::ticks();
    if let Err(code) = absd_runtime::layout::Layout::format(block) {
        println!("SIZING FAILED layout format code={code}");
        std::process::exit(3);
    }
    let layout_ticks = absd_runtime::ticks() - start;
    println!("SIZING FORMAT layout_scan_ticks={layout_ticks}");
    let start = absd_runtime::ticks();
    let fs = mount();
    println!(
        "SIZING FORMAT region_format_and_mount_ticks={} layout_scan_ticks={layout_ticks} {}",
        absd_runtime::ticks() - start,
        blocks(&fs)
    );
}

/// A long-lived server's steady state: one file grows by one block per
/// commit, `count` times, as an appended log and its idle commit do.
fn append(count: u64) {
    let mut fs = mount();
    let flags = OpenFlags { read: false, write: true, create: true, create_new: false, truncate: false };
    let handle = fs.open(b"/append", flags).unwrap_or_else(|e| {
        println!("SIZING FAILED append open error={e:?}");
        std::process::exit(3);
    });
    let block = [0x33u8; 4096];
    let start = absd_runtime::ticks();
    for round in 1..=count {
        let size = fs.fstat(handle).map(|attr| attr.size).unwrap_or(0);
        if let Err(e) = fs.write_at(handle, size, &block) {
            println!("SIZING REFUSED phase=append round={round} error={e:?} {} {}", blocks(&fs), heap());
            break;
        }
        let commit_start = absd_runtime::ticks();
        let result = fs.sync();
        let ticks = absd_runtime::ticks() - commit_start;
        if result.is_err() || round % 10 == 0 || round <= 3 {
            println!("SIZING APPEND round={round} result={result:?} commit_ticks={ticks} image_bytes_total={} {}",
                     fs.write_stats().image_bytes, heap());
        }
        if result.is_err() {
            break;
        }
    }
    println!("SIZING DONE mode=append rounds={count} append_ticks={} {} {}", absd_runtime::ticks() - start, blocks(&fs), heap());
}

fn space_line() -> String {
    match absd_runtime::fsd::space() {
        Ok(space) => format!("data_blocks={} free_blocks={} commit_seq={}", space.data_blocks, space.free_blocks, space.commit),
        Err(code) => format!("space_error={code}"),
    }
}

/// A client of the file server (an `fsd` durable boot: the worker holds
/// the control channel, whose `/var/log` mount is writable): `files`
/// files of 64 MiB, each followed by a timed `op::COMMIT`, then 100
/// one-block appends to one file, each followed by a timed commit. The
/// worker's exit ends the control channel, so the server stops in order
/// and prints `FSD STATS phase=stop`.
fn client(files: u64) {
    use std::io::Write;
    if !absd_runtime::fsd::active() {
        println!("SIZING FAILED client without a file server");
        std::process::exit(3);
    }
    let fail = |what: &str, e: std::io::Error| -> ! {
        println!("SIZING FAILED client {what} error={e} {}", space_line());
        std::process::exit(3);
    };
    println!("SIZING CLIENT begin files={files} {}", space_line());
    std::fs::create_dir_all("/var/log/sizing").unwrap_or_else(|e| fail("mkdir", e));
    let chunk = vec![0x5au8; 64 * 1024];
    for index in 0..files {
        let path = format!("/var/log/sizing/g{index:04}");
        let start = absd_runtime::ticks();
        let mut file = std::fs::File::create(&path).unwrap_or_else(|e| fail("create", e));
        for _ in 0..(FILE_BLOCKS as usize * 4096 / chunk.len()) {
            file.write_all(&chunk).unwrap_or_else(|e| fail("write", e));
        }
        drop(file);
        let write_ticks = absd_runtime::ticks() - start;
        let commit_start = absd_runtime::ticks();
        let committed = absd_runtime::fsd::commit();
        let commit_ticks = absd_runtime::ticks() - commit_start;
        println!(
            "SIZING CLIENT file={index} bytes={} write_ticks={write_ticks} commit={committed:?} commit_ticks={commit_ticks} {}",
            FILE_BLOCKS as usize * 4096,
            space_line()
        );
        if committed.is_err() {
            std::process::exit(3);
        }
    }
    let mut log = std::fs::OpenOptions::new().create(true).append(true)
        .open("/var/log/sizing/append").unwrap_or_else(|e| fail("append open", e));
    let (mut total, mut max, mut min) = (0u64, 0u64, u64::MAX);
    for _ in 0..100 {
        log.write_all(&chunk[..4096]).unwrap_or_else(|e| fail("append", e));
        let start = absd_runtime::ticks();
        if let Err(code) = absd_runtime::fsd::commit() {
            println!("SIZING FAILED client append commit code={code}");
            std::process::exit(3);
        }
        let ticks = absd_runtime::ticks() - start;
        total += ticks;
        max = max.max(ticks);
        min = min.min(ticks);
    }
    println!("SIZING CLIENT appends=100 commit_ticks_total={total} commit_ticks_min={min} commit_ticks_max={max} {}", space_line());
    println!("SIZING DONE mode=client files={files}");
}

fn main() {
    absd_runtime::link_anchor();
    let step = absd_runtime::step();
    let (mode, permille) = (step / 10_000, step % 10_000);
    println!("SIZING START step={step} {}", heap());
    match mode {
        1 if permille <= 1001 => fill(permille),
        2 => small(),
        3 => format_split(),
        4 => append(permille),
        5 => client(permille),
        _ => {
            println!("SIZING FAILED step={step}");
            std::process::exit(3);
        }
    }
}
