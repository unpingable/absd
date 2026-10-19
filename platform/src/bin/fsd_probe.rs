#![feature(restricted_std)]
//! `fsd-probe`: a session-side probe for the file server matrix
//! (`scripts/fsd-matrix.py`), installed as `/bin/fsd-probe`. Each
//! subcommand prints one line starting with its name and the outcome, and
//! exits 0 when the outcome is the one the subcommand is named for.
//!
//!   mounts                       the channel's mount list
//!   read PATH                    read the whole file; bytes and time
//!   write PATH BYTES             create/truncate and write a pattern; time
//!   recovery-pending PATH BYTES  qualification: acknowledged overwrite,
//!                                open and unsynced until VM interruption
//!   stat-loop PATH N             N stats; time
//!   hold PATH MILLIS             append a numbered line every 100 ms,
//!                                syncing each, until MILLIS have passed
//!   create-new PATH TEXT         create-new (fails if it exists)
//!   rename FROM TO               rename, replacing
//!   try-write PATH               open PATH for writing; OK or the error
//!   try-read PATH                read PATH; OK with its length or the error
//!   block                        every handle number 1..=64 as a block
//!                                device: must all be refused
//!   spawn-ro PROGRAM ARGS...     run PROGRAM with this session's mounts,
//!                                read-only, on a spare channel
//!   spawn-nofs PROGRAM ARGS...   run PROGRAM with no filesystem at all
//!   spawn PROGRAM ARGS...        run PROGRAM with the default policy
//!   garbage                      break this channel's framing on purpose
//!   leave                        write one whole request and exit without
//!                                reading the reply (a session ending with
//!                                a request in flight)
//!   drain                        read stdin to its end (the far side of a
//!                                shell pipeline); bytes, reads, and the
//!                                time from the first byte
//!   fill-scratch N               create N empty files in this session's
//!                                own /tmp/session-N; count and time
//!   pingpong N                   N one-byte round trips through /bin/cat
//!                                on two pipes (the IPC cost fsd pays)
//!   syscalls N                   N bare `time` syscalls; time
//!   stream N BYTES               N round trips of BYTES (<= 1024, a
//!                                pipe's capacity) through /bin/cat

use std::io::{Read, Write};
use std::time::Instant;

use absd_runtime::fsd::{self, ChildFs};

fn millis(start: Instant) -> u128 {
    start.elapsed().as_millis()
}

fn fail(line: String) -> ! {
    println!("{line}");
    std::process::exit(1);
}

fn run(policy: Option<ChildFs>, argv: &[String]) -> ! {
    if let Some(policy) = policy {
        fsd::set_next_child(policy);
    }
    let Some(program) = argv.first() else { fail("spawn: no program".into()) };
    match std::process::Command::new(program).args(&argv[1..]).status() {
        Ok(status) => {
            println!("spawn: {program} exited {}", status.code().unwrap_or(-1));
            std::process::exit(status.code().unwrap_or(1));
        }
        // The kernel's refusal of a start without the spawn right, by its
        // kind (std's own text for it is generic).
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            fail(format!("spawn: {program}: permission denied"))
        }
        Err(error) => fail(format!("spawn: {program}: {error}")),
    }
}

fn main() {
    absd_runtime::link_anchor();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |index: usize| args.get(index).cloned().unwrap_or_default();
    match arg(0).as_str() {
        "mounts" => match fsd::mounts() {
            Ok(mounts) => {
                let shown: Vec<String> = mounts
                    .iter()
                    .map(|m| format!("{}:{}", String::from_utf8_lossy(&m.path), if m.writable { "rw" } else { "ro" }))
                    .collect();
                println!("mounts: {}", shown.join(","));
            }
            Err(code) => fail(format!("mounts: error {code}")),
        },
        "read" => {
            let start = Instant::now();
            match std::fs::read(arg(1)) {
                Ok(bytes) => println!("read: {} bytes {} ms", bytes.len(), millis(start)),
                Err(error) => fail(format!("read: {error}")),
            }
        }
        "write" => {
            let size: usize = arg(2).parse().unwrap_or(0);
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let start = Instant::now();
            let result = std::fs::File::create(arg(1)).and_then(|mut file| {
                file.write_all(&data)?;
                file.sync_all()
            });
            match result {
                Ok(()) => println!("write: {size} bytes {} ms", millis(start)),
                Err(error) => fail(format!("write: {error}")),
            }
        }
        "recovery-pending" => {
            // Qualification boundary: WRITE_AT has answered, but this
            // handle has not closed or synced. The host ends this VM after
            // the marker, then boots the same disk with a new file server.
            let size: usize = arg(2).parse().unwrap_or(0);
            if size == 0 || size > 65536 {
                fail("recovery-pending: size must be 1..65536".into());
            }
            let data: Vec<u8> = (0..size).map(|i| ((i + 17) % 251) as u8).collect();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(arg(1))
                .unwrap_or_else(|error| fail(format!("recovery-pending: open: {error}")));
            let written = file
                .write(&data)
                .unwrap_or_else(|error| fail(format!("recovery-pending: write: {error}")));
            if written != size {
                fail(format!("recovery-pending: short write: {written}/{size}"));
            }
            println!("RECOVERY PENDING write_accepted bytes={size}");
            std::io::stdout()
                .flush()
                .unwrap_or_else(|error| fail(format!("recovery-pending: marker: {error}")));
            loop {
                absd_runtime::sleep_ticks(1);
            }
        }
        "stat-loop" => {
            let count: usize = arg(2).parse().unwrap_or(1);
            let start = Instant::now();
            for _ in 0..count {
                if let Err(error) = std::fs::metadata(arg(1)) {
                    fail(format!("stat-loop: {error}"));
                }
            }
            println!("stat-loop: {count} stats {} ms", millis(start));
        }
        "hold" => {
            let limit: u128 = arg(2).parse().unwrap_or(1000);
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(arg(1))
                .unwrap_or_else(|error| fail(format!("hold: {error}")));
            let start = Instant::now();
            let mut line = 0u64;
            while millis(start) < limit {
                line += 1;
                // One write request per line, then a commit: a kill leaves
                // whole lines or none.
                let text = format!("line {line}\n");
                if let Err(error) = file.write_all(text.as_bytes()).and_then(|()| file.sync_all()) {
                    fail(format!("hold: line {line}: {error}"));
                }
                let pause = Instant::now();
                while millis(pause) < 100 {
                    absd_runtime::sleep_ticks(10);
                }
            }
            println!("hold: {line} lines");
        }
        "drain" => {
            let mut stdin = std::io::stdin().lock();
            let mut buffer = [0u8; 4096];
            let (mut bytes, mut reads) = (0usize, 0usize);
            let mut start = None;
            loop {
                match stdin.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        start.get_or_insert_with(Instant::now);
                        bytes += count;
                        reads += 1;
                    }
                    Err(error) => fail(format!("drain: {error}")),
                }
            }
            println!("drain: {bytes} bytes {reads} reads {} ms", start.map_or(0, millis));
        }
        "fill-scratch" => {
            let count: usize = arg(1).parse().unwrap_or(1);
            let mounts = fsd::mounts().unwrap_or_else(|code| fail(format!("fill-scratch: mounts: error {code}")));
            let Some(scratch) = mounts.iter().find(|m| m.writable && m.path.starts_with(b"/tmp/session-")) else {
                fail("fill-scratch: no session scratch mount".into())
            };
            let dir = String::from_utf8_lossy(&scratch.path).into_owned();
            let start = Instant::now();
            for index in 0..count {
                if let Err(error) = std::fs::File::create(format!("{dir}/f{index}")) {
                    fail(format!("fill-scratch: file {index}: {error}"));
                }
            }
            println!("fill-scratch: {count} files in {dir} {} ms", millis(start));
        }
        "create-new" => {
            let result = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(arg(1))
                .and_then(|mut file| file.write_all(arg(2).as_bytes()));
            match result {
                Ok(()) => println!("create-new: OK {}", arg(1)),
                Err(error) => fail(format!("create-new: {:?} {}", error.kind(), arg(1))),
            }
        }
        "rename" => match std::fs::rename(arg(1), arg(2)) {
            Ok(()) => println!("rename: OK {} {}", arg(1), arg(2)),
            Err(error) => fail(format!("rename: {:?} {} {}", error.kind(), arg(1), arg(2))),
        },
        "try-write" => {
            let result = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(arg(1))
                .and_then(|mut file| file.write_all(b"written by a child\n"));
            match result {
                Ok(()) => println!("try-write: OK {}", arg(1)),
                Err(error) => fail(format!("try-write: {:?} {}", error.kind(), arg(1))),
            }
        }
        "try-read" => {
            let mut bytes = Vec::new();
            match std::fs::File::open(arg(1)).and_then(|mut file| file.read_to_end(&mut bytes)) {
                Ok(count) => println!("try-read: OK {} {count}", arg(1)),
                Err(error) => fail(format!("try-read: {:?} {}", error.kind(), arg(1))),
            }
        }
        "block" => {
            // A session holds no block handle: every handle number this
            // process could name is refused as a block device, for reading
            // and for writing.
            // A write is tried only through a handle that read sector 0,
            // and writes the same bytes back, so the probe can never damage
            // a device it should not have been able to reach.
            let mut sector = [0u8; absd_runtime::layout::SECTOR_BYTES];
            let mut accepted = Vec::new();
            for handle in 1..=64u64 {
                if absd_runtime::layout::read_raw(handle, 0, &mut sector).is_ok() {
                    let written = absd_runtime::layout::write_raw(handle, 0, &sector).is_ok();
                    accepted.push((handle, written));
                }
            }
            if accepted.is_empty() {
                println!("block: REFUSED handles=64 block_handle={}", absd_runtime::block_handle());
            } else {
                fail(format!("block: ACCEPTED {accepted:?}"));
            }
        }
        "pingpong" => {
            let count: usize = arg(1).parse().unwrap_or(100);
            fsd::set_next_child(ChildFs::None);
            let mut child = std::process::Command::new("/bin/cat")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| fail(format!("pingpong: {error}")));
            let mut input = child.stdin.take().unwrap();
            let mut output = child.stdout.take().unwrap();
            let start = Instant::now();
            let mut byte = [0u8; 1];
            for _ in 0..count {
                input.write_all(b"\n").unwrap();
                output.read_exact(&mut byte).unwrap();
            }
            println!("pingpong: {count} round trips {} ms", millis(start));
            drop(input);
            let _ = child.wait();
        }
        "syscalls" => {
            let count: usize = arg(1).parse().unwrap_or(1000);
            let start = Instant::now();
            let mut last = 0;
            for _ in 0..count {
                last = absd_runtime::ticks();
            }
            println!("syscalls: {count} calls {} us (tick {})", start.elapsed().as_micros(), last > 0);
        }
        "stream" => {
            let count: usize = arg(1).parse().unwrap_or(100);
            let size: usize = arg(2).parse().unwrap_or(256);
            if size > 1024 {
                // One thread writes then reads: more than a pipe holds
                // would leave both sides blocked.
                fail(format!("stream: at most 1024 bytes a round trip, not {size}"));
            }
            fsd::set_next_child(ChildFs::None);
            let mut child = std::process::Command::new("/bin/cat")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| fail(format!("stream: {error}")));
            let mut input = child.stdin.take().unwrap();
            let mut output = child.stdout.take().unwrap();
            // Newline-terminated, so cat's line-buffered stdout passes it on.
            let mut data = vec![b'x'; size.max(1)];
            *data.last_mut().unwrap() = b'\n';
            let size = data.len();
            let mut back = vec![0u8; size];
            let start = Instant::now();
            for _ in 0..count {
                input.write_all(&data).unwrap();
                output.read_exact(&mut back).unwrap();
            }
            println!("stream: {count} x {size} bytes {} ms", millis(start));
            drop(input);
            let _ = child.wait();
        }
        "garbage" => {
            // A length no frame may have, on this process's own channel:
            // the server stops reading that channel and reports it, even
            // when it reads the bytes only after this session's release;
            // nobody else notices.
            let (request, _) = fsd::channels()[0];
            match absd_runtime::write_within(request, &[0xff; 4], 100) {
                Ok(4) => println!("garbage: sent"),
                other => fail(format!("garbage: {other:?}")),
            }
        }
        "leave" => {
            // A whole request nobody waits for: served, or refused if the
            // server reads it after the release; either way its reply is
            // drained by sshd before the slot is bound again.
            let (request, _) = fsd::channels()[0];
            let frame = absd_fsd::proto::Frame::request(absd_fsd::proto::op::STAT).bytes(b"/etc/motd").finish();
            match absd_runtime::write_within(request, &frame, 100) {
                Ok(count) if count == frame.len() => println!("leave: sent"),
                other => fail(format!("leave: {other:?}")),
            }
        }
        "spawn-ro" => run(Some(ChildFs::ReadOnly), &args[1..]),
        "spawn-nofs" => run(Some(ChildFs::None), &args[1..]),
        "spawn" => run(None, &args[1..]),
        other => fail(format!("fsd-probe: unknown subcommand {other:?}")),
    }
}
