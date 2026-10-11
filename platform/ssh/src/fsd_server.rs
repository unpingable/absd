// The ABSD body of `absd-fsd` (see `fsd_main.rs`).

use absd_fs::{Error, Fs, Kind, OpenFlags};
use absd_fsd::log::{self as logfile, LogFile};
use absd_fsd::proto::{self, Mount};
use absd_fsd::recovery;
use absd_fsd::{CONTROL, Event, Inbox, PipeState, Server, Taken};
use absd_runtime::fsd::pipe_info;
use absd_runtime::storage::{self, RegionDevice};

const SEED_PATH: &[u8] = b"/ssh/host_ed25519_seed";
const SEED_STAGING: &[u8] = b"/ssh/host_ed25519_seed.new";
const ERROR_TIMEOUT: i64 = -110;
const MAX_TRANSFER: usize = 256;

fn fatal(message: &str) -> ! {
    println!("FSD FAILED {message}");
    std::process::exit(3);
}

/// `/var/log/fsd`: the server's own lines, written into its own
/// filesystem (`absd_fsd::log` has the bound). Every line also goes to the
/// console as before.
struct Log {
    file: LogFile,
}

impl Log {
    fn say(&mut self, server: &mut Server<RegionDevice>, text: &str) {
        println!("{text}");
        self.write(server, text);
    }

    /// Into the file only (a line already on the console).
    fn write(&mut self, server: &mut Server<RegionDevice>, text: &str) {
        let wall = absd_runtime::wall_clock_seconds().ok();
        let line = logfile::line(wall, "fsd", text);
        server.fs.set_clock(wall);
        if self.file.append(&mut server.fs, wall, &line).is_ok() {
            server.note_write(absd_runtime::ticks());
        }
    }
}

/// The RTC's seconds for `mtime`; `None` when the kernel refuses.
fn wall_clock() -> Option<u64> {
    absd_runtime::wall_clock_seconds().ok()
}

fn ensure_dir(fs: &mut Fs<RegionDevice>, path: &[u8]) -> Result<(), Error> {
    match fs.stat(path) {
        Ok(attr) if attr.kind == Kind::Dir => Ok(()),
        Ok(_) => Err(Error::NotDir),
        Err(Error::NotFound) => fs.mkdir(path),
        Err(error) => Err(error),
    }
}

/// Loads, or creates, the host key seed. Creation: `.new` create-new, the
/// seed, sync, rename over the seed (a commit), as sshd did before.
fn host_key(fs: &mut Fs<RegionDevice>, regenerate: bool) -> Result<&'static str, String> {
    ensure_dir(fs, b"/ssh").map_err(|e| format!("/ssh: {e:?}"))?;
    if !regenerate {
        match fs.stat(SEED_PATH) {
            Ok(attr) if attr.kind == Kind::File && attr.size == 32 => return Ok("PRESENT"),
            Ok(attr) => return Err(format!("host key seed is {} bytes, not 32", attr.size)),
            Err(Error::NotFound) => {}
            Err(error) => return Err(format!("host key: {error:?}")),
        }
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("entropy: {e}"))?;
    match fs.unlink(SEED_STAGING) {
        Ok(()) | Err(Error::NotFound) => {}
        Err(error) => return Err(format!("staging: {error:?}")),
    }
    let flags = OpenFlags { read: false, write: true, create: false, create_new: true, truncate: false };
    let handle = fs.open(SEED_STAGING, flags).map_err(|e| format!("create: {e:?}"))?;
    fs.write_at(handle, 0, &seed).map_err(|e| format!("write: {e:?}"))?;
    fs.sync().map_err(|e| format!("sync: {e:?}"))?;
    fs.close(handle).map_err(|e| format!("close: {e:?}"))?;
    fs.rename(SEED_STAGING, SEED_PATH, false).map_err(|e| format!("install: {e:?}"))?;
    Ok("GENERATED")
}

struct Io {
    request: u64,
    reply: u64,
    /// What the request pipe delivered so far (`absd_fsd::inbox`: the
    /// framing decision and the release-versus-bind rule live there).
    inbox: Inbox,
    output: Vec<u8>,
    sent: usize,
}

impl Io {
    fn pending(&self) -> bool {
        self.sent < self.output.len()
    }
}

fn state(io: &Io) -> Option<PipeState> {
    let request = pipe_info(io.request).ok()?;
    let reply = pipe_info(io.reply).ok()?;
    Some(PipeState {
        // Bytes read but not yet taken count as waiting too: a request
        // read halfway is work the binding checks must not let a bind
        // discard.
        request_available: request[0] + io.inbox.len() as u64,
        request_writers: request[3],
        reply_available: reply[0],
        reply_readers: reply[2],
    })
}

/// Longest run of ticks one channel is served back to back before the
/// others are looked at (each idle one costs at most a tick).
const HOT_TICKS: u64 = 10;

fn report(server: &mut Server<RegionDevice>, log: &mut Log, events: Vec<Event>, qualification_exit_on_notice: bool) {
    let list = |mounts: &[Mount]| {
        mounts
            .iter()
            .map(|m| format!("{}:{}", String::from_utf8_lossy(&m.path), if m.writable { "rw" } else { "ro" }))
            .collect::<Vec<_>>()
            .join(",")
    };
    for event in events {
        let text = match event {
            Event::Bound { slot, spares, mounts } => {
                format!("FSD BIND slot={slot} spares={spares:?} mounts={}", list(&mounts))
            }
            Event::BindRefused { slot, status } => format!("FSD BIND REFUSED slot={slot} status={status}"),
            // Not a leak: the released slot's last request is still to be
            // read and refused, or its refusal drained. The matrices count
            // REFUSED as a leftover holder and this line as a retry.
            Event::BindDeferred { slot } => format!("FSD BIND DEFERRED slot={slot}"),
            Event::Released { slot, closed, scratch } => {
                let (bound, opens, draining) = server.capacity();
                format!(
                    "FSD RELEASE slot={slot} closed={closed} scratch_removed={scratch} fs_objects={} bound={bound} opens={opens} draining={draining}",
                    server.fs.object_count()
                )
            }
            // One per command a shell starts: the console only, so that
            // a command's start never writes the filesystem.
            Event::Derived { spare, owner, mounts } => {
                println!("FSD DERIVE spare={spare} owner={owner} mounts={}", list(&mounts));
                continue;
            }
            Event::DeriveRefused { owner, status } => format!("FSD DERIVE REFUSED owner={owner} status={status}"),
            // sshd's line for the console: sshd has none of its own, and
            // logs the line itself (/var/log/sshd).
            Event::Notice(text) => {
                if qualification_exit_on_notice && text.as_slice() == b"FSD QUALIFICATION EXIT" {
                    // Local VM control: retire the file server while sshd is
                    // waiting for the NOTICE reply. Normal boots never set
                    // the flag, and no protocol operation is added.
                    println!("FSD QUALIFICATION EXIT status=7");
                    std::process::exit(7);
                }
                println!("{}", String::from_utf8_lossy(&text));
                continue;
            }
        };
        log.say(server, &text);
    }
}

/// Direct console record at a settled dispatcher boundary. The two fixed
/// rotated logs may first appear during churn; no other object growth is
/// exempted from the capacity comparison.
fn report_capacity(server: &Server<RegionDevice>, boot: &str) {
    let settled_releases = server.settled();
    let mut rotated_logs = 0usize;
    for path in [&b"/var/log/fsd.0"[..], &b"/var/log/sshd.0"[..]] {
        match server.fs.stat(path) {
            Ok(_) => rotated_logs += 1,
            Err(Error::NotFound) => {}
            Err(error) => fatal(&format!("capacity stat {}: {error:?}", String::from_utf8_lossy(path))),
        }
    }
    let (bound, opens, draining) = server.capacity();
    println!(
        "FSD CAPACITY boot={boot} settled_releases={settled_releases} fs_objects={} rotated_logs={rotated_logs} bound={bound} opens={opens} draining={draining} heap_pages_peak={}",
        server.fs.object_count(),
        absd_runtime::heap_mapped_pages(),
    );
}

/// A new binding: discards what an earlier holder left, our buffers and
/// the bytes still waiting in the request pipe. Only a bind asks for this
/// (`server.resets`); a release discards nothing, and the loop goes on
/// reading the released channel until whatever its session left has gone.
fn reset(io: &mut Io) {
    io.inbox.discard();
    io.output.clear();
    io.sent = 0;
    let mut chunk = [0u8; MAX_TRANSFER];
    while let Ok([available, ..]) = pipe_info(io.request) {
        if available == 0 {
            break;
        }
        let take = (available as usize).min(MAX_TRANSFER);
        if absd_runtime::read_within(io.request, &mut chunk[..take], 1).unwrap_or(0) == 0 {
            break;
        }
    }
}

/// Finalize mode (`--finalize`): started by init after an orderly end
/// completed (file server reaped with status 0, every orphan drained,
/// worker stream clean), with the block handle and no channels, to leave
/// init's verdict for the next generation's recovery ledger
/// (absd_fsd::recovery::SERVED_COMPLETED). Nothing else is served or
/// changed; the fact is committed before exit 0, and any failure exits 3
/// so the streak stays (conservative).
fn finalize() -> ! {
    if !absd_runtime::has_block_device() {
        println!("FSD FINALIZE FAILED no block handle");
        std::process::exit(3);
    }
    if let Err(e) = storage::mount(false, true) {
        println!("FSD FINALIZE FAILED mount: {e:?}");
        std::process::exit(3);
    }
    let mut fs = storage::take_mounted().unwrap_or_else(|| {
        println!("FSD FINALIZE FAILED mount vanished");
        std::process::exit(3);
    });
    let boot = absd_runtime::boot_id().unwrap_or_else(|code| {
        println!("FSD FINALIZE FAILED boot identity: {code}");
        std::process::exit(3);
    });
    let hex = boot.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let boot_id: recovery::Boot = hex.as_bytes().try_into().expect("32 hex digits");
    match recovery::completed(&mut fs, &boot_id).and_then(|()| fs.sync()) {
        Ok(()) => {
            println!("FSD FINALIZED boot={hex}");
            std::process::exit(0);
        }
        Err(e) => {
            println!("FSD FINALIZE FAILED {e:?}");
            std::process::exit(3);
        }
    }
}

fn main() {
    absd_runtime::link_anchor();
    if std::env::args().any(|arg| arg == "--finalize") {
        finalize();
    }
    let regenerate = std::env::args().any(|arg| arg == "--regenerate-host-key");
    let qualification_exit_on_notice = std::env::args().any(|arg| arg == "--qualification-exit-on-notice");
    let ends = absd_runtime::server::channels();
    if ends.len() < 2 || !absd_runtime::has_block_device() {
        fatal("needs the block handle and at least the control channel and one slot");
    }
    let mounted = storage::mount(true, true).unwrap_or_else(|e| match e {
        Error::UnsupportedFormat => fatal(
            "mount: UnsupportedFormat: the disk holds another filesystem format; this release \
             reads format 2 only (docs/FILESYSTEM.md); migrate the image on the host",
        ),
        e => fatal(&format!("mount: {e:?}")),
    });
    let mut fs = storage::take_mounted().unwrap_or_else(|| fatal("mount vanished"));
    // `mtime` comes from the wall clock; the loop refreshes it per request.
    fs.set_clock(absd_runtime::wall_clock_seconds().ok());
    for dir in [&b"/tmp"[..], b"/home", b"/home/operator", b"/var", logfile::DIR] {
        ensure_dir(&mut fs, dir).unwrap_or_else(|e| fatal(&format!("{}: {e:?}", String::from_utf8_lossy(dir))));
    }
    let key = host_key(&mut fs, regenerate).unwrap_or_else(|e| fatal(&e));
    fs.sync().unwrap_or_else(|e| fatal(&format!("sync: {e:?}")));
    // sshd reads the host key, its configuration under /etc, and the
    // commands; it writes its own log.
    let control = vec![
        Mount::new(b"/ssh", false),
        Mount::new(b"/bin", false),
        Mount::new(b"/etc", false),
        Mount::new(logfile::DIR, true),
        // The recovery ledger (absd_fsd::recovery) sshd reads but never
        // writes, and the facts directory it writes; the server refuses
        // either in any session's mount list.
        Mount::new(recovery::DIR, false),
        Mount::new(recovery::FACTS, true),
    ];
    let mut server = Server::new(fs, ends.len() - 1, control);
    let mut log = Log { file: LogFile::new(b"/var/log/fsd", "fsd") };
    let boot = absd_runtime::boot_id()
        .unwrap_or_else(|code| fatal(&format!("boot identity: {code}")))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    log.write(&mut server, &format!("started: boot {boot}, uptime {} ms", absd_runtime::boot_millis()));
    log.say(&mut server, &format!("FSD HOST KEY {key} path={}", String::from_utf8_lossy(SEED_PATH)));
    // Scratch of sessions an earlier boot's reset left bound: gone before
    // anything is served, so the baseline counts nothing of theirs and no
    // session of this boot meets it.
    server.clock(absd_runtime::ticks(), wall_clock);
    let swept = server.sweep_scratch().unwrap_or_else(|e| fatal(&format!("sweep: {e:?}")));
    log.say(&mut server, &format!("FSD SWEEP scratch_removed={swept}"));
    // The release this boot serves (docs/RELEASE.md section 3, items 2
    // and 3): the selected tree's record must state exactly this build's
    // identity, or nothing is served and init's pre-ready refusal ends the
    // boot. The refusal is a console line only: nothing more is written.
    let release = absd_fsd::release::select(&mut server.fs, &absd_release::compiled()).unwrap_or_else(|refusal| {
        println!("RELEASE REFUSED reason={}", refusal.reason());
        std::process::exit(3);
    });
    server.bind_release(&release);
    log.say(&mut server, &format!("RELEASE OK release={}", String::from_utf8_lossy(&release)));
    // The recovery ledger is charged and committed here, before anything
    // is served: this generation already counts as not ended, so no
    // failure of sshd or of this server needs to record itself. A ledger
    // that was established and is now missing or corrupt is a refusal
    // like a bad release record: the console names it and nothing resets.
    let boot_id: recovery::Boot = boot
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| fatal("boot identity is not 32 hex digits"));
    let (ledger, previous) = recovery::charge(&mut server.fs, &boot_id).unwrap_or_else(|refusal| {
        match refusal {
            recovery::Refusal::Storage(e) => println!("RECOVERY STATE REFUSED reason=storage error={e:?}"),
            other => println!("RECOVERY STATE REFUSED reason={}", other.reason()),
        }
        std::process::exit(3);
    });
    log.say(
        &mut server,
        &format!("FSD RECOVERY seq={} streak={} previous={}", ledger.seq, ledger.streak, previous.name()),
    );
    let mut io: Vec<Io> = ends
        .iter()
        .map(|&(request, reply)| Io { request, reply, inbox: Inbox::new(), output: Vec::new(), sent: 0 })
        .collect();
    let ready_objects = server.fs.object_count();
    log.say(
        &mut server,
        &format!(
            "FSD READY channels={} slots={} fs_seq={} formatted={} fs_objects={}",
            io.len(),
            io.len() - 1,
            mounted.sequence,
            mounted.formatted,
            ready_objects
        ),
    );
    report_capacity(&server, &boot);
    let mut served = 0u64;
    let mut next = 0usize;
    // The channel served back to back, and since which tick.
    let mut hot: Option<(usize, u64)> = None;
    loop {
        let mut progress = false;
        // Round robin over the channels served now, starting after the one
        // last served. Each look blocks at most one tick on an idle
        // channel and returns at once when a client writes or drains:
        // `pipe_info` is kept for the binding checks, off this path.
        let count = io.len();
        for step in 0..count {
            let channel = (next + step) % count;
            if !server.active(channel) {
                continue;
            }
            // Stream the reply while the client keeps draining it: the pipe
            // holds four transfers, and every wait here ends the moment the
            // client reads. A tick without room means it is not reading.
            while io[channel].pending() {
                let this = &mut io[channel];
                let end = (this.sent + MAX_TRANSFER).min(this.output.len());
                match absd_runtime::write_within(this.reply, &this.output[this.sent..end], 1) {
                    Ok(count) if count > 0 => {
                        this.sent += count;
                        progress = true;
                    }
                    Ok(_) | Err(ERROR_TIMEOUT) => break,
                    // No reader left: the client is gone with its reply.
                    Err(_) => {
                        this.output = Vec::new();
                        this.sent = 0;
                    }
                }
            }
            if io[channel].pending() {
                continue;
            }
            if !io[channel].output.is_empty() {
                // Sent whole: the buffer goes back to the allocator for any
                // channel's next reply, instead of each channel keeping its
                // last (a 64 KiB read's reply per channel, otherwise).
                io[channel].output = Vec::new();
                io[channel].sent = 0;
            }
            let this = &mut io[channel];
            // Take the request whole while the client is still writing it.
            // `quiet`: the pipe had nothing more for a tick.
            let mut quiet = false;
            while this.inbox.wants_more() {
                let mut chunk = [0u8; MAX_TRANSFER];
                match absd_runtime::read_within(this.request, &mut chunk, 1) {
                    Ok(0) if channel == CONTROL => {
                        // End of file: sshd, the only holder of the control
                        // channel's client end, is gone.
                        let commits = server.fs.write_stats().commits;
                        // The server's own fact for the next generation's
                        // ledger: it reached its orderly end. It rides the
                        // final commit; if that fails nothing is cleared.
                        if let Err(e) = recovery::stopped(&mut server.fs, &boot_id) {
                            log.say(&mut server, &format!("FSD RECOVERY STOPPED FACT FAILED {e:?}"));
                        }
                        log.say(&mut server, &format!("FSD STOPPED served={served} commits={commits}"));
                        match server.sync() {
                            Ok(()) => {
                                std::process::exit(0);
                            }
                            Err(e) => fatal(&format!("final commit: {e:?}")),
                        }
                    }
                    // A bound slot always has a writer (sshd keeps one).
                    Ok(0) => break,
                    Ok(count) => {
                        this.inbox.push(&chunk[..count]);
                        progress = true;
                    }
                    Err(ERROR_TIMEOUT) => {
                        quiet = true;
                        break;
                    }
                    Err(code) => fatal(&format!("request read {code}")),
                }
            }
            let mut taken = this.inbox.take();
            if taken == Taken::Nothing && quiet {
                // Quiet with a frame not all here: if it is a dead
                // holder's, the next holder's whole frame is behind it.
                this.inbox.idle();
                taken = this.inbox.take();
            }
            match taken {
                Taken::Nothing => {
                    // A released channel is read until whatever its
                    // session left behind has gone: each whole request
                    // sent while the binding was live is answered
                    // (refused). Once it is quiet, what remains can never
                    // complete (a dead holder's part of a frame) and is
                    // dropped, so the channel settles.
                    if quiet && server.draining(channel) {
                        this.inbox.discard();
                        server.clock(absd_runtime::ticks(), wall_clock);
                        if server.settle(channel, state(this)) {
                            report_capacity(&server, &boot);
                        }
                    }
                }
                Taken::Frame { seq, body } => {
                    // The binding checks look at every channel's pipes.
                    let lookup = |index: usize| io.get(index).and_then(state);
                    let now = absd_runtime::ticks();
                    server.clock(now, wall_clock);
                    let mut reply = server.dispatch(channel, &body, &lookup, now);
                    // The reply carries its request's sequence word, so
                    // the holder that asked can tell it from a reply to
                    // an earlier holder of the channel.
                    proto::stamp_seq(&mut reply, seq);
                    served += 1;
                    for index in std::mem::take(&mut server.resets) {
                        reset(&mut io[index]);
                    }
                    io[channel].output = reply;
                    io[channel].sent = 0;
                    let events = std::mem::take(&mut server.events);
                    report(&mut server, &mut log, events, qualification_exit_on_notice);
                    if server.fs.poisoned() {
                        fatal("filesystem poisoned by a device failure");
                    }
                    progress = true;
                    // Serve this client again first: it is about to read
                    // its reply and most likely send another request. But
                    // not for longer than `HOT_TICKS` in a row: then the
                    // round robin goes on, or a client that never pauses
                    // would keep every other channel (sshd's control
                    // channel included) from ever being looked at.
                    let now = absd_runtime::ticks();
                    next = match hot {
                        Some((last, since)) if last == channel && now >= since + HOT_TICKS => {
                            hot = None;
                            (channel + 1) % count
                        }
                        Some((last, _)) if last == channel => channel,
                        _ => {
                            hot = Some((channel, now));
                            channel
                        }
                    };
                    break;
                }
            }
        }
        if let Err(e) = server.idle_commit(absd_runtime::ticks()) {
            fatal(&format!("commit: {e:?}"));
        }
        if !progress {
            next = (next + 1) % io.len();
        }
    }
}
