// The ABSD body of `absd-fsd` (see `fsd_main.rs`).

use absd_fs::{Error, Fs, Kind, OpenFlags};
use absd_fsd::log::{self as logfile, LogFile};
use absd_fsd::proto::{self, Mount};
use absd_fsd::recovery;
use absd_fsd::{readiness, write_guard};
use absd_fsd::{CONTROL, Event, Inbox, PipeState, Server, Taken};
use absd_runtime::fsd::pipe_info;
use absd_runtime::storage::{self, RegionDevice};

mod service_journal;

const SEED_PATH: &[u8] = b"/ssh/host_ed25519_seed";
const SEED_STAGING: &[u8] = b"/ssh/host_ed25519_seed.new";
const ERROR_TIMEOUT: i64 = -110;
const MAX_TRANSFER: usize = 256;

fn fatal(message: &str) -> ! {
    eprintln!("FSD FAILED {message}");
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

/// Software civil seconds for `mtime`; `None` when the kernel has no time.
fn wall_clock() -> Option<u64> {
    absd_runtime::wall_clock_seconds().ok()
}

fn refresh_civil_clock(server:&mut Server<RegionDevice>,ticks:u64) {
    match absd_runtime::civil_clock::info() {
        Ok(info)=>{
            let seconds=info.unix_ns.map(|ns|ns/1_000_000_000);
            if seconds.is_some(){server.observe_clock_generation(info.generation);}else{server.forget_clock();}
            server.clock(ticks,||seconds);
        },
        // Old kernel: preserve its original bounded raw RTC read behavior.
        Err(-38)=>server.clock(ticks,wall_clock),
        Err(_)=>{server.forget_clock();server.clock(ticks,||None);},
    }
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
    quiet: readiness::Quiet,
    request_ended: bool,
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

/// Local VM controls a qualification boot sets on the command line; a
/// normal boot sets neither, and neither adds a protocol operation.
#[derive(Clone, Copy)]
struct QualificationControls {
    /// `--qualification-exit-on-notice`: exit on the NOTICE
    /// `FSD QUALIFICATION EXIT`.
    exit_on_notice: bool,
    /// `--qualification-hang-on-notice`: spin on the NOTICE
    /// `FSD QUALIFICATION HANG`.
    hang_on_notice: bool,
}

fn report(server: &mut Server<RegionDevice>, log: &mut Log, events: Vec<Event>, qualification: QualificationControls) {
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
                if qualification.exit_on_notice && text.as_slice() == b"FSD QUALIFICATION EXIT" {
                    // Local VM control: retire the file server while sshd is
                    // waiting for the NOTICE reply. Normal boots never set
                    // the flag, and no protocol operation is added.
                    println!("FSD QUALIFICATION EXIT status=7");
                    std::process::exit(7);
                }
                if qualification.hang_on_notice && text.as_slice() == b"FSD QUALIFICATION HANG" {
                    // Local VM control: stop making progress while sshd is
                    // waiting for the NOTICE reply. The spin is in user
                    // mode, so the process stays live and runnable and
                    // never beats its liveness cell again: init's liveness
                    // judgment, not a process exit, has to end it (kernel
                    // docs/service-lifecycle-20261008/LIVENESS.md). Normal
                    // boots never set the flag.
                    println!("FSD QUALIFICATION HANG kind=spin");
                    loop {
                        std::hint::spin_loop();
                    }
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
    let heap_free_pages = absd_runtime::heap_free_pooled_pages();
    // Sample outside println: never log while holding the allocator guard.
    println!(
        "FSD CAPACITY boot={boot} settled_releases={settled_releases} fs_objects={} rotated_logs={rotated_logs} bound={bound} opens={opens} logger_opens={} draining={draining} heap_pages_peak={} heap_free_pages={heap_free_pages}",
        server.fs.object_count(),
        server.logger_opens(),
        absd_runtime::heap_mapped_pages(),
    );
}

/// Idle commits this generation timed (`FSD STATS`): how many, their
/// ticks in all, and the slowest. Commits made inside a request (namespace
/// operations, a client's sync or commit) are counted by `WriteStats` but
/// not timed here.
#[derive(Default)]
struct IdleCommits {
    count: u64,
    ticks: u64,
    max: u64,
}

/// Direct console record of what the filesystem costs this process
/// (docs/storage-sizing-20261102): the heap now and its true high-water
/// mark (`heap_peak_pages`, unlike CAPACITY's sampled `heap_pages_peak`),
/// commit totals since mount (`WriteStats`), and the block counts. At
/// `stop` it adds the idle commits' timing and the final commit's, in PIT
/// ticks (about 1 ms); at `ready` nothing has been timed, so it says
/// `timing=none`. Console only, so it writes nothing.
fn report_stats(server: &Server<RegionDevice>, phase: &str, timing: Option<(&IdleCommits, u64)>) {
    let stats = server.fs.write_stats();
    let heap_free_pages = absd_runtime::heap_free_pooled_pages();
    let timing = match timing {
        Some((idle, last)) => format!(
            "idle_commits={} idle_commit_ticks_total={} idle_commit_ticks_max={} final_commit_ticks={last}",
            idle.count, idle.ticks, idle.max
        ),
        None => String::from("timing=none"),
    };
    println!(
        "FSD STATS phase={phase} heap_pages={} heap_peak_pages={} heap_free_pages={heap_free_pages} commits={} image_bytes={} superblock_sectors={} {timing} data_blocks={} free_blocks={} fs_objects={}",
        absd_runtime::heap_mapped_pages(),
        absd_runtime::heap_mapped_pages_peak(),
        stats.commits,
        stats.image_bytes,
        stats.superblock_sectors,
        server.fs.geometry().data_blocks,
        server.fs.free_blocks(),
        server.fs.object_count(),
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
    io.quiet.reset();
    io.request_ended = false;
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
/// (absd_fsd::recovery::SERVED_COMPLETED). After a bounded diagnostic drain,
/// the fact is committed before exit 0; no client is served. Any failure exits 3
/// so the streak stays (conservative).
fn finalize(bounded: bool) -> ! {
    if !absd_runtime::has_block_device() {
        println!("FSD FINALIZE FAILED no block handle");
        std::process::exit(3);
    }
    let boot = absd_runtime::boot_id().unwrap_or_else(|code| {
        println!("FSD FINALIZE FAILED boot identity: {code}");
        std::process::exit(3);
    });
    let hex = boot.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let boot_id: recovery::Boot = hex.as_bytes().try_into().expect("32 hex digits");
    let (_, reader) = storage::mount_read_only_authority()
        .unwrap_or_else(|error| fatal(&format!("finalize read-only mount: {error:?}")));
    let mut fs = storage::take_mounted().unwrap_or_else(|| fatal("finalize read-only mount vanished"));
    write_guard::assess_finalization(&mut fs, &boot_id, bounded)
        .unwrap_or_else(|error| fatal(&format!("finalize state: {error:?}")));
    drop(fs);
    absd_runtime::close(reader).unwrap_or_else(|code| fatal(&format!("finalize reader close: {code}")));
    storage::mount(false, true).unwrap_or_else(|error| fatal(&format!("finalize mount: {error:?}")));
    let mut fs = storage::take_mounted().unwrap_or_else(|| fatal("finalize mount vanished"));
    let mut journal = service_journal::Collector::new(&mut fs, boot_id);
    journal.drain(&mut fs);
    match write_guard::finish(&mut fs, &boot_id, bounded) {
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

/// Every file-server generation assesses the durable entry guard and
/// history through a read-only block duplicate. An unclean or unknown
/// state refuses before any write or flush (docs/WRITABLE-ENTRY.md).
/// A served refusal is pre-ready and never resets the machine. This is
/// the one entry that may be admitted by an operator's resume record
/// (`Resume::Allowed`, docs/WRITABLE-ENTRY.md "Operator-authorized
/// resume"); the finalizer, enrollment and bounded updates never are.
fn refuse_unfenced_recovery() -> write_guard::Admission {
    let reader = match storage::mount_read_only_authority() {
        Ok((_, reader)) => reader,
        Err(e) => fatal(&format!("read-only mount: {e:?}")),
    };
    let mut fs = storage::take_mounted().unwrap_or_else(|| fatal("read-only mount vanished"));
    let admission = write_guard::assess(&mut fs, write_guard::Resume::Allowed).unwrap_or_else(|refusal| {
        match refusal {
            recovery::Refusal::Unfenced(previous) => println!(
                "RECOVERY WRITABLE REFUSED reason=storage_fence previous={} fence=none", previous.name()),
            recovery::Refusal::Storage(e) => println!("RECOVERY STATE REFUSED reason=storage error={e:?}"),
            other => println!("RECOVERY STATE REFUSED reason={}", other.reason()),
        }
        std::process::exit(3);
    });
    drop(fs);
    absd_runtime::close(reader).unwrap_or_else(|code| fatal(&format!("read-only handle close: {code}")));
    admission
}

fn main() {
    link_anchor();
    if std::env::args().any(|arg| arg == "--finalize") {
        finalize(false);
    }
    if std::env::args().any(|arg| arg == "--finalize-bounded") {
        finalize(true);
    }
    match absd_runtime::wait_readable(&[], absd_runtime::WAIT_READABLE_POLL) {
        Err(-22) => {} // The supported call validates the deliberately empty set.
        Err(-38) => fatal("kernel lacks wait_readable"),
        result => fatal(&format!("wait_readable support probe {result:?}")),
    }
    let regenerate = cfg!(feature = "regenerate-host-key") || std::env::args().any(|arg| arg == "--regenerate-host-key");
    let qualification = QualificationControls {
        exit_on_notice: std::env::args().any(|arg| arg == "--qualification-exit-on-notice"),
        hang_on_notice: std::env::args().any(|arg| arg == "--qualification-hang-on-notice"),
    };
    let ends = absd_runtime::server::channels();
    let logger_channel=std::env::args().find_map(|a|a.strip_prefix("--logger-channel=").map(str::to_string)).map(|s|s.parse::<usize>().unwrap_or(usize::MAX));
    if logger_channel.is_some_and(|n|n==0 || n+1!=ends.len()) {fatal("invalid private logger channel");}
    if ends.len() < 2 || !absd_runtime::has_block_device() {
        fatal("needs the block handle and at least the control channel and one slot");
    }
    // Every writable entry is assessed, including net-fsd boots without a
    // liveness cell. No caller-supplied declaration establishes a fence.
    let args: Vec<String> = std::env::args().collect();
    let fence = recovery::Fence::from_args(args.iter().map(String::as_str));
    let admission = refuse_unfenced_recovery();
    let mounted = storage::mount(false, true).unwrap_or_else(|e| match e {
        Error::UnsupportedFormat => fatal(
            "mount: UnsupportedFormat: the disk holds another filesystem format; this release \
             reads format 2 only (docs/FILESYSTEM.md); migrate the image on the host",
        ),
        e => fatal(&format!("mount: {e:?}")),
    });
    let mut fs = storage::take_mounted().unwrap_or_else(|| fatal("mount vanished"));
    // Arming is the first mutation and touches only the preallocated
    // marker sector. Charge precedes every directory, key or log write.
    write_guard::begin(&mut fs, admission)
        .unwrap_or_else(|error| fatal(&format!("writable entry: {error:?}")));
    // An entry admitted by an operator's resume record: the record was
    // consumed by `begin` as the first device write; the line is printed
    // after consumption and before charge (ACCEPTANCE-v5 predicate A), and
    // repeated into /var/log/fsd once the log exists.
    let resumed = admission.resumed().map(|record| format!(
        "RECOVERY WRITABLE RESUMED id={} previous={} fs_seq={} ledger_seq={}",
        String::from_utf8_lossy(&record.id), record.previous.name(), record.seq, record.ledger_seq));
    if let Some(line) = &resumed {
        println!("{line}");
    }
    let boot = absd_runtime::boot_id()
        .unwrap_or_else(|code| fatal(&format!("boot identity: {code}")))
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let boot_id: recovery::Boot = boot.as_bytes().try_into()
        .unwrap_or_else(|_| fatal("boot identity is not 32 hex digits"));
    let (ledger, previous) = recovery::charge(&mut fs, &boot_id)
        .unwrap_or_else(|error| fatal(&format!("recovery charge: {error:?}")));
    if previous != admission.previous { fatal("recovery changed after assessment"); }
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
        Mount::new(absd_fsd::journal::DIR, false),
        Mount::new(b"/var/log/journal-health", false),
        // The recovery ledger (absd_fsd::recovery) sshd reads but never
        // writes, and the facts directory it writes; the server refuses
        // either in any session's mount list.
        Mount::new(recovery::DIR, false),
        Mount::new(recovery::FACTS, true),
    ];
    if logger_channel.is_some() {
        if let Err(e)=ensure_dir(&mut fs,absd_fsd::journal::DIR){eprintln!("FSD JOURNAL PREPARE {e:?}");}
        for path in [b"/var/log/journal/current".as_slice(),b"/var/log/journal/current.0",b"/var/log/journal/previous",b"/var/log/journal/previous.0",b"/var/log/journal-health",b"/var/log/sshd"] {
            match fs.open(path,OpenFlags{write:true,create:true,..Default::default()}){Ok(h)=>{let _=fs.close(h);},Err(e)=>eprintln!("FSD JOURNAL PREPARE {e:?}")}
        }
    }
    let mut server = Server::new(fs, ends.len() - 1, control);
    if let Some(channel)=logger_channel {if !server.attach_logger(channel){fatal("private logger construction");}}
    let mut journal = if logger_channel.is_none(){Some(service_journal::Collector::new(&mut server.fs, boot_id))}else{None};
    let mut log = Log { file: LogFile::new(b"/var/log/fsd", "fsd") };
    log.write(&mut server, &format!("started: boot {boot}, uptime {} ms", absd_runtime::boot_millis()));
    if let Some(line) = &resumed {
        log.write(&mut server, line);
    }
    log.say(&mut server, &format!("FSD HOST KEY {key} path={}", String::from_utf8_lossy(SEED_PATH)));
    // Scratch of sessions an earlier boot's reset left bound: gone before
    // anything is served, so the baseline counts nothing of theirs and no
    // session of this boot meets it.
    refresh_civil_clock(&mut server,absd_runtime::ticks());
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
    if let Err(error) = recovery::publish_projection(&mut server.fs, &ledger) {
        log.say(&mut server, &format!("RECOVERY PROJECTION UNAVAILABLE reason=storage error={error:?}"));
    }
    log.say(
        &mut server,
        &format!("FSD RECOVERY seq={} streak={} previous={}", ledger.seq, ledger.streak, previous.name()),
    );
    // Its own line: FSD RECOVERY's fields are parsed exactly by health and
    // the harnesses. `assessed` is what the read-only check saw; it equals
    // `previous` unless the disk changed in between.
    log.say(&mut server,
        &format!("FSD STORAGE FENCE fence={} previous={} assessed={}",
            fence.name(), previous.name(), admission.previous.name()));
    let mut io: Vec<Io> = ends
        .iter()
        .map(|&(request, reply)| Io { request, reply, inbox: Inbox::new(), output: Vec::new(), sent: 0, quiet: readiness::Quiet::default(), request_ended: false })
        .collect();
    let ready_objects = server.fs.object_count();
    log.say(
        &mut server,
        &format!(
            "FSD READY channels={} slots={} fs_seq={} formatted={} fs_objects={}",
            io.len(),
            io.len() - 1 - usize::from(logger_channel.is_some()),
            mounted.sequence,
            mounted.formatted,
            ready_objects
        ),
    );
    report_capacity(&server, &boot);
    report_stats(&server, "ready", None);
    let mut idle_commits = IdleCommits::default();
    let mut served = 0u64;
    let mut next = 0usize;
    // The channel served back to back, and since which tick.
    let mut hot: Option<(usize, u64)> = None;
    let mut stopping:Option<u64>=None;
    loop {
        // One liveness beat per pass, and one more for every transfer
        // that moves bytes for a client below: a beat says the server made
        // progress. Idle requests are polled; the bounded idle wait uses argument
        // one (up to two delivered ticks), plus one idle commit. A client that
        // trickles a frame or drains a reply a few bytes at a time keeps
        // the server in the transfer loops, and those beat on progress, so
        // a beat missing for init's bound means the server stopped moving
        // (kernel docs/service-lifecycle-20261008/LIVENESS.md).
        absd_runtime::liveness_beat();
        if let Some(journal)=&mut journal {if journal.poll(&mut server.fs) { server.note_write(absd_runtime::ticks()); }}
        let mut progress = false;
        // Round robin over the channels served now, starting after the one
        // last served. Poll every request, then wait once on at most eleven
        // sources after an idle pass; omitted sources rotate each idle wait.
        // Timed reply writes still wake as the client drains. `pipe_info`
        // is kept for the binding checks, off this path.
        let count = io.len();
        for channel in readiness::round_robin(next, count) {
            if (stopping.is_some() && channel==CONTROL) || !server.active(channel) {
                continue;
            }
            // Bound transfer work too: a reader draining one byte at a time
            // must not monopolize FSD before the dispatch-level hot bound.
            let transfer_end=absd_runtime::ticks().saturating_add(HOT_TICKS);
            let mut transfers=0usize;
            // Stream the reply while the client keeps draining it: the pipe
            // holds four transfers, and every wait here ends the moment the
            // client reads. A tick without room means it is not reading.
            while io[channel].pending() && transfers<64 && absd_runtime::ticks()<transfer_end {
                transfers+=1;
                let this = &mut io[channel];
                let end = (this.sent + MAX_TRANSFER).min(this.output.len());
                match absd_runtime::write_within(this.reply, &this.output[this.sent..end], 1) {
                    Ok(count) if count > 0 => {
                        this.sent += count;
                        progress = true;
                        absd_runtime::liveness_beat();
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
            while this.inbox.wants_more() && transfers<64 && absd_runtime::ticks()<transfer_end {
                transfers+=1;
                {
                    if this.request_ended {
                        quiet = true;
                        break;
                    }
                    match absd_runtime::wait_readable(&[this.request], absd_runtime::WAIT_READABLE_POLL) {
                        Ok(0) => {
                            // An empty poll is not the old read timeout. Keep
                            // its quiet period before recovering partial frames
                            // or settling a released holder's channel.
                            quiet = this.quiet.empty(absd_runtime::ticks());
                            break;
                        }
                        Ok(_) => {}
                        Err(code) => fatal(&format!("request readiness {code}")),
                    }
                }
                let mut chunk = [0u8; MAX_TRANSFER];
                match absd_runtime::read_within(this.request, &mut chunk, 1) {
                    Ok(0) if channel == CONTROL => {
                        // Keep serving only bounded outstanding logger work;
                        // init independently closes its stop pipe on worker exit.
                        stopping.get_or_insert_with(absd_runtime::ticks);
                        break;
                    }
                    // A bound slot always has a writer (sshd keeps one).
                    Ok(0) => {
                        this.request_ended = true;
                        quiet = true;
                        break;
                    }
                    Ok(count) => {
                        this.quiet.reset();
                        this.inbox.push(&chunk[..count]);
                        progress = true;
                        absd_runtime::liveness_beat();
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
                        refresh_civil_clock(&mut server,absd_runtime::ticks());
                        if server.settle(channel, state(this)) {
                            report_capacity(&server, &boot);
                        }
                    }
                }
                Taken::Frame { seq, body } => {
                    // The binding checks look at every channel's pipes.
                    let lookup = |index: usize| io.get(index).and_then(state);
                    let now = absd_runtime::ticks();
                    refresh_civil_clock(&mut server,now);
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
                    report(&mut server, &mut log, events, qualification);
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
        if let Some(since)=stopping {
            let done=logger_channel.is_none_or(|index| {
                let pipe=pipe_info(io[index].request).ok();
                pipe.is_some_and(|p|p[3]<=1&&p[0]==0)&&io[index].inbox.is_empty()&&!io[index].pending()
            });
            if done || absd_runtime::ticks().saturating_sub(since)>=2000 {
                if !done {eprintln!("FSD JOURNAL STOP logger grace expired; final commit follows");}
                if let Some(channel)=logger_channel {server.retire_logger(channel);}

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
                        if let Some(journal)=&mut journal {journal.drain(&mut server.fs);}
                        let start = absd_runtime::ticks();
                        match server.sync() {
                            Ok(()) => {
                                let ticks = absd_runtime::ticks() - start;
                                report_stats(&server, "stop", Some((&idle_commits, ticks)));
                                std::process::exit(0);
                            }
                            Err(e) => fatal(&format!("final commit: {e:?}")),
                        }

            }
        }
        let commits = server.fs.write_stats().commits;
        let start = absd_runtime::ticks();
        if let Err(e) = server.idle_commit(start) {
            fatal(&format!("commit: {e:?}"));
        }
        if server.fs.write_stats().commits != commits {
            let ticks = absd_runtime::ticks() - start;
            idle_commits.count += 1;
            idle_commits.ticks += ticks;
            idle_commits.max = idle_commits.max.max(ticks);
        }
        if !progress {
            let wait_start = next;
            next = readiness::next_idle_start(next, io.len());
            {
                let plan = readiness::WaitPlan::collect(readiness::round_robin(wait_start, io.len()).map(|channel| {
                    let io = &io[channel];
                    readiness::Channel {
                        request: io.request,
                        active: server.active(channel) && !(stopping.is_some() && channel == CONTROL),
                        reply_pending: io.pending(),
                        buffered_work: !io.inbox.wants_more(),
                        request_ended: io.request_ended,
                    }
                }));
                if plan.buffered_work { continue; }
                if plan.handles().is_empty() {
                    // Read readiness cannot notify that a reply gained room.
                    // Preserve bounded retry for the existing timed writes.
                    absd_runtime::sleep_ticks(readiness::IDLE_TICKS);
                } else {
                    match absd_runtime::wait_readable(plan.handles(), readiness::IDLE_TICKS) {
                        Ok(_) | Err(ERROR_TIMEOUT) => {}
                        Err(code) => fatal(&format!("idle readiness {code}")),
                    }
                }
            }
        }
    }
}
