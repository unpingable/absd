#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! Plain-text, bounded journal inspection. A slow stdout never owns the collector.
use absd_fsd::journal::{FILE_LIMIT, FILES, Record};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const USAGE: &str = "usage: logs [--volatile] [--list-boots|--sources|--health] [-b 0|-1|all|BOOT] [-u SOURCE] [-p 0..7] [--since TICKS] [--after SEQ] [-n COUNT] [-f] [--export|--raw-file PATH]";

#[derive(Default)]
struct Options {
    help: bool,
    boot: Option<String>,
    source: Option<String>,
    priority: Option<u8>,
    since: u64,
    after: u64,
    lines: usize,
    follow: bool,
    volatile: bool,
    boots: bool,
    sources: bool,
    health: bool,
    export: bool,
    raw_file: Option<PathBuf>,
}
fn parse(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut o = Options {
        lines: 50,
        ..Default::default()
    };
    let mut args = args;
    while let Some(a) = args.next() {
        match a.as_str(){
        "--list-boots"=>o.boots=true,"--sources"=>o.sources=true,"--health"=>o.health=true,
        "-f"|"--follow"=>o.follow=true,"--volatile"=>o.volatile=true,"--export"=>o.export=true,
        "-b"|"--boot"=>o.boot=Some(args.next().ok_or("missing boot")?),
        "-u"|"--service"|"--source"=>o.source=Some(args.next().ok_or("missing service")?),
        "-p"|"--priority"=>{let p=args.next().ok_or("missing priority")?.parse::<u8>().map_err(|_|"invalid priority")?;if p>7{return Err("priority must be 0..7".into())}o.priority=Some(p)},
        "--since"=>o.since=args.next().ok_or("missing ticks")?.parse().map_err(|_|"invalid ticks")?,
        "--after"=>o.after=args.next().ok_or("missing sequence")?.parse().map_err(|_|"invalid sequence")?,
        "-n"=>{o.lines=args.next().ok_or("missing count")?.parse().map_err(|_|"invalid count")?;if o.lines>10000{return Err("count exceeds 10000".into())}},
        "--raw-file"=>o.raw_file=Some(args.next().ok_or("missing output file")?.into()),
        "-h"|"--help"=>{o.help=true;return Ok(o)},
        _=>return Err(format!("unknown option {a}")),
    }
    }
    if let Some(b) = &o.boot {
        if !["0", "-1", "all"].contains(&b.as_str())
            && !(b.len() == 32
                && b.bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)))
        {
            return Err("boot must be 0, -1, all, or 32 lowercase hex digits".into());
        }
    }
    if o.raw_file.is_some() && o.follow {
        return Err("--raw-file does not follow".into());
    }
    Ok(o)
}
fn read_limit(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut out)?;
    Ok(out)
}
enum HealthRead {
    Sample(Vec<u8>),
    Unavailable(String),
}
// Only VERSION is bounded here. After admission, ordinary sample I/O may
// still wait if the server stalls; --volatile never uses that path.
fn read_health(path: &Path) -> io::Result<HealthRead> {
    #[cfg(target_os = "absd")]
    if let Err(refusal) = absd_runtime::fsd::check_server_within(0, false, 1000) {
        return Ok(HealthRead::Unavailable(refusal.line()));
    }
    read_limit(path, 2048).map(HealthRead::Sample)
}
fn acquire(root: &Path) -> io::Result<Vec<Record>> {
    let mut records = Vec::new();
    let mut found = false;
    for f in FILES {
        match read_limit(&root.join(f), FILE_LIMIT) {
            Ok(data) => {
                found = true; // Refuse partial last record after interrupted write.
                for raw in data.split_inclusive(|b| *b == b'\n') {
                    if raw.last() == Some(&b'\n') {
                        if let Some(r) = Record::parse(raw) {
                            records.push(r);
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    if !found {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no retained journal; use dmesg for the independent volatile route",
        ));
    }
    Ok(records)
}
fn boot_id(records: &[Record], asked: Option<&str>) -> Option<[u8; 32]> {
    match asked.unwrap_or("0") {
        "all" => None,
        "0" => records.last().map(|r| r.boot),
        "-1" => {
            let current = records.last()?.boot;
            records
                .iter()
                .rev()
                .find(|r| r.boot != current)
                .map(|r| r.boot)
        }
        id => records.iter().find(|r| r.boot.as_slice() == id.as_bytes()).map(|r| r.boot),
    }
}
fn retained_boot(records: &[Record], asked: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    if asked == Some("all") { return Ok(None); }
    match boot_id(records, asked) {
        Some(id) => Ok(Some(id)),
        None if asked.is_none() => Ok(None), // Existing empty journal, no selected identity yet.
        None => Err(match asked {
            Some("-1") => "no previous boot retained".into(),
            Some("0") => "no current boot retained".into(),
            _ => "requested boot is not retained".into(),
        }),
    }
}
fn validate_volatile_boot(boot: [u8; 32], asked: Option<&str>) -> io::Result<()> {
    match asked.unwrap_or("0") {
        "0" | "all" => Ok(()),
        id if id.as_bytes() == boot => Ok(()),
        "-1" => Err(io::Error::new(io::ErrorKind::InvalidInput, "previous boot unavailable in volatile mode; current boot only")),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "requested boot unavailable in volatile mode; current boot only")),
    }
}
fn validate_health_selection(data: &[u8], records: &[Record], boot: Option<[u8; 32]>) -> Result<(), String> {
    // Journal::health emits fixed metadata before its final error= field.
    // Debug-formatted error detail is opaque text, never metadata to select.
    let Some(end) = data.windows(b" error=".len()).position(|s| s == b" error=") else {
        return Err("collector-health metadata unavailable for explicit boot selection".into());
    };
    let metadata = &data[..end];
    let header: Vec<_> = metadata.split(|b| b.is_ascii_whitespace()).collect();
    let fields: Vec<_> = header.iter().filter_map(|field| field.strip_prefix(b"boot=")).collect();
    if !metadata.starts_with(b"journal boot=") || header.len() != 16
        || !header[2].starts_with(b"collector_pid=") || metadata.contains(&b'\n')
        || fields.len() != 1 || !records.iter().any(|r| r.boot.as_slice() == fields[0] && boot.is_none_or(|wanted| r.boot == wanted)) {
        return Err("no collector-health snapshot retained for the selected boot".into());
    }
    Ok(())
}

fn selected(r: &Record, o: &Options, boot: Option<[u8; 32]>) -> bool {
    boot.is_none_or(|b| r.boot == b)
        && r.ticks >= o.since
        && r.sequence > o.after
        && o.priority.is_none_or(|p| r.severity <= p)
        && o.source
            .as_ref()
            .is_none_or(|s| r.source == *s || r.source == format!("service.{s}"))
}
const CURRENT_HEALTH_UNKNOWN: &str = "Current collector persistence, errors, and consecutive-unproductive count are unknown.\ncurrent_liveness=unknown current_persistence=unknown current_error=unknown current_consecutive_unproductive=unknown\n";
fn health_snapshot(data: &[u8]) -> String {
    let mut out = String::from(CURRENT_HEALTH_UNKNOWN);
    let data = data.strip_suffix(b"\n").unwrap_or(data);
    if data.is_empty() {
        out.push_str("No retained collector sample is available.");
        return out;
    }
    out.push_str("Last retained collector sample (historical, not current health):\n");
    if let Ok(text) = std::str::from_utf8(data)
        && let Some(text) = text.strip_prefix("journal ")
    {
        // Error is the producer's final field and may contain spaces and
        // metadata-looking text. Scope it as a whole; never parse its detail.
        let (fields, error) = if let Some(error) = text.strip_prefix("error=") {
            ("", Some(error))
        } else {
            text.split_once(" error=")
                .map_or((text, None), |(a, b)| (a, Some(b)))
        };
        for field in fields.split(' ').filter(|s| !s.is_empty()) {
            let field = if let Some(pid) = field.strip_prefix("collector_pid=") {
                let pid = if pid == "None" {
                    "unknown"
                } else {
                    pid.strip_prefix("Some(")
                        .and_then(|s| s.strip_suffix(')'))
                        .filter(|n| n.parse::<u64>().is_ok_and(|v| v.to_string() == *n))
                        .unwrap_or(pid)
                };
                format!("collector_pid={pid}")
            } else {
                field.to_owned()
            };
            if !field.starts_with("sample_") {
                out.push_str("sample_");
            }
            out.push_str(&absd_fsd::journal::escape_text(field.as_bytes()));
            out.push(' ');
        }
        if let Some(error) = error {
            out.push_str("sample_error=");
            out.push_str(&absd_fsd::journal::escape_text(if error == "None" {
                b"none"
            } else {
                error.as_bytes()
            }));
        }
    } else {
        out.push_str("sample_raw=");
        out.push_str(&absd_fsd::journal::escape_text(data));
    }
    out
}
#[derive(Debug, PartialEq, Eq)]
enum SupervisorState {
    Retrying,
    Collected,
    Exhausted,
    Quarantined,
    Unconfirmed,
}
impl SupervisorState {
    fn description(&self) -> &'static str {
        match self {
            Self::Retrying => "was retrying",
            Self::Collected => "had collected and synced new records",
            Self::Exhausted => "had stopped after exhausting crash replacements",
            Self::Quarantined => "had quarantined an unconfirmed child",
            Self::Unconfirmed => "had stopped replacement with unconfirmed child custody",
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Retrying => "retrying",
            Self::Collected => "collected",
            Self::Exhausted => "exhausted",
            Self::Quarantined => "quarantined",
            Self::Unconfirmed => "unconfirmed",
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SupervisorObservation {
    boot: [u8; 32],
    sequence: u64,
    ticks: u64,
    pid: u64,
    count: Option<u32>,
    retry_ticks: Option<u64>,
    state: SupervisorState,
}
pub(crate) fn supervisor_record(record: &Record) -> Option<SupervisorObservation> {
    // INFERRED/LOSS records do not carry init's typed lifecycle attribution.
    if record.source != "service.logd" || record.flags & (8 | 16) != 0 {
        return None;
    }
    let text = record.message.strip_prefix("pid=")?;
    let (pid, body) = text.split_once(" stream=lifecycle ")?;
    let pid = pid.parse().ok()?;
    let terminal = if body
        == "Logging stopped after four crash replacements. Volatile diagnostics remain available."
    {
        Some(SupervisorState::Exhausted)
    } else if body
        == "Logger child is quarantined. Replacement and raw-handle actions are stopped; cleanup remains unconfirmed."
        || body.starts_with("Logger exact wait refused.")
        || body
            == "Logger child identity remains unconfirmed. Cleanup refused; retained raw handle will not be used."
    {
        Some(SupervisorState::Quarantined)
    } else if body == "Logger child identity is unconfirmed. Automatic replacement is stopped."
        || body == "logd identity unavailable and reap unconfirmed; automatic replacement stopped"
    {
        Some(SupervisorState::Unconfirmed)
    } else {
        None
    };
    if let Some(state) = terminal {
        return Some(SupervisorObservation {
            boot: record.boot,
            sequence: record.sequence,
            ticks: record.ticks,
            pid,
            count: None,
            retry_ticks: None,
            state,
        });
    }
    let (state, body) = if let Some(body) = body.strip_prefix("Logging is retrying. ") {
        (SupervisorState::Retrying, body)
    } else {
        (
            SupervisorState::Collected,
            body.strip_prefix("Logging collected and synced new records. ")?,
        )
    };
    let mut fields = body.split(' ');
    let count = fields
        .next()?
        .strip_prefix("consecutive_unproductive=")?
        .parse()
        .ok()?;
    fields
        .next()?
        .strip_prefix("crash_restarts=")?
        .parse::<u8>()
        .ok()?;
    let retry_ticks = fields.next()?.strip_prefix("retry_ticks=")?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    Some(SupervisorObservation {
        boot: record.boot,
        sequence: record.sequence,
        ticks: record.ticks,
        pid,
        count: Some(count),
        retry_ticks: Some(retry_ticks),
        state,
    })
}
/// One finite current-boot ring snapshot, even under concurrent producers.
fn supervisor_observation(
    mut read: impl FnMut() -> io::Result<ViewRead>,
) -> io::Result<Option<SupervisorObservation>> {
    let mut end = None;
    let mut latest = None;
    for _ in 0..256 {
        let read = read()?;
        let fence = *end.get_or_insert(read.end);
        if let Some(record) = read.record
            && record.sequence < fence
            && let Some(observation) = supervisor_record(&record)
        {
            latest = Some(observation);
        }
        if read.next >= fence {
            return Ok(latest);
        }
    }
    Err(io::Error::other(
        "supervisor observation window did not end",
    ))
}
fn supervisor_summary(observation: Option<&SupervisorObservation>) -> String {
    match observation {
        None => "No retained supervisor count was observed; current count remains unknown.".into(),
        Some(o) => format!(
            "Latest retained supervisor observation: logging {}.\nobserved_state={} observed_consecutive_unproductive={} observed_count_scope=retained_current_boot_attempts observed_boot={} observed_sequence={} observed_ticks={} observed_subject_pid={} observed_retry_ticks={}",
            o.state.description(),
            o.state.name(),
            o.count
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".into()),
            std::str::from_utf8(&o.boot).unwrap_or("invalid"),
            o.sequence,
            o.ticks,
            o.pid,
            o.retry_ticks
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".into())
        ),
    }
}
fn selected_supervisor_summary(observation: Option<&SupervisorObservation>, boot: Option<[u8; 32]>) -> String {
    if observation.is_some_and(|o| boot.is_some_and(|boot| o.boot != boot)) {
        return "Supervisor observation unavailable for the selected boot; current count remains unknown.".into();
    }
    supervisor_summary(observation)
}
#[cfg(target_os = "absd")]
fn current_boot_supervisor_observation() -> io::Result<Option<SupervisorObservation>> {
    let raw = absd_runtime::boot_id()
        .map_err(|e| io::Error::other(format!("boot identity refused: {e}")))?;
    let boot: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let boot: [u8; 32] = boot
        .as_bytes()
        .try_into()
        .map_err(|_| io::Error::other("boot identity length"))?;
    let mut cursor = absd_runtime::kernel_log::Cursor::new();
    supervisor_observation(|| {
        let read = absd_runtime::kernel_log::read(&mut cursor)
            .map_err(|e| io::Error::other(format!("supervisor observation refused: {e}")))?;
        let record = read.record.map(|r| Record {
            boot,
            sequence: r.sequence,
            ticks: r.ticks.unwrap_or(0),
            severity: r.severity,
            source: String::from_utf8_lossy(r.source()).into_owned(),
            kernel_sequence: Some(r.sequence),
            flags: r.flags as u64,
            message: absd_fsd::journal::escape_text(r.text()),
        });
        Ok(ViewRead {
            record,
            next: read.next,
            oldest: read.oldest,
            end: read.end,
            lost: read.lost,
            producer_dropped: read.producer_dropped,
        })
    })
}

fn run(o: Options) -> Result<(), Box<dyn std::error::Error>> {
    if o.volatile {
        return volatile(&o);
    }
    run_retained(o, Path::new("/var/log/journal"), Path::new("/var/log/journal-health"), &mut io::stdout())
}
fn run_retained_health(o: &Options, root: &Path, data: io::Result<HealthRead>, display: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    run_retained_health_observed(o, root, data, display, || {
        #[cfg(target_os = "absd")]
        { current_boot_supervisor_observation() }
        #[cfg(not(target_os = "absd"))]
        { Ok(None) }
    })
}
fn run_retained_health_observed(o: &Options, root: &Path, data: io::Result<HealthRead>, display: &mut dyn Write,
    supervisor: impl FnOnce() -> io::Result<Option<SupervisorObservation>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let selected_boot = if o.boot.is_some() {
        let bytes = match &data {
            Ok(HealthRead::Sample(bytes)) => bytes,
            Ok(HealthRead::Unavailable(reason)) => return Err(io::Error::other(format!("collector-health unavailable for explicit boot selection: {reason}")).into()),
            Err(_) => return Err(data.err().unwrap().into()),
        };
        let records = acquire(root)?;
        let boot = retained_boot(&records, o.boot.as_deref())?;
        validate_health_selection(bytes, &records, boot)?;
        boot
    } else { None };
    let mut display = DisplayWriter(display);
    // Acquired-input errors stay primary even when the display also closes.
    let output: io::Result<()> = (|| {
        match &data {
            Ok(HealthRead::Sample(bytes)) => writeln!(display, "{}", health_snapshot(bytes))?,
            Ok(HealthRead::Unavailable(reason)) => {
                write!(display, "{CURRENT_HEALTH_UNKNOWN}")?;
                writeln!(display, "Retained sample unavailable: {}", absd_fsd::journal::escape_text(reason.as_bytes()))?;
            }
            Err(error) => {
                write!(display, "{CURRENT_HEALTH_UNKNOWN}")?;
                writeln!(display, "Retained sample unavailable: {}", absd_fsd::journal::escape_text(error.to_string().as_bytes()))?;
            }
        }
        match supervisor() {
            Ok(observation) => writeln!(display, "{}", selected_supervisor_summary(observation.as_ref(), selected_boot))?,
            Err(error) => writeln!(display,
                "Supervisor observation unavailable; current count remains unknown. {}",
                absd_fsd::journal::escape_text(error.to_string().as_bytes())
            )?,
        }
        display.flush()
    })();
    if let Err(error) = data { return Err(error.into()); }
    output?;
    Ok(())
}
fn run_retained(o: Options, root: &Path, health_path: &Path, display: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    if o.health {
        return run_retained_health(&o, root, read_health(health_path), display);
    }
    let mut display = DisplayWriter(display);
    let mut records = acquire(root)?;
    // Without a selector, list-boots continues to enumerate all retained IDs.
    let boot = if o.boots && o.boot.is_none() { None } else { retained_boot(&records, o.boot.as_deref())? };
    if o.boots {
        let mut seen = BTreeSet::new();
        for r in &records {
            if boot.is_none_or(|b| r.boot == b) && seen.insert(r.boot) {
                writeln!(display, "{}", std::str::from_utf8(&r.boot)?)?;
            }
        }
        return Ok(());
    }
    if o.sources {
        let mut sources = BTreeSet::new();
        for r in &records {
            if selected(r, &o, boot) {
                sources.insert(r.source.clone());
            }
        }
        for s in sources {
            writeln!(display, "{s}")?
        }
        return Ok(());
    }
    let mut output: Box<dyn Write + '_> = match &o.raw_file {
        // Decoded application bytes are written only to a new explicit file,
        // never interpreted by the terminal and never over an existing object.
        Some(p) => Box::new(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(p)?,
        ),
        None => Box::new(display),
    };
    let mut cursors = BTreeMap::<[u8; 32], u64>::new();
    let mut first_pass = true;
    loop {
        let chosen: Vec<_> = records.iter().filter(|r| selected(r, &o, boot)).collect();
        let start = if first_pass && !o.export && o.raw_file.is_none() {
            chosen.len().saturating_sub(o.lines)
        } else {
            0
        };
        for r in &chosen[start..] {
            let cursor = cursors.get(&r.boot).copied().unwrap_or(o.after);
            if r.sequence <= cursor {
                continue;
            }
            if cursors.contains_key(&r.boot)
                && r.sequence > cursor.saturating_add(1)
                && o.source.is_none()
                && o.priority.is_none()
            {
                eprintln!(
                    "logs: retained sequence gap {}..{} (rotation/suppression/restart)",
                    cursor.saturating_add(1),
                    r.sequence - 1
                );
            }
            if o.raw_file.is_some() {
                output.write_all(
                    &absd_fsd::journal::decode_text(&r.message).ok_or("invalid escaped message")?,
                )?;
                output.write_all(b"\n")?;
            } else {
                output.write_all(&r.encode())?;
            }
            cursors.insert(r.boot, r.sequence);
        }
        output.flush()?;
        first_pass = false;
        if !o.follow {
            return Ok(());
        }
        #[cfg(target_os = "absd")]
        absd_runtime::sleep_ticks(250);
        #[cfg(not(target_os = "absd"))]
        std::thread::sleep(std::time::Duration::from_millis(250));
        records = acquire(root)?;
    }
}
struct ViewRead {
    record: Option<Record>,
    next: u64,
    oldest: u64,
    end: u64,
    lost: u64,
    producer_dropped: u64,
}
fn finish_volatile_initial(
    o: &Options,
    buffer: &mut std::collections::VecDeque<Record>,
    sources: &BTreeSet<String>,
    truncated: u64,
    out: &mut dyn Write,
    notices: &mut dyn Write,
) -> io::Result<()> {
    if truncated > 0 {
        writeln!(
            notices,
            "logs: volatile view truncated initial={truncated} (recent display limit)"
        )?;
    }
    if o.sources {
        for source in sources {
            writeln!(out, "{source}")?;
        }
    } else {
        while let Some(record) = buffer.pop_front() {
            out.write_all(&record.encode())?;
        }
    }
    out.flush()
}
/// Freeze the initial end sequence. Export streams that finite window;
/// follow streams every later record directly, with no hidden recent cap.
fn volatile_view(
    boot: [u8; 32],
    mut acquire: impl FnMut() -> io::Result<ViewRead>,
    mut idle: impl FnMut(),
    o: &Options,
    out: &mut dyn Write,
    notices: &mut dyn Write,
) -> io::Result<()> {
    validate_volatile_boot(boot, o.boot.as_deref())?;
    let mut out = DisplayWriter(out);
    if o.boots {
        writeln!(out, "{} volatile current boot", std::str::from_utf8(&boot).map_err(io::Error::other)?)?;
        return Ok(());
    }
    let mut fence = None;
    let mut initial = true;
    let mut buffer = std::collections::VecDeque::new();
    let mut sources = BTreeSet::new();
    let mut truncated = 0u64;
    loop {
        let read = acquire()?;
        let end = *fence.get_or_insert(read.end);
        if read.lost > 0 {
            writeln!(
                notices,
                "logs: volatile gap lost={} producer_dropped={}",
                read.lost, read.producer_dropped
            )?;
        }
        if o.health {
            writeln!(
                out,
                "volatile next={} oldest={} end={} producer_dropped={}",
                read.next, read.oldest, read.end, read.producer_dropped
            )?;
            return Ok(());
        }
        if initial && read.record.as_ref().is_some_and(|r| r.sequence >= end) {
            finish_volatile_initial(o, &mut buffer, &sources, truncated, &mut out, notices)?;
            initial = false;
            if !o.follow || o.sources {
                return Ok(());
            }
        }
        let empty = read.record.is_none();
        if let Some(record) = read.record {
            if selected(&record, o, Some(boot)) {
                if o.sources {
                    sources.insert(record.source.clone());
                } else if initial && !o.export {
                    buffer.push_back(record);
                    if buffer.len() > o.lines {
                        buffer.pop_front();
                        truncated = truncated.saturating_add(1);
                    }
                } else {
                    out.write_all(&record.encode())?;
                    out.flush()?;
                }
            }
        }
        if initial && (read.next >= end || empty) {
            finish_volatile_initial(o, &mut buffer, &sources, truncated, &mut out, notices)?;
            initial = false;
            if !o.follow || o.sources {
                return Ok(());
            }
        }
        if empty {
            out.flush()?;
            idle();
        }
    }
}
#[cfg(target_os = "absd")]
fn volatile(o: &Options) -> Result<(), Box<dyn std::error::Error>> {
    use absd_runtime::kernel_log::{self, Cursor};
    if o.raw_file.is_some() {
        return Err(
            "--raw-file requires retained history; use --export for safe volatile text".into(),
        );
    }
    let raw = absd_runtime::boot_id().map_err(|e| format!("boot identity: {e}"))?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let boot: [u8; 32] = hex.as_bytes().try_into()?;
    eprintln!(
        "logs: volatile independent kernel/service ring; bounded retention; persistent sink not consulted"
    );
    let mut cursor = Cursor::new();
    volatile_view(
        boot,
        || {
            let read = loop {
                match kernel_log::read(&mut cursor) {
                    Ok(read) => break read,
                    Err(-11) => absd_runtime::sleep_ticks(1),
                    Err(e) => {
                        return Err(io::Error::other(format!("volatile reader refused: {e}")));
                    }
                }
            };
            let record = read.record.map(|r| Record {
                boot,
                sequence: r.sequence,
                ticks: r.ticks.unwrap_or(0),
                severity: r.severity,
                source: String::from_utf8_lossy(r.source()).into_owned(),
                kernel_sequence: Some(r.sequence),
                flags: r.flags as u64,
                message: absd_fsd::journal::escape_text(r.text()),
            });
            Ok(ViewRead {
                record,
                next: read.next,
                oldest: read.oldest,
                end: read.end,
                lost: read.lost,
                producer_dropped: read.producer_dropped,
            })
        },
        || absd_runtime::sleep_ticks(250),
        o,
        &mut io::stdout(),
        &mut io::stderr(),
    )?;
    Ok(())
}
#[cfg(not(target_os = "absd"))]
fn volatile(_o: &Options) -> Result<(), Box<dyn std::error::Error>> {
    Err("volatile ring requires ABSD".into())
}

#[derive(Debug)]
struct ClosedOutput(io::Error);
impl std::fmt::Display for ClosedOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}
impl std::error::Error for ClosedOutput {}

// Tag errors where display bytes leave the query, rather than at individual
// print calls. Acquisition, notices and explicit file exports do not use this
// writer, so their errors cannot be mistaken for a closed stdout consumer.
struct DisplayWriter<W>(W);
impl<W: Write> Write for DisplayWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        stdout_result(self.0.write(bytes))
    }
    fn flush(&mut self) -> io::Result<()> {
        stdout_result(self.0.flush())
    }
}
// Only stdout writes gain this private marker. Acquisition and explicit-file
// errors (even BrokenPipe) must remain visible failures, not pipeline closure.
fn stdout_result<T>(result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| {
        if error.kind() == io::ErrorKind::BrokenPipe { io::Error::new(io::ErrorKind::BrokenPipe, ClosedOutput(error)) }
        else { error }
    })
}
fn is_closed_output(error: &(dyn std::error::Error + 'static)) -> bool {
    error.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe && e.get_ref().is_some_and(|cause| cause.is::<ClosedOutput>()))
}

fn main() {
    #[cfg(target_os = "absd")]
    absd_runtime::link_anchor();
    match parse(std::env::args().skip(1)) {
        Ok(o) => {
            let result = if o.help {
                writeln!(DisplayWriter(io::stdout()), "{USAGE}").map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            } else { run(o) };
            if let Err(e) = result {
                if is_closed_output(e.as_ref()) { return; }
                eprintln!("logs: {e}");
                std::process::exit(1)
            }
        }
        Err(e) => {
            eprintln!("logs: {e}");
            std::process::exit(2)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn human_health_formats_the_actual_producer_without_changing_its_sample() {
        let mut journal = absd_fsd::journal::Journal::new(*b"0123456789abcdef0123456789abcdef");
        journal.collector_pid = Some(4);
        journal.sample_ticks = 1;
        let stored = journal.health();
        assert!(stored.contains("collector_pid=Some(4)"));
        assert!(stored.contains("error=None"));
        let output = health_snapshot(stored.as_bytes());
        assert!(output.contains(" sample_collector_pid=4 "));
        assert!(output.ends_with(" sample_error=none"));
        assert!(output.contains("sample_ticks=1"));
        assert!(output.contains("current_liveness=unknown"));
        assert!(output.contains("sample_persistence=volatile"));
        assert_eq!(journal.health(), stored);
        journal.collector_pid = None;
        assert!(health_snapshot(journal.health().as_bytes()).contains(" sample_collector_pid=unknown "));
    }
    #[test]
    fn human_health_keeps_real_error_details_as_whole_recorded_values() {
        for (error, expected) in [
            (absd_fs::Error::NoSpace, "sample_error=Some(NoSpace)"),
            (absd_fs::Error::Device(-110), "sample_error=Some(Device(-110))"),
            (
                absd_fs::Error::Corrupt("bad directory"),
                "sample_error=Some(Corrupt(\"bad directory\"))",
            ),
        ] {
            let mut journal = absd_fsd::journal::Journal::new(*b"0123456789abcdef0123456789abcdef");
            journal.sink_error = Some(error);
            let stored = journal.health();
            assert!(health_snapshot(stored.as_bytes()).ends_with(expected));
            assert_eq!(journal.health(), stored);
        }
    }
    #[test]
    fn human_health_preserves_unknown_and_malformed_values_as_observations() {
        for (input, expected) in [
            (
                "collector_pid=Some(nope) error=Some(FutureFault)",
                "sample_collector_pid=Some(nope) sample_error=Some(FutureFault)",
            ),
            (
                "collector_pid=Some(+4) error=Some(None)",
                "sample_collector_pid=Some(+4) sample_error=Some(None)",
            ),
            (
                "collector_pid=Some(4 error=Some(NoSpace",
                "sample_collector_pid=Some(4 sample_error=Some(NoSpace",
            ),
            (
                "collector_pid=unknown error=unknown",
                "sample_collector_pid=unknown sample_error=unknown",
            ),
            (
                "error=Some(Corrupt(\"bad\\q\"))",
                "error=Some(Corrupt(\"bad\\x5cq\"))",
            ),
            ("error=Some(Device(+5))", "error=Some(Device(+5))"),
            (
                "error=Some(Corrupt(\"bad\\u{110000}\"))",
                "error=Some(Corrupt(\"bad\\x5cu{110000}\"))",
            ),
            (
                "sample_ticks=1 persistence=written",
                "sample_ticks=1 sample_persistence=written ",
            ),
        ] {
            let output = health_snapshot(format!("journal {input}\n").as_bytes());
            assert!(output.ends_with(expected), "{output}");
            assert!(output.starts_with(
                "Current collector persistence, errors, and consecutive-unproductive count are unknown."
            ));
        }
        let output = health_snapshot(b"journal collector_pid=None error=Some(Corrupt(\"collector_pid=Some(9) error=None\"))\n");
        assert!(output.ends_with(
            "sample_collector_pid=unknown sample_error=Some(Corrupt(\"collector_pid=Some(9) error=None\"))"
        ));
        assert!(
            health_snapshot(b"journal error=Some(NoSpace)\xff\n")
                .ends_with("error=Some(NoSpace)\\xff")
        );
    }
    #[test]
    fn human_health_does_not_relabel_error_details_as_metadata() {
        let mut journal = absd_fsd::journal::Journal::new(*b"0123456789abcdef0123456789abcdef");
        journal.sink_error = Some(absd_fs::Error::Corrupt("old persistence=written (x)"));
        let output = health_snapshot(journal.health().as_bytes());
        assert!(output.contains(" sample_persistence=volatile "));
        assert!(output.ends_with("sample_error=Some(Corrupt(\"old persistence=written (x)\"))"));
        journal.sink_error = Some(absd_fs::Error::Corrupt("quote\" slash\\ control\u{1b}"));
        let output = health_snapshot(journal.health().as_bytes());
        assert!(
            output.ends_with("sample_error=Some(Corrupt(\"quote\\x5c\" slash\\x5c\\x5c control\\x5cu{1b}\"))"),
            "{output}"
        );
        assert!(output.contains("sample_error=Some(Corrupt"));
        assert!(!output.as_bytes().contains(&0x1b));
    }
    #[test]
    fn human_health_fallback_preserves_invalid_utf8_error_detail() {
        let output = health_snapshot(b"journal persistence=volatile error=Some(Corrupt(\"old persistence=written (x)\"))\xff\n");
        assert_eq!(output, "Current collector persistence, errors, and consecutive-unproductive count are unknown.\ncurrent_liveness=unknown current_persistence=unknown current_error=unknown current_consecutive_unproductive=unknown\nLast retained collector sample (historical, not current health):\nsample_raw=journal persistence=volatile error=Some(Corrupt(\"old persistence=written (x)\"))\\xff");
    }
    #[test]
    fn human_health_fallback_preserves_unknown_sample_verbatim() {
        let output = health_snapshot(b"future-health error=Some(Corrupt(\"old persistence=written (x)\"))\n");
        assert_eq!(output, "Current collector persistence, errors, and consecutive-unproductive count are unknown.\ncurrent_liveness=unknown current_persistence=unknown current_error=unknown current_consecutive_unproductive=unknown\nLast retained collector sample (historical, not current health):\nsample_raw=future-health error=Some(Corrupt(\"old persistence=written (x)\"))");
    }
    #[test]
    fn retained_health_does_not_assert_a_live_collector() {
        let output = health_snapshot(
            b"journal collector_pid=Some(44) counter_scope=collector_generation persistence=written sink_lost=0\x1b\n",
        );
        assert!(output.contains("liveness=unknown"));
        assert!(output.contains("counter_scope=collector_generation"));
        assert!(output.contains("sample_persistence=written"));
        assert!(!output.contains(" persistence=written"));
        assert!(!output.as_bytes().contains(&0x1b));
    }
    #[test]
    fn flags_and_filter_are_the_actual_query_boundary() {
        let o = parse(
            ["-u", "sshd", "-p", "3", "--since", "50", "--after", "4"]
                .into_iter()
                .map(str::to_string),
        )
        .unwrap();
        let mut r=Record::parse(b"J1 0123456789abcdef0123456789abcdef 5 50 3 service.sshd 1 0 pid=8 stream=stderr fail\n").unwrap();
        assert!(selected(&r, &o, Some(r.boot)));
        r.source = "kernel".into();
        r.message = "service.sshd forged".into();
        assert!(!selected(&r, &o, Some(r.boot)));
        assert!(parse(["--priority", "8"].into_iter().map(str::to_string)).is_err());
    }
    #[test]
    fn bounded_reader_ignores_partial_tail_and_resolves_previous_boot() {
        let root = std::env::temp_dir().join(format!("absd-logs-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("previous"),
            b"J1 0123456789abcdef0123456789abcdef 1 1 3 service.fsd 1 0 previous\n",
        )
        .unwrap();
        std::fs::write(
            root.join("current"),
            b"J1 fedcba9876543210fedcba9876543210 1 2 6 service.sshd 2 0 current\nJ1 partial",
        )
        .unwrap();
        let records = acquire(&root).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            boot_id(&records, Some("-1")),
            Some(*b"0123456789abcdef0123456789abcdef")
        );
        std::fs::remove_file(root.join("current")).unwrap();
        std::fs::remove_file(root.join("previous")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    fn record(n: u64) -> Record {
        Record {
            boot: *b"0123456789abcdef0123456789abcdef",
            sequence: n,
            ticks: n,
            severity: 6,
            source: "service.sshd".into(),
            kernel_sequence: Some(n),
            flags: 0,
            message: format!("message{n}"),
        }
    }
    #[test]
    fn volatile_export_streams_every_record_in_the_initial_window() {
        let options = Options {
            export: true,
            lines: 2,
            ..Default::default()
        };
        let mut n = 0u64;
        let mut output = Vec::new();
        let mut notices = Vec::new();
        volatile_view(
            record(1).boot,
            || {
                n += 1;
                Ok(ViewRead {
                    record: Some(record(n)),
                    next: n + 1,
                    oldest: 1,
                    end: 301,
                    lost: 0,
                    producer_dropped: 0,
                })
            },
            || {},
            &options,
            &mut output,
            &mut notices,
        )
        .unwrap();
        assert_eq!(
            output
                .split(|b| *b == b'\n')
                .filter(|b| !b.is_empty())
                .count(),
            300
        );
        assert!(notices.is_empty());
        assert_eq!(n, 300);
    }
    #[test]
    fn volatile_follow_caps_only_initial_display_and_announces_that_truncation() {
        let options = Options {
            follow: true,
            lines: 2,
            ..Default::default()
        };
        let mut n = 0u64;
        let mut output = Vec::new();
        let mut notices = Vec::new();
        let result = volatile_view(
            record(1).boot,
            || {
                n += 1;
                if n > 203 {
                    return Err(io::Error::other("fixture end"));
                }
                Ok(ViewRead {
                    record: Some(record(n)),
                    next: n + 1,
                    oldest: 1,
                    end: if n <= 3 { 4 } else { 204 },
                    lost: 0,
                    producer_dropped: 0,
                })
            },
            || {},
            &options,
            &mut output,
            &mut notices,
        );
        assert!(result.is_err());
        let records: Vec<_> = output
            .split(|b| *b == b'\n')
            .filter_map(Record::parse)
            .collect();
        assert_eq!(records.len(), 202);
        assert_eq!(records.first().unwrap().sequence, 2);
        assert_eq!(records.last().unwrap().sequence, 203);
        assert_eq!(
            String::from_utf8(notices).unwrap(),
            "logs: volatile view truncated initial=1 (recent display limit)\n"
        );
    }
    #[test]
    fn absent_previous_and_explicit_boot_do_not_fabricate_identity() {
        let records = [record(1)];
        assert!(boot_id(&records, Some("-1")).is_none());
        assert!(boot_id(&records, Some("ffffffffffffffffffffffffffffffff")).is_none());
    }
    #[test]
    fn volatile_unavailable_selector_is_rejected_before_output_in_every_view() {
        for mode in ["records", "health", "sources", "boots"] {
            for requested in ["-1", "ffffffffffffffffffffffffffffffff"] {
                let options = Options { volatile: true, boot: Some(requested.into()), health: mode == "health", sources: mode == "sources", boots: mode == "boots", ..Default::default() };
                let mut out = Vec::new();
                let mut notices = Vec::new();
                let mut reads = 0;
                let result = volatile_view(record(1).boot, || { reads += 1; Ok(ViewRead { record: Some(record(1)), next: 2, oldest: 1, end: 2, lost: 0, producer_dropped: 0 }) }, || {}, &options, &mut out, &mut notices);
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput, "{mode} silently accepted {requested}");
                assert_eq!(reads, 0, "invalid selector must fail before acquisition");
                assert!(out.is_empty(), "{mode} emitted data from the wrong boot");
            }
        }
    }
    #[test]
    fn help_is_a_successful_parse_request() {
        assert!(parse(["--help".to_string()].into_iter()).is_ok());
    }

    fn retained_fixture() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!("absd-logs-select-{}-{}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("current"), record(1).encode()).unwrap();
        std::fs::write(root.join("health"), absd_fsd::journal::Journal::new(record(1).boot).health()).unwrap();
        root
    }
    #[test]
    fn retained_missing_selection_errors_in_actual_queries_before_output_or_export() {
        let root = retained_fixture();
        for mode in ["records", "sources", "boots", "health"] {
            for requested in ["-1", "ffffffffffffffffffffffffffffffff"] {
                let raw = root.join("must-not-create");
                let options = Options { boot: Some(requested.into()), sources: mode == "sources", boots: mode == "boots", health: mode == "health", raw_file: (mode == "records").then_some(raw.clone()), ..Default::default() };
                let mut output = Vec::new();
                let error = run_retained(options, &root, &root.join("health"), &mut output).unwrap_err();
                assert!(error.to_string().contains(if requested == "-1" { "no previous boot retained" } else { "not retained" }));
                assert!(output.is_empty());
                assert!(!raw.exists());
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn known_boot_empty_filter_is_success_and_exports_keep_exact_j1() {
        let root = retained_fixture();
        let id = "0123456789abcdef0123456789abcdef";
        let mut output = Vec::new();
        let filtered = Options { boot: Some(id.into()), source: Some("absent".into()), ..Default::default() };
        run_retained(filtered, &root, &root.join("health"), &mut output).unwrap();
        assert!(output.is_empty());
        let exact = Options { boot: Some(id.into()), export: true, ..Default::default() };
        run_retained(exact, &root, &root.join("health"), &mut output).unwrap();
        assert_eq!(output, b"J1 0123456789abcdef0123456789abcdef 1 1 6 service.sshd 1 0 message1\n");
        let raw_path = root.join("raw");
        run_retained(Options { boot: Some(id.into()), raw_file: Some(raw_path.clone()), ..Default::default() }, &root, &root.join("health"), &mut Vec::new()).unwrap();
        assert_eq!(std::fs::read(raw_path).unwrap(), b"message1\n");
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn retained_previous_lists_and_health_cannot_alias_current_snapshot() {
        let root = retained_fixture();
        let mut previous = record(2);
        previous.boot = *b"fedcba9876543210fedcba9876543210";
        std::fs::write(root.join("previous"), previous.encode()).unwrap();
        let mut output = Vec::new();
        run_retained(Options { boots: true, ..Default::default() }, &root, &root.join("health"), &mut output).unwrap();
        assert_eq!(output, b"fedcba9876543210fedcba9876543210\n0123456789abcdef0123456789abcdef\n");
        output.clear();
        run_retained(Options { boots: true, boot: Some("-1".into()), ..Default::default() }, &root, &root.join("health"), &mut output).unwrap();
        assert_eq!(output, b"fedcba9876543210fedcba9876543210\n");
        output.clear();
        assert!(run_retained(Options { health: true, boot: Some("-1".into()), ..Default::default() }, &root, &root.join("health"), &mut output).unwrap_err().to_string().contains("no collector-health snapshot"));
        assert!(output.is_empty());
        run_retained(Options { health: true, boot: Some("0".into()), ..Default::default() }, &root, &root.join("health"), &mut output).unwrap();
        assert!(String::from_utf8(output).unwrap().contains("boot=0123456789abcdef0123456789abcdef"));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn volatile_valid_selectors_remain_current_boot_scoped_in_every_view() {
        let boot = record(1).boot;
        for asked in [None, Some("0"), Some("all"), Some("0123456789abcdef0123456789abcdef")] {
            for mode in ["records", "health", "sources", "boots"] {
                let options = Options { volatile: true, export: true, boot: asked.map(str::to_owned), health: mode == "health", sources: mode == "sources", boots: mode == "boots", ..Default::default() };
                let mut output = Vec::new();
                volatile_view(boot, || Ok(ViewRead { record: Some(record(1)), next: 2, oldest: 1, end: 2, lost: 0, producer_dropped: 0 }), || {}, &options, &mut output, &mut Vec::new()).unwrap();
                assert!(!output.is_empty());
                if mode == "records" { assert_eq!(output, b"J1 0123456789abcdef0123456789abcdef 1 1 6 service.sshd 1 0 message1\n"); }
            }
        }
        let mut foreign = record(1); foreign.boot = *b"ffffffffffffffffffffffffffffffff";
        let mut output = Vec::new();
        volatile_view(boot, || Ok(ViewRead { record: Some(foreign.clone()), next: 2, oldest: 1, end: 2, lost: 0, producer_dropped: 0 }), || {}, &Options { export: true, boot: Some("all".into()), ..Default::default() }, &mut output, &mut Vec::new()).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn actual_retained_query_closed_output_is_typed_broken_pipe_only() {
        let root = retained_fixture();
        let (reader, mut writer) = std::io::pipe().unwrap();
        drop(reader);
        let error = run_retained(Options { export: true, ..Default::default() }, &root, &root.join("health"), &mut writer).unwrap_err();
        assert!(is_closed_output(error.as_ref()));
        let mut readonly = File::open("/dev/null").unwrap();
        let other = run_retained(Options { export: true, ..Default::default() }, &root, &root.join("health"), &mut readonly).unwrap_err();
        assert!(!is_closed_output(other.as_ref()));
        assert!(!is_closed_output(&io::Error::new(io::ErrorKind::BrokenPipe, "input acquisition failed")));
        let input_error = volatile_view(record(1).boot, || Err(io::Error::new(io::ErrorKind::BrokenPipe, "reader failed")), || {}, &Options::default(), &mut Vec::new(), &mut Vec::new()).unwrap_err();
        assert!(!is_closed_output(&input_error));
        assert!(!is_closed_output(&io::Error::other("Broken pipe")));
        assert!(!is_closed_output(&io::Error::new(io::ErrorKind::PermissionDenied, "denied")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn actual_health_producer_error_detail_cannot_change_selected_boot() {
        let record = record(1);
        let mut journal = absd_fsd::journal::Journal::new(record.boot);
        journal.sink_error = Some(absd_fs::Error::Corrupt("detail boot=ffffffffffffffffffffffffffffffff collector_pid=Some(999)"));
        let sample = journal.health();
        validate_health_selection(sample.as_bytes(), &[record.clone()], Some(record.boot)).unwrap();
    }

    #[test]
    fn malformed_or_wrong_health_sample_cannot_satisfy_explicit_selection() {
        let r = record(1);
        let good = absd_fsd::journal::Journal::new(r.boot).health();
        for bad in [Vec::new(), b"unknown boot=0123456789abcdef0123456789abcdef error=None".to_vec(), b"journal boot=0123456789abcdef0123456789abcdef collector_pid=None".to_vec(), good.replace("journal boot=", "journal boot=bad extra=").into_bytes(), good.replace(" sample_ticks=", " boot=ffffffffffffffffffffffffffffffff sample_ticks=").into_bytes()] {
            assert!(validate_health_selection(&bad, &[r.clone()], Some(r.boot)).is_err());
        }
        let wrong = absd_fsd::journal::Journal::new(*b"ffffffffffffffffffffffffffffffff").health();
        assert!(validate_health_selection(wrong.as_bytes(), &[r.clone()], Some(r.boot)).is_err());
    }
    #[test]
    fn default_health_remains_independent_of_retained_journal() {
        let root = retained_fixture();
        std::fs::remove_file(root.join("current")).unwrap();
        let mut output = Vec::new();
        run_retained(Options { health: true, ..Default::default() }, &root, &root.join("health"), &mut output).unwrap();
        assert!(String::from_utf8(output).unwrap().contains("Last retained collector sample (historical, not current health):"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn default_health_actual_input_failure_is_visible_and_not_an_empty_sample() {
        let root = retained_fixture();
        std::fs::remove_file(root.join("health")).unwrap();
        std::fs::create_dir(root.join("health")).unwrap();
        let mut output = Vec::new();
        let result = run_retained(Options { health: true, ..Default::default() }, &root, &root.join("health"), &mut output);
        std::fs::remove_dir_all(&root).unwrap();
        let error = result.unwrap_err();
        assert!(!is_closed_output(error.as_ref()));
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("Current collector persistence, errors, and consecutive-unproductive count are unknown."));
        assert!(text.contains("Retained sample unavailable:"));
        assert!(text.contains("current count remains unknown"));
        assert!(!text.contains("No retained collector sample is available."));
    }

    #[test]
    fn optional_health_refusal_is_partial_unknown_and_cannot_select_history() {
        let root = retained_fixture();
        let o = Options { health: true, ..Default::default() };
        let mut output = Vec::new();
        run_retained_health(&o, &root, Ok(HealthRead::Unavailable("version refused\nreason".into())), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with(CURRENT_HEALTH_UNKNOWN));
        assert!(text.contains("Retained sample unavailable: version refused\\x0areason"));
        assert!(text.contains("current count remains unknown"));
        assert!(!text.contains("No retained collector sample is available."));
        assert!(!text.contains("Last retained collector sample"));
        for boot in ["0", "-1", "all", "0123456789abcdef0123456789abcdef"] {
            let mut output = Vec::new();
            let options = Options { health: true, boot: Some(boot.into()), ..Default::default() };
            let error = run_retained_health(&options, &root, Ok(HealthRead::Unavailable("refused".into())), &mut output).unwrap_err();
            assert!(error.to_string().contains("unavailable for explicit boot selection"));
            assert!(output.is_empty());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn acquired_empty_health_is_distinct_from_refusal_and_input_error() {
        let root = retained_fixture();
        std::fs::write(root.join("health"), []).unwrap();
        let mut output = Vec::new();
        run_retained(Options { health: true, ..Default::default() }, &root, &root.join("health"), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("No retained collector sample is available."));
        assert!(!text.contains("Retained sample unavailable:"));
        let mut output = Vec::new();
        assert!(run_retained(Options { health: true, boot: Some("0".into()), ..Default::default() }, &root, &root.join("health"), &mut output).is_err());
        assert!(output.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn health_input_error_remains_primary_when_actual_display_pipe_closes() {
        let root = retained_fixture();
        for boot in [None, Some("0")] {
            let (reader, mut writer) = std::io::pipe().unwrap();
            drop(reader);
            let o = Options { health: true, boot: boot.map(str::to_owned), ..Default::default() };
            let error = run_retained_health(&o, &root, Err(io::Error::new(io::ErrorKind::BrokenPipe, "actual acquisition boundary")), &mut writer).unwrap_err();
            assert!(!is_closed_output(error.as_ref()));
            assert_eq!(error.to_string(), "actual acquisition boundary");
        }
        let (reader, mut writer) = std::io::pipe().unwrap();
        drop(reader);
        let error = run_retained_health(&Options { health: true, ..Default::default() }, &root, Ok(HealthRead::Unavailable("refused".into())), &mut writer).unwrap_err();
        assert!(is_closed_output(error.as_ref()));
        std::fs::remove_dir_all(root).unwrap();
    }

    // A real reader closing must be classified the same way in every view;
    // a missing annotation on any stdout branch breaks this contract.
    #[test]
    fn closed_consumer_is_quiet_in_every_volatile_view() {
        for view in ["records", "health", "sources", "boots"] {
            let (reader, mut writer) = std::io::pipe().unwrap();
            drop(reader);
            let options = Options { export: true, health: view == "health", sources: view == "sources", boots: view == "boots", ..Default::default() };
            let error = volatile_view(record(1).boot, || Ok(ViewRead { record: Some(record(1)), next: 2, oldest: 1, end: 2, lost: 0, producer_dropped: 0 }), || {}, &options, &mut writer, &mut Vec::new()).unwrap_err();
            assert!(is_closed_output(&error), "{view}: closed stdout reported as a failure: {error}");
        }
    }

    #[test]
    fn closed_consumer_is_quiet_in_every_retained_view() {
        let root = retained_fixture();
        for view in ["records", "health", "sources", "boots"] {
            let (reader, mut writer) = std::io::pipe().unwrap();
            drop(reader);
            let options = Options { export: true, health: view == "health", sources: view == "sources", boots: view == "boots", ..Default::default() };
            let error = run_retained(options, &root, &root.join("health"), &mut writer).unwrap_err();
            assert!(is_closed_output(error.as_ref()), "{view}: {error}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn buffered_display_flush_keeps_closed_consumer_origin() {
        let root = retained_fixture();
        for health in [false, true] {
            let (reader, writer) = std::io::pipe().unwrap();
            drop(reader);
            let mut buffered = std::io::BufWriter::new(writer);
            let error = run_retained(Options { export: !health, health, ..Default::default() }, &root, &root.join("health"), &mut buffered).unwrap_err();
            assert!(is_closed_output(error.as_ref()));
        }
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut buffered = std::io::BufWriter::new(writer);
        let error = run_retained_health(&Options { health: true, ..Default::default() }, &root, Ok(HealthRead::Unavailable("refused".into())), &mut buffered).unwrap_err();
        assert!(is_closed_output(error.as_ref()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn input_and_notice_pipe_errors_are_not_quiet_output_closure() {
        let options = Options { health: true, ..Default::default() };
        let error = volatile_view(record(1).boot, || Err(io::Error::new(io::ErrorKind::BrokenPipe, "input ended")), || {}, &options, &mut Vec::new(), &mut Vec::new()).unwrap_err();
        assert!(!is_closed_output(&error));
        let (reader, mut notices) = std::io::pipe().unwrap();
        drop(reader);
        let error = volatile_view(record(1).boot, || Ok(ViewRead { record: None, next: 2, oldest: 1, end: 2, lost: 1, producer_dropped: 0 }), || {}, &options, &mut Vec::new(), &mut notices).unwrap_err();
        assert!(!is_closed_output(&error));
    }

    #[test]
    fn invalid_selector_and_explicit_file_errors_survive_closed_stdout() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        drop(reader);
        let options = Options { boot: Some("-1".into()), health: true, ..Default::default() };
        let error = volatile_view(record(1).boot, || panic!("invalid selector acquired data"), || {}, &options, &mut writer, &mut Vec::new()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!is_closed_output(&error));
        let root = retained_fixture();
        let options = Options { raw_file: Some(root.join("current")), ..Default::default() };
        let error = run_retained(options, &root, &root.join("health"), &mut writer).unwrap_err();
        assert!(!is_closed_output(error.as_ref()));
        assert_eq!(std::fs::read(root.join("current")).unwrap(), record(1).encode());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn other_stdout_errors_remain_failures_in_every_view() {
        let root = retained_fixture();
        for view in ["records", "health", "sources", "boots"] {
            let options = || Options { export: true, health: view == "health", sources: view == "sources", boots: view == "boots", ..Default::default() };
            let mut read_only = File::open("/dev/null").unwrap();
            let error = volatile_view(record(1).boot, || Ok(ViewRead { record: Some(record(1)), next: 2, oldest: 1, end: 2, lost: 0, producer_dropped: 0 }), || {}, &options(), &mut read_only, &mut Vec::new()).unwrap_err();
            assert!(!is_closed_output(&error), "volatile {view}");
            let error = run_retained(options(), &root, &root.join("health"), &mut read_only).unwrap_err();
            assert!(!is_closed_output(error.as_ref()), "retained {view}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

}

#[cfg(test)]
mod round3_health_regression {
    use super::*;
    #[test]
    fn an_old_healthy_sample_cannot_claim_current_persistence_errors_or_retry_count() {
        let output=health_snapshot(b"journal boot=old collector_pid=Some(9) sample_ticks=1 pending=0 persistence=written written=7 flushed=7 error=None\n");
        assert!(output.starts_with(
            "Current collector persistence, errors, and consecutive-unproductive count are unknown."
        ));
        assert!(output.contains("sample_error=none"));
        assert!(!output.contains(" error=None"));
        assert!(output.contains("sample_persistence=written"));
    }
}

#[cfg(test)]
mod supervisor_health_tests {
    use super::*;
    fn record(seq: u64, text: &str) -> Record {
        Record {
            boot: *b"0123456789abcdef0123456789abcdef",
            sequence: seq,
            ticks: seq * 10,
            severity: 5,
            source: "service.logd".into(),
            kernel_sequence: Some(seq),
            flags: 0,
            message: text.into(),
        }
    }
    #[test]
    fn old_healthy_file_and_new_retry_observation_keep_current_state_unknown() {
        let sample = health_snapshot(
            b"journal boot=old collector_pid=Some(9) pending=0 persistence=written error=None\n",
        );
        assert!(sample.contains("current_consecutive_unproductive=unknown"));
        assert!(sample.contains("sample_boot=old sample_collector_pid=9"));
        assert!(sample.contains("sample_error=none"));
        let record = record(
            44,
            "pid=1 stream=lifecycle Logging is retrying. consecutive_unproductive=17 crash_restarts=1 retry_ticks=60000",
        );
        let observation = supervisor_record(&record).unwrap();
        let summary = supervisor_summary(Some(&observation));
        assert!(summary.contains("observed_consecutive_unproductive=17"));
        assert!(summary.contains("observed_count_scope=retained_current_boot_attempts"));
        assert!(summary.contains("observed_sequence=44 observed_ticks=440"));
        assert!(summary.contains("observed_boot=0123456789abcdef0123456789abcdef"));
    }
    #[test]
    fn selected_history_cannot_display_an_observation_from_a_different_boot() {
        let observed = supervisor_record(&record(44, "pid=1 stream=lifecycle Logging is retrying. consecutive_unproductive=17 crash_restarts=1 retry_ticks=60000")).unwrap();
        for boot in [None, Some(observed.boot)] {
            assert!(selected_supervisor_summary(Some(&observed), boot).contains("observed_consecutive_unproductive=17"));
        }
        let text = selected_supervisor_summary(Some(&observed), Some(*b"fedcba9876543210fedcba9876543210"));
        assert!(text.contains("Supervisor observation unavailable for the selected boot; current count remains unknown."));
        assert!(!text.contains("observed_boot="));
    }
    #[test]
    fn lifecycle_attribution_and_exact_count_grammar_are_required() {
        for text in [
            "pid=1 stream=stdout Logging is retrying. consecutive_unproductive=3 crash_restarts=0 retry_ticks=4000",
            "pid=1 stream=lifecycle Logging is retrying. consecutive_unproductive=4294967296 crash_restarts=0 retry_ticks=1",
            "pid=1 stream=lifecycle Logging is retrying. consecutive_unproductive=3 crash_restarts=0 retry_ticks=4000 extra=1",
        ] {
            assert!(supervisor_record(&record(1, text)).is_none());
        }
        let mut inferred = record(
            1,
            "pid=1 stream=lifecycle Logging is retrying. consecutive_unproductive=3 crash_restarts=0 retry_ticks=4000",
        );
        inferred.flags = 8;
        assert!(supervisor_record(&inferred).is_none());
        let collected = record(
            2,
            "pid=1 stream=lifecycle Logging collected and synced new records. consecutive_unproductive=0 crash_restarts=1 retry_ticks=0",
        );
        assert_eq!(supervisor_record(&collected).unwrap().count, Some(0));
    }
    #[test]
    fn finite_snapshot_does_not_treat_newer_records_or_unavailable_ring_as_current_health() {
        let mut index = 0;
        let observed=supervisor_observation(|| {index+=1;Ok(ViewRead {record:Some(record(index,"pid=1 stream=lifecycle Logging is retrying. consecutive_unproductive=3 crash_restarts=0 retry_ticks=4000")),next:index+1,oldest:1,end:if index==1 {3} else {100},lost:0,producer_dropped:0})}).unwrap().unwrap();
        assert_eq!(observed.sequence, 2);
        assert_eq!(index, 2);
        assert!(supervisor_observation(|| Err(io::Error::other("grant refused"))).is_err());
        assert!(health_snapshot(b"").starts_with("Current collector"));
        assert!(
            health_snapshot(b"journal error=Some(Corrupt(\"error=None pending=0\"))\n")
                .contains("sample_error=Some(Corrupt(\"error=None pending=0\"))")
        );
    }
}

#[cfg(test)]
mod round4_terminal_regression {
    use super::*;
    #[test]
    fn terminal_supervisor_records_replace_old_retry_or_collected_observation() {
        for body in [
            "Logging stopped after four crash replacements. Volatile diagnostics remain available.",
            "Logger exact wait refused. Child identity is unconfirmed; other children will still be reaped. Replacement and raw-handle actions are stopped.",
        ] {
            let record = Record {
                boot: *b"0123456789abcdef0123456789abcdef",
                sequence: 100,
                ticks: 1000,
                severity: 3,
                source: "service.logd".into(),
                kernel_sequence: Some(100),
                flags: 0,
                message: format!("pid=1 stream=lifecycle {body}"),
            };
            assert!(
                supervisor_record(&record).is_some(),
                "latest terminal observation must not be ignored"
            );
        }
    }
}

#[cfg(test)]
mod terminal_order_tests {
    use super::*;
    #[test]
    fn a_later_terminal_state_replaces_retrying_with_no_invented_count() {
        for (body, expected) in [
            (
                "Logging stopped after four crash replacements. Volatile diagnostics remain available.",
                "exhausted",
            ),
            (
                "Logger child is quarantined. Replacement and raw-handle actions are stopped; cleanup remains unconfirmed.",
                "quarantined",
            ),
            (
                "Logger child identity is unconfirmed. Automatic replacement is stopped.",
                "unconfirmed",
            ),
        ] {
            let mut n = 0;
            let observation=supervisor_observation(|| {n+=1;let message=if n==1 {"Logging is retrying. consecutive_unproductive=60 crash_restarts=1 retry_ticks=60000"} else {body};Ok(ViewRead {record:Some(Record {boot:*b"0123456789abcdef0123456789abcdef",sequence:n,ticks:n*100,severity:3,source:"service.logd".into(),kernel_sequence:Some(n),flags:0,message:format!("pid=1 stream=lifecycle {message}")}),next:n+1,oldest:1,end:3,lost:0,producer_dropped:0})}).unwrap().unwrap();
            let summary = supervisor_summary(Some(&observation));
            assert!(summary.contains(&format!("observed_state={expected}")));
            assert!(summary.contains("observed_consecutive_unproductive=unknown"));
            assert!(!summary.contains("was retrying"));
            assert_eq!(observation.sequence, 2);
        }
    }
}

#[cfg(test)]
mod root_composition_controls {
    use super::*;
    fn run_retained_observed(o: Options, root: &Path, health_path: &Path, display: &mut dyn Write,
        supervisor: impl FnOnce() -> io::Result<Option<SupervisorObservation>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        run_retained_health_observed(&o, root, read_health(health_path), display, supervisor)
    }
    fn fixture() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!("absd-client-compose-{}-{}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::create_dir(&root).unwrap();
        let r = event("Logging is retrying. consecutive_unproductive=7 crash_restarts=1 retry_ticks=4000");
        std::fs::write(root.join("current"), r.encode()).unwrap();
        std::fs::write(root.join("health"), absd_fsd::journal::Journal::new(r.boot).health()).unwrap();
        root
    }
    fn event(body: &str) -> Record {
        Record { boot: *b"0123456789abcdef0123456789abcdef", sequence: 9, ticks: 90,
            severity: 5, source: "service.logd".into(), kernel_sequence: Some(9), flags: 0,
            message: format!("pid=1 stream=lifecycle {body}") }
    }
    fn options(boot: Option<&str>) -> Options {
        Options { health: true, boot: boot.map(str::to_owned), ..Default::default() }
    }
    #[test]
    fn matching_current_and_all_selectors_preserve_every_supervisor_state() {
        let root = fixture();
        for (body, expected) in [
            ("Logging is retrying. consecutive_unproductive=7 crash_restarts=1 retry_ticks=4000", "retrying"),
            ("Logging collected and synced new records. consecutive_unproductive=0 crash_restarts=1 retry_ticks=0", "collected"),
            ("Logging stopped after four crash replacements. Volatile diagnostics remain available.", "exhausted"),
            ("Logger child is quarantined. Replacement and raw-handle actions are stopped; cleanup remains unconfirmed.", "quarantined"),
            ("Logger child identity is unconfirmed. Automatic replacement is stopped.", "unconfirmed"),
        ] {
            for selector in [None, Some("0"), Some("all"), Some("0123456789abcdef0123456789abcdef")] {
                let mut out = Vec::new();
                run_retained_observed(options(selector), &root, &root.join("health"), &mut out, || Ok(supervisor_record(&event(body)))).unwrap();
                let out = String::from_utf8(out).unwrap();
                assert!(out.contains(&format!("observed_state={expected}")), "{out}");
                assert!(out.contains("observed_boot=0123456789abcdef0123456789abcdef"));
                assert!(out.contains("current_consecutive_unproductive=unknown"));
                if ["exhausted", "quarantined", "unconfirmed"].contains(&expected) {
                    assert!(out.contains("observed_consecutive_unproductive=unknown"));
                }
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn previous_health_never_borrows_current_supervisor_state() {
        let root = fixture(); let old = *b"fedcba9876543210fedcba9876543210";
        let mut r = event("ignored"); r.boot = old;
        std::fs::write(root.join("previous"), r.encode()).unwrap();
        let mut out = Vec::new();
        // An available current sample cannot satisfy an explicit previous query.
        let error = run_retained_observed(options(Some("-1")), &root, &root.join("health"), &mut out, || panic!("mismatched sample queried supervisor")).unwrap_err();
        assert!(error.to_string().contains("no collector-health snapshot")); assert!(out.is_empty());
        std::fs::write(root.join("health"), absd_fsd::journal::Journal::new(old).health()).unwrap();
        run_retained_observed(options(Some("-1")), &root, &root.join("health"), &mut out, || Ok(supervisor_record(&event("Logging stopped after four crash replacements. Volatile diagnostics remain available.")))).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("sample_boot=fedcba9876543210fedcba9876543210"));
        assert!(out.contains("Supervisor observation unavailable for the selected boot"));
        assert!(!out.contains("observed_state=")); assert!(!out.contains("observed_boot="));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn missing_sample_and_unavailable_supervisor_preserve_default_unknown() {
        let root = fixture(); std::fs::remove_file(root.join("health")).unwrap();
        let mut out = Vec::new();
        let error = run_retained_observed(options(None), &root, &root.join("health"), &mut out, || Err(io::Error::new(io::ErrorKind::BrokenPipe, "reader ended"))).unwrap_err();
        assert_eq!(error.downcast_ref::<io::Error>().unwrap().kind(), io::ErrorKind::NotFound);
        assert!(!is_closed_output(error.as_ref()));
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("No retained collector sample is available."));
        assert!(out.contains("Retained sample unavailable:"));
        assert!(out.contains("Supervisor observation unavailable; current count remains unknown. reader ended"));
        let error = run_retained_observed(options(Some("0")), &root, &root.join("health"), &mut Vec::new(), || panic!("missing explicit sample queried supervisor")).unwrap_err();
        assert_eq!(error.downcast_ref::<io::Error>().unwrap().kind(), io::ErrorKind::NotFound);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn real_pipes_cover_missing_sample_and_late_supervisor_output() {
        let root = fixture();
        let (reader, mut writer) = io::pipe().unwrap(); drop(reader);
        let error = run_retained_observed(options(None), &root, &root.join("absent"), &mut writer, || panic!("closed sample display queried supervisor")).unwrap_err();
        assert!(!is_closed_output(error.as_ref()));
        assert_eq!(error.downcast_ref::<io::Error>().unwrap().kind(), io::ErrorKind::NotFound);
        struct CloseOnSupervisor { reader: Option<io::PipeReader>, writer: io::PipeWriter, closed: bool }
        impl Write for CloseOnSupervisor {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if bytes.starts_with(b"Latest retained supervisor observation:") {
                    self.reader.take(); self.closed = true;
                }
                self.writer.write(bytes)
            }
            fn flush(&mut self) -> io::Result<()> { self.writer.flush() }
        }
        let (reader, writer) = io::pipe().unwrap();
        let mut out = CloseOnSupervisor { reader: Some(reader), writer, closed: false };
        let error = run_retained_observed(options(None), &root, &root.join("health"), &mut out, || Ok(supervisor_record(&event("Logging is retrying. consecutive_unproductive=7 crash_restarts=1 retry_ticks=4000")))).unwrap_err();
        assert!(out.closed); assert!(is_closed_output(error.as_ref()));
        let mut readonly = File::open("/dev/null").unwrap();
        let error = run_retained_observed(options(None), &root, &root.join("absent"), &mut readonly, || Ok(None)).unwrap_err();
        assert!(!is_closed_output(error.as_ref()));
        std::fs::remove_dir_all(root).unwrap();
    }
}
