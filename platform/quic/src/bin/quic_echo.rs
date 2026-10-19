#![feature(restricted_std)]
//! A single native QUIC consumer; protocol stdout stays separate from diagnostics.

use absd_native_quic_fixture::{
    engine::{Hooks, Outcome, Phase, Report, Settings},
    fixture_cases,
    fixture_family::{Family, IPV6_PEER},
    transport::{Failure, NativeTransport},
};
use absd_net::datagram::{
    self as d,
    channel::{KernelPipe, Pipe},
};
use std::sync::atomic::{AtomicU64, Ordering};

static CASE_ORDINAL: AtomicU64 = AtomicU64::new(0);
static HEAP_HIGH_PAGES: AtomicU64 = AtomicU64::new(0);
static FRAMES_HIGH: AtomicU64 = AtomicU64::new(0);
static PARTIAL_READS: AtomicU64 = AtomicU64::new(0);
static PARTIAL_WRITES: AtomicU64 = AtomicU64::new(0);

struct Arguments {
    case: String,
    unix_seconds: Option<u64>,
    grant_expiry_ms: u64,
}

fn decimal(text: &str) -> Result<u64, &'static str> {
    if text.is_empty()
        || text.len() > 20
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err("noncanonical decimal argument");
    }
    let number = text.parse::<u64>().map_err(|_| "decimal overflow")?;
    if number == 0 {
        return Err("zero time argument");
    }
    Ok(number)
}

fn arguments() -> Result<Arguments, &'static str> {
    let mut args = std::env::args();
    let _ = args.next();
    let (mut case, mut unix_seconds, mut grant_expiry_ms) = (None, None, None);
    let mut pairs = 0;
    while let Some(key) = args.next() {
        pairs += 1;
        if pairs > 3 || key.len() > 24 {
            return Err("argument bound");
        }
        let value = args.next().ok_or("missing argument value")?;
        if value.len() > 48 {
            return Err("argument value bound");
        }
        match key.as_str() {
            "--case" if case.is_none() => {
                fixture_cases::find(&value).ok_or("unknown case")?;
                case = Some(value);
            }
            "--unix-time" if unix_seconds.is_none() => {
                unix_seconds = Some(if value == "none" {
                    None
                } else {
                    Some(decimal(&value)?)
                });
            }
            "--grant-expiry" if grant_expiry_ms.is_none() => {
                grant_expiry_ms = Some(decimal(&value)?);
            }
            _ => return Err("unknown or duplicate argument"),
        }
    }
    Ok(Arguments {
        case: case.ok_or("missing case")?,
        unix_seconds: unix_seconds.ok_or("missing time argument")?,
        grant_expiry_ms: grant_expiry_ms.ok_or("missing grant expiry")?,
    })
}

fn sample_resources() {
    HEAP_HIGH_PAGES.fetch_max(absd_runtime::heap_mapped_pages(), Ordering::Relaxed);
    if let Ok(stats) = absd_runtime::frame_stats() {
        FRAMES_HIGH.fetch_max(stats.allocated_frames, Ordering::Relaxed);
    }
}

fn phase_event(phase: Phase) {
    sample_resources();
    eprintln!(
        "QUIC PHASE case=Q{:02} phase={phase:?} at_ms={}",
        CASE_ORDINAL.load(Ordering::Relaxed),
        absd_runtime::boot_millis()
    );
}

#[cfg(target_arch = "x86_64")]
fn report_cpu() {
    // CPUID is an observation. The provider checks instruction availability
    // and success itself; these bits never supply or replace entropy.
    let vendor = unsafe { core::arch::x86_64::__cpuid(0) };
    let features = unsafe { core::arch::x86_64::__cpuid(1) };
    let mut name = [0; 12];
    name[..4].copy_from_slice(&vendor.ebx.to_le_bytes());
    name[4..8].copy_from_slice(&vendor.edx.to_le_bytes());
    name[8..].copy_from_slice(&vendor.ecx.to_le_bytes());
    let base_family = (features.eax >> 8) & 15;
    let family = base_family
        + if base_family == 15 {
            (features.eax >> 20) & 255
        } else {
            0
        };
    let model = ((features.eax >> 4) & 15)
        | if matches!(base_family, 6 | 15) {
            ((features.eax >> 16) & 15) << 4
        } else {
            0
        };
    eprintln!(
        "QUIC CPU vendor={} family={family} model={model} leaf1_eax={} leaf1_ecx={} rdrand={}",
        String::from_utf8_lossy(&name),
        features.eax,
        features.ecx,
        (features.ecx >> 30) & 1
    );
}

#[cfg(not(target_arch = "x86_64"))]
fn report_cpu() {
    eprintln!("QUIC CPU unsupported_arch=1");
}

/// Owns the actual channel. Partial I/O changes only caller-visible transfer
/// sizes; it never duplicates a handle or retries an uncertain datagram.
struct ChildPipe {
    inner: KernelPipe,
    chunk_limit: usize,
}
impl Pipe for ChildPipe {
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        sample_resources();
        let requested = bytes.len();
        let limit = requested.min(self.chunk_limit);
        let result = self.inner.read(&mut bytes[..limit]);
        if matches!(result, Ok(Some(n)) if n > 0 && n < requested) {
            PARTIAL_READS.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        sample_resources();
        let requested = bytes.len();
        let result = self.inner.write(&bytes[..requested.min(self.chunk_limit)]);
        if matches!(result, Ok(Some(n)) if n > 0 && n < requested) {
            PARTIAL_WRITES.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

fn optional_integer(number: Option<u64>) -> String {
    number.map_or_else(|| "none".into(), |value| value.to_string())
}

fn hash_text(hash: Option<[u8; 32]>) -> String {
    use std::fmt::Write;
    let Some(hash) = hash else {
        return "none".into();
    };
    let mut text = String::with_capacity(64);
    for byte in hash {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn native_fields(failure: Option<Failure>) -> (&'static str, Option<u64>, Option<i64>) {
    match failure {
        None => ("none", None, None),
        Some(Failure::Config) => ("Config", None, None),
        Some(Failure::Clock) => ("Clock", None, None),
        Some(Failure::Deadline) => ("Deadline", None, None),
        Some(Failure::Cancelled) => ("Cancelled", None, None),
        Some(Failure::Fenced) => ("Fenced", None, None),
        Some(Failure::Unknown(code)) => ("Unknown", None, Some(code)),
        Some(Failure::Malformed) => ("Malformed", None, None),
        Some(Failure::Limit) => ("Limit", None, None),
        Some(Failure::Native(error)) => {
            let detail = match error {
                d::Error::TooSmall { needed } => Some(needed as i64),
                d::Error::PathMtu { maximum } => Some(maximum as i64),
                d::Error::Icmp(absd_net::icmp::Error::DestinationUnreachable { code })
                | d::Error::Icmp(absd_net::icmp::Error::TimeExceeded { code }) => Some(code as i64),
                d::Error::Icmp(absd_net::icmp::Error::FragmentationNeeded { mtu }) => {
                    Some(mtu as i64)
                }
                _ => None,
            };
            ("Native", Some(error.code() as u64), detail)
        }
    }
}

fn emit_report(args: &Arguments, start: u64, deadline: u64, native_pair: bool, report: &Report) {
    sample_resources();
    let (kind, code, detail) = native_fields(report.native_failure);
    let detail = detail.map_or_else(|| "none".into(), |n| n.to_string());
    eprintln!(
        "QUIC RESULT case={} outcome={:?} phase={:?} authenticated={} sent_stream={} received_stream={} request_fin={} peer_fin={} request_acked={} connection_drained={} engine_transmits={} endpoint_responses_discarded={} ecn_hints_omitted={} max_timer_lateness_ms={} max_turn_span_ms={} native_failure_kind={} native_error_code={} native_error_detail={} transport_error_code={} transport_close_origin={} send_calls={} send_accepted={} send_bytes={} exhausted={} receive_calls={} received={} receive_bytes={} close_calls={} close_accepted={} pipe_fenced={} unknown_send={} unexpected_rng_draws={} entropy_attempts={} last_send_ms={} fence_ms={} sends_after_fence={} queue_fills={} queue_retry_accepted={} pending_exhausted_sha256={} pending_retry_sha256={} start_ms={} end_ms={} deadline_ms={} grant_expiry_ms={} no_native_pair={} partial_pipe_reads={} partial_pipe_writes={} heap_observed_high_pages={} frames_observed_high={}",
        args.case,
        report.outcome,
        report.phase,
        report.authenticated,
        report.sent_stream,
        report.received_stream,
        report.request_fin,
        report.peer_fin,
        report.request_acked,
        report.connection_drained,
        report.engine_transmits,
        report.endpoint_responses_discarded,
        report.ecn_hints_omitted,
        report.max_timer_lateness_ms,
        report.max_turn_span_ms,
        kind,
        optional_integer(code),
        detail,
        optional_integer(report.transport_error_code),
        report
            .transport_close_origin
            .map_or("none", |origin| origin.as_str()),
        report.native.send_calls,
        report.native.send_accepted,
        report.native.send_bytes,
        report.native.exhausted,
        report.native.receive_calls,
        report.native.received,
        report.native.receive_bytes,
        report.native.close_calls,
        report.native.close_accepted,
        report.native.pipe_fenced,
        report.native.unknown_send,
        absd_native_quic_fixture::entropy::unexpected_draws(),
        absd_native_quic_fixture::entropy::material_attempts(),
        optional_integer(report.native.last_send_ms),
        optional_integer(report.native.fence_ms),
        report.native.sends_after_fence,
        report.queue_fills,
        report.queue_retry_accepted,
        hash_text(report.pending_exhausted_sha256),
        hash_text(report.pending_retry_sha256),
        start,
        absd_runtime::boot_millis(),
        deadline,
        args.grant_expiry_ms,
        !native_pair,
        PARTIAL_READS.load(Ordering::Relaxed),
        PARTIAL_WRITES.load(Ordering::Relaxed),
        HEAP_HIGH_PAGES.load(Ordering::Relaxed),
        FRAMES_HIGH.load(Ordering::Relaxed),
    );
    // entropy_attempts counts explicit Material acquisition entries, not every
    // internal TLS provider draw. Missing-time construction refuses before any
    // of those later steps; the independent source review binds that ordering.
    // Error text is diagnostic only. Qualification consumes typed fields above.
    eprintln!("QUIC DETAIL case={} detail={:?}", args.case, report.detail);
}

fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let start = absd_runtime::boot_millis();
    let args = arguments().map_err(str::to_owned)?;
    let case = fixture_cases::find(&args.case).ok_or("unknown fixture case")?;
    let family = Family::selected().map_err(str::to_owned)?;
    family.check_case(case.id).map_err(str::to_owned)?;
    if family == Family::Ipv6 {
        eprintln!(
            "QUIC TRANSPORT case={} family=6 scope=1 peer_ip=fd00:ab5d::2 peer_port=4443",
            case.id
        );
    }
    if args.unix_seconds.is_none() != case.missing_time {
        return Err("case time argument mismatch".into());
    }
    let maximum = start.checked_add(15_000).ok_or("grant expiry overflow")?;
    if args.grant_expiry_ms <= start || args.grant_expiry_ms > maximum {
        return Err("expired or inconsistent grant expiry".into());
    }
    let deadline = start
        .checked_add(10_000)
        .ok_or("deadline overflow")?
        .min(args.grant_expiry_ms);
    CASE_ORDINAL.store(
        case.id[1..].parse().map_err(|_| "case ordinal")?,
        Ordering::Relaxed,
    );
    if absd_runtime::nic::handle() != 0 || absd_runtime::has_block_device() {
        return Err("unexpected device authority".into());
    }
    report_cpu();
    sample_resources();
    let pair = absd_runtime::startup_stream_handles();
    eprintln!(
        "QUIC BEGIN case={} start_ms={start} deadline_ms={deadline} grant_expiry_ms={} unix_time={:?} native_pair={} body_len=4096",
        args.case,
        args.grant_expiry_ms,
        args.unix_seconds,
        pair.is_some()
    );
    let Some((input, output)) = pair else {
        let mut report = Report::new();
        report.detail = "missing validated named startup stream pair".into();
        report.phase = Phase::Fenced;
        phase_event(Phase::Fenced);
        emit_report(&args, start, deadline, false, &report);
        return Ok(());
    };
    let pipe = ChildPipe {
        inner: KernelPipe {
            request_reader: input,
            reply_writer: output,
        },
        chunk_limit: if args.case == "Q02" { 7 } else { usize::MAX },
    };
    if family == Family::Ipv6 {
        if input == output {
            drop(pipe);
            return Err("IPv6 named stream roles must be distinct".into());
        }
        eprintln!(
            "QUIC IPV6 CLIENT AUTHORITY case={} nic={} block={} input={} output={}",
            args.case,
            absd_runtime::nic::handle(),
            absd_runtime::has_block_device(),
            input,
            output,
        );
    }
    if case.missing_output {
        // A malformed fixture setup still emits its observed shape. It must
        // fail the independent no_native_pair predicate rather than being hidden.
        drop(pipe);
        let mut report = Report::new();
        report.detail = "missing-output fixture unexpectedly received both roles".into();
        report.phase = Phase::Fenced;
        report.native.pipe_fenced = true;
        phase_event(Phase::Fenced);
        emit_report(&args, start, deadline, true, &report);
        return Ok(());
    }
    let report = if args.case == "Q17" {
        let mut peer = absd_native_quic_fixture::PEER;
        peer.port = 4444;
        let mut transport = match family {
            Family::Ipv4 => NativeTransport::new(pipe, peer, deadline, || false),
            Family::Ipv6 => {
                let mut peer = IPV6_PEER;
                peer.port = 4444;
                NativeTransport::new_ipv6(pipe, peer, deadline, || false)
            }
        };
        let mut report = Report::new();
        phase_event(Phase::Init);
        match transport.send(b"ABSD_QUIC_DENIED") {
            Err(failure) => {
                report.outcome = Outcome::Native;
                report.native_failure = Some(failure);
            }
            Ok(_) => {
                report.outcome = Outcome::Protocol;
                report.detail = "unexpected denied-destination SEND result".into();
            }
        }
        transport.fence();
        report.native = transport.metrics;
        report.phase = Phase::Fenced;
        phase_event(Phase::Fenced);
        report
    } else {
        let settings = Settings {
            unix_seconds: args.unix_seconds,
            child_start_ms: start,
            grant_expiry_ms: args.grant_expiry_ms,
            queue_control: case.queue_control,
        };
        let hooks = Hooks {
            now_ms: absd_runtime::boot_millis,
            pause_ms: absd_runtime::sleep_ticks,
            cancelled: || false,
            phase: phase_event,
        };
        let root = include_bytes!(env!("ABSD_QUIC_ROOT_DER"));
        match family {
            Family::Ipv4 => absd_native_quic_fixture::engine::run(pipe, root, settings, hooks),
            Family::Ipv6 => {
                absd_native_quic_fixture::engine::run_ipv6(pipe, IPV6_PEER, root, settings, hooks)
            }
        }
    };
    emit_report(&args, start, deadline, true, &report);
    // A normal exit means one typed observation, including negative outcomes.
    // The independent runner decides whether the selected occurrence passed.
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("QUIC CONSUMER ERROR phase=Init error={error:?}");
            std::process::ExitCode::from(1)
        }
    }
}
