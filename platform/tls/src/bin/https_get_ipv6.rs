#![feature(restricted_std)]
//! One fixture request over an owner-issued scoped IPv6 stream channel.
//! stdout remains protocol-only; all observations go to stderr.

use absd_native_tls_fixture::{fixture_cases, ipv6_fixture};
use absd_native_tls_fixture::{Hooks, IoEvent, Phase, Settings};
use absd_net::ipv6::{
    channel::{KernelPipe, transact},
    session as d, stream,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static HEAP_HIGH_PAGES: AtomicU64 = AtomicU64::new(0);
static FRAMES_HIGH: AtomicU64 = AtomicU64::new(0);
static IN_HANDSHAKE: AtomicBool = AtomicBool::new(false);
static HANDSHAKE_REPORTED: AtomicBool = AtomicBool::new(false);
static PAUSE_AFTER_REQUEST_MS: AtomicU64 = AtomicU64::new(0);
static INTERRUPT_HANDSHAKE: AtomicBool = AtomicBool::new(false);
static INTERRUPT_AUTHENTICATED: AtomicBool = AtomicBool::new(false);
static READ_AGAIN_EVENTS: AtomicU64 = AtomicU64::new(0);
static WRITE_AGAIN_EVENTS: AtomicU64 = AtomicU64::new(0);
static READ_PROGRESS_EVENTS: AtomicU64 = AtomicU64::new(0);
static WRITE_PROGRESS_EVENTS: AtomicU64 = AtomicU64::new(0);
static SHORT_WRITE_EVENTS: AtomicU64 = AtomicU64::new(0);

struct Arguments {
    case: String,
    unix_seconds: Option<u64>,
    grant_expiry_ms: u64,
    expected_body_len: usize,
}

fn decimal(text: &str) -> Result<u64, &'static str> {
    if text.is_empty()
        || text.len() > 20
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err("noncanonical decimal argument");
    }
    text.parse().map_err(|_| "decimal overflow")
}

fn arguments() -> Result<Arguments, &'static str> {
    let mut args = std::env::args();
    let _ = args.next();
    let mut case = None;
    let mut unix_seconds = None;
    let mut grant_expiry_ms = None;
    let mut expected_body_len = None;
    let mut pairs = 0;
    while let Some(key) = args.next() {
        pairs += 1;
        if pairs > 4 || key.len() > 24 {
            return Err("argument bound");
        }
        let value = args.next().ok_or("missing argument value")?;
        if value.len() > 48 {
            return Err("argument value bound");
        }
        match key.as_str() {
            "--case" if case.is_none() => {
                if value.is_empty()
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/')
                    })
                {
                    return Err("case identifier");
                }
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
            "--expected-body" if expected_body_len.is_none() => {
                let length = decimal(&value)?;
                if length > 16_384 {
                    return Err("body expectation bound");
                }
                expected_body_len = Some(length as usize);
            }
            _ => return Err("unknown or duplicate argument"),
        }
    }
    Ok(Arguments {
        case: case.ok_or("missing case")?,
        unix_seconds: unix_seconds.ok_or("missing time argument")?,
        grant_expiry_ms: grant_expiry_ms.ok_or("missing grant expiry")?,
        expected_body_len: expected_body_len.ok_or("missing body expectation")?,
    })
}

fn sample_resources() {
    HEAP_HIGH_PAGES.fetch_max(absd_runtime::heap_mapped_pages(), Ordering::Relaxed);
    if let Ok(stats) = absd_runtime::frame_stats() {
        FRAMES_HIGH.fetch_max(stats.allocated_frames, Ordering::Relaxed);
    }
}

fn io_event(event: IoEvent) {
    sample_resources();
    let write = event.direction.code().eq_ignore_ascii_case("write");
    let again = event.native_error == Some(stream::Error::Again);
    let counter = match (write, again) {
        (false, false) => &READ_PROGRESS_EVENTS,
        (true, false) => &WRITE_PROGRESS_EVENTS,
        (false, true) => &READ_AGAIN_EVENTS,
        (true, true) => &WRITE_AGAIN_EVENTS,
    };
    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
    let short = write && event.native_error.is_none() && event.accepted < event.requested;
    let short_count = if short {
        SHORT_WRITE_EVENTS.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        0
    };
    // Finite diagnostic sampling prevents idle Again or byte-fragmented input
    // from filling the report pipe. Final Metrics retains every operation.
    let sampled = if again {
        count.is_power_of_two()
    } else {
        count <= 64 || count.is_power_of_two()
    };
    let terminal = event.native_error.is_some() && !again;
    if sampled || terminal || (short && (short_count <= 16 || short_count.is_power_of_two())) {
        eprintln!(
            "TLS IO direction={} requested={} accepted={} native_error={:?} event_count={} again={} short_count={} at_ms={}",
            event.direction.code(),
            event.requested,
            event.accepted,
            event.native_error,
            count,
            again,
            short_count,
            absd_runtime::boot_millis(),
        );
    }
    if write && event.accepted > 0 {
        if IN_HANDSHAKE.load(Ordering::Relaxed) && !HANDSHAKE_REPORTED.swap(true, Ordering::Relaxed)
        {
            eprintln!(
                "TLS CLIENT HANDSHAKE START at_ms={}",
                absd_runtime::boot_millis()
            );
            if INTERRUPT_HANDSHAKE.load(Ordering::Relaxed) {
                absd_runtime::sleep_ticks(1000);
            }
        }
    }
}

fn phase_event(phase: Phase) {
    sample_resources();
    IN_HANDSHAKE.store(phase == Phase::Handshake, Ordering::Relaxed);
    eprintln!(
        "TLS PHASE phase={} at_ms={}",
        phase.code(),
        absd_runtime::boot_millis()
    );
    if phase == Phase::Request {
        eprintln!(
            "TLS CLIENT AUTHENTICATED at_ms={}",
            absd_runtime::boot_millis()
        );
        if INTERRUPT_AUTHENTICATED.load(Ordering::Relaxed) {
            absd_runtime::sleep_ticks(1000);
        }
    }
    if phase == Phase::Headers {
        // The engine emits this notification only after the complete request
        // ciphertext drains, immediately before it first reads the response.
        let pause = PAUSE_AFTER_REQUEST_MS.swap(0, Ordering::Relaxed);
        if pause != 0 {
            eprintln!(
                "TLS READ PAUSE milliseconds={} at_ms={}",
                pause,
                absd_runtime::boot_millis()
            );
            absd_runtime::sleep_ticks(pause);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn report_cpu() {
    // Observation only. The provider retains its own runtime feature and
    // instruction-result checks; this report never supplies entropy.
    let vendor = unsafe { core::arch::x86_64::__cpuid(0) };
    let features = unsafe { core::arch::x86_64::__cpuid(1) };
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&vendor.ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&vendor.edx.to_le_bytes());
    bytes[8..].copy_from_slice(&vendor.ecx.to_le_bytes());
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
        "TLS CPU vendor={} family={} model={} leaf1_eax={} leaf1_ecx={} rdrand={}",
        String::from_utf8_lossy(&bytes),
        family,
        model,
        features.eax,
        features.ecx,
        (features.ecx >> 30) & 1,
    );
}

#[cfg(not(target_arch = "x86_64"))]
fn report_cpu() {
    eprintln!("TLS CPU unsupported_arch=1");
}

fn wrong_peer(
    pipe: &mut KernelPipe,
    peer: absd_net::ipv6::Address,
    deadline: u64,
) -> Result<(), String> {
    let now = absd_runtime::boot_millis();
    if now >= deadline {
        return Err("denial deadline".into());
    }
    let mut request = [0; stream::HEADER];
    request[0] = stream::VERSION;
    request[1] = stream::CONNECT;
    request[3] = stream::FAMILY;
    request[4..20].copy_from_slice(&peer.ip);
    request[20..24].copy_from_slice(&peer.scope.to_be_bytes());
    request[24..26].copy_from_slice(&4444u16.to_be_bytes());
    let mut reply = [0; d::MAX_MESSAGE];
    let length = transact(pipe, &request, &mut reply, (deadline - now).min(1000))
        .map_err(|error| format!("denial channel {error}"))?;
    eprintln!(
        "TLS DENIAL reply_bytes={} header={:?}",
        length,
        &reply[..length.min(stream::HEADER)]
    );
    let mut expected = request;
    expected[2] = stream::Error::Denied.code();
    expected[24..26].copy_from_slice(&peer.port.to_be_bytes());
    if length != expected.len() || reply[..length] != expected {
        return Err("wrong-peer reply shape or status".into());
    }
    Ok(())
}

fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let start = absd_runtime::boot_millis();
    let peer = ipv6_fixture::selected().map_err(str::to_owned)?.peer;
    let args = arguments().map_err(str::to_owned)?;
    let case = fixture_cases::find(&args.case).ok_or("unknown fixture case")?;
    if args.expected_body_len != case.expected_body
        || args.unix_seconds.is_none() != case.missing_time
    {
        return Err("case argument mismatch".into());
    }
    PAUSE_AFTER_REQUEST_MS.store(case.pause_before_response_ms, Ordering::Relaxed);
    INTERRUPT_HANDSHAKE.store(case.id == "L04/handshake", Ordering::Relaxed);
    INTERRUPT_AUTHENTICATED.store(case.id == "L04/authenticated", Ordering::Relaxed);
    let maximum_expiry = start.checked_add(15_000).ok_or("grant expiry overflow")?;
    if args.grant_expiry_ms <= start || args.grant_expiry_ms > maximum_expiry {
        return Err("expired or inconsistent grant expiry".into());
    }
    let deadline = start
        .checked_add(10_000)
        .ok_or("deadline overflow")?
        .min(args.grant_expiry_ms);
    let nic_handle = absd_runtime::nic::handle();
    let block_device = absd_runtime::has_block_device();
    if nic_handle != 0 || block_device {
        return Err("unexpected device authority".into());
    }
    let (input, output) =
        absd_runtime::startup_stream_handles().ok_or("missing startup channel authority")?;
    if input == 0 || output == 0 || absd_runtime::nic::info(input).is_ok() {
        return Err("invalid channel authority".into());
    }
    eprintln!(
        "TLS IPV6 CLIENT AUTHORITY nic={} block={} input={} output={}",
        nic_handle, block_device, input, output
    );
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    report_cpu();
    sample_resources();
    eprintln!(
        "TLS IPV6 BEGIN case={} start_ms={} grant_expiry_ms={} deadline_ms={} unix_time={:?} expected_body={}",
        args.case, start, args.grant_expiry_ms, deadline, args.unix_seconds, args.expected_body_len,
    );
    if args.case.starts_with("L07") {
        wrong_peer(&mut pipe, peer, deadline)?;
        drop(pipe);
        eprintln!(
            "TLS RESULT case={} outcome=NATIVE phase=INIT native_error=Denied actor=authority-control denied_connect_requests=1 http_emitted=0 preauth_http_emitted=0 http_body=0 authenticated=false peer_closed=false local_close_drained=false native_close_accepted=false end_ms={}",
            args.case,
            absd_runtime::boot_millis(),
        );
        return Ok(());
    }
    let report = absd_native_tls_fixture::run_ipv6(
        pipe,
        peer,
        include_bytes!(env!("ABSD_TLS_ROOT_DER")),
        Settings {
            child_start_ms: start,
            unix_seconds: args.unix_seconds,
            grant_expiry_ms: args.grant_expiry_ms,
            expected_body_len: args.expected_body_len,
        },
        Hooks {
            now_ms: absd_runtime::boot_millis,
            pause_ms: absd_runtime::sleep_ticks,
            cancelled: || false,
            io_event,
            phase_event,
        },
    );
    sample_resources();
    eprintln!(
        "TLS RESULT case={} outcome={} phase={} start_ms={} end_ms={} deadline_ms={} grant_expiry_ms={} http_emitted={} preauth_http_emitted={} http_body={} authenticated={} peer_closed={} local_close_drained={} native_close_accepted={} native_error={:?} tls_error_code={:?} http_error_code={:?} cleanup_error={:?} protocol_version={:?} cipher={:?} group={:?} max_crypto_ms={} read_calls={} write_calls={} read_requested={} read_accepted={} write_requested={} write_accepted={} read_again={} write_again={} short_writes={} connect_calls={} close_calls={} native_eof={} pipe_fenced={} heap_observed_high_pages={} frames_observed_high={}",
        args.case,
        report.outcome.code(),
        report.phase.code(),
        start,
        absd_runtime::boot_millis(),
        deadline,
        args.grant_expiry_ms,
        report.http_emitted,
        report.preauth_http_emitted,
        report.http_body,
        report.authenticated,
        report.peer_closed,
        report.local_close_drained,
        report.native_close_accepted,
        report.native_error,
        report.tls_error_code,
        report.http_error_code,
        report.cleanup_error,
        report.protocol_version,
        report.cipher,
        report.group,
        report.max_crypto_ms,
        report.metrics.read_calls,
        report.metrics.write_calls,
        report.metrics.read_requested,
        report.metrics.read_accepted,
        report.metrics.write_requested,
        report.metrics.write_accepted,
        report.metrics.read_again,
        report.metrics.write_again,
        report.metrics.short_writes,
        report.metrics.connect_calls,
        report.metrics.close_calls,
        report.metrics.native_eof,
        report.metrics.pipe_fenced,
        HEAP_HIGH_PAGES.load(Ordering::Relaxed),
        FRAMES_HIGH.load(Ordering::Relaxed),
    );
    // A normal exit means that the selected fixture produced a typed report.
    // The independent runner compares that report with this case's oracle;
    // a negative TLS outcome is never relabelled as application success here.
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("TLS CONSUMER ERROR phase=INIT error={error:?}");
            std::process::ExitCode::from(1)
        }
    }
}
