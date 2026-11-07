#![cfg_attr(target_os = "absd", feature(restricted_std, absd_fs_ext))]
//! One configured document, one original grant, one exclusive publication.
use absd_native_tls_fixture::app_policy::{Anchor, AppTime, Sample, verify_direct};
use absd_net::datagram::Address;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
// BEGIN BOUNDED FAILURE DIAGNOSTIC
// Fixed operator diagnostics; local acceptance is never peer delivery.
const MAX_FAILURE_LINE_BYTES: usize = 512;
const _: () = assert!(usize::BITS <= 64);
const DIAGNOSTIC_OUTCOMES: &[&str] = &[
    "SUCCESS",
    "CONFIG",
    "TIME",
    "CANCELLED",
    "TIMEOUT",
    "CLOCK",
    "NATIVE",
    "TLS",
    "CERTIFICATE",
    "HTTP",
    "HTTP_INCOMPLETE",
    "TRUNCATED",
    "WIRE_BUDGET",
    "CLOSE_INCOMPLETE",
];
const DIAGNOSTIC_PHASES: &[&str] = &[
    "INIT",
    "HANDSHAKE",
    "REQUEST",
    "HEADERS",
    "BODY",
    "CLOSING",
    "ERROR_CLOSING",
    "CLOSED",
    "FENCED",
];
const DIAGNOSTIC_TLS_CODES: &[&str] = &[
    "TIME_UNAVAILABLE",
    "ENTROPY_UNAVAILABLE",
    "ALPN_UNAVAILABLE",
    "UNKNOWN_ISSUER",
    "BAD_SIGNATURE",
    "EXPIRED",
    "NOT_YET_VALID",
    "WRONG_NAME",
    "CERTIFICATE_INVALID",
    "TLS_PROTOCOL",
    "DIRECT_ISSUER_COVERAGE",
    "TLS_VERSION_UNSUPPORTED",
];

struct DiagnosticOutput<'a> {
    queued: bool,
    attempts: usize,
    native_bytes_accepted: u64,
    queue_drained: bool,
    error: Option<&'a str>,
}
struct DiagnosticFailure<'a> {
    outcome: &'a str,
    phase: &'a str,
    tls_error_code: Option<&'a str>,
    authenticated: bool,
    http: [usize; 3],
    output: Option<DiagnosticOutput<'a>>,
}
fn diagnostic_code(value: Option<&str>, codes: &'static [&'static str]) -> &'static str {
    match value {
        None => "NONE",
        Some(value) => codes
            .iter()
            .copied()
            .find(|code| *code == value)
            .unwrap_or("OTHER"),
    }
}
fn failure_diagnostic(report: &DiagnosticFailure<'_>) -> String {
    let (queued, attempts, bytes, drained, error) = match &report.output {
        None => ("NONE", "NONE".into(), "NONE".into(), "NONE", "NONE"),
        Some(o) => (
            if o.queued { "1" } else { "0" },
            o.attempts.to_string(),
            o.native_bytes_accepted.to_string(),
            if o.queue_drained { "1" } else { "0" },
            diagnostic_code(o.error, DIAGNOSTIC_OUTCOMES),
        ),
    };
    let text = format!(
        "absd-https-failure/1 outcome={} phase={} tls_error_code={} authenticated={} http_emitted={} preauth_http_emitted={} http_body={} queued={} attempts={} native_bytes_accepted={} queue_drained={} error={}\n",
        diagnostic_code(Some(report.outcome), DIAGNOSTIC_OUTCOMES),
        diagnostic_code(Some(report.phase), DIAGNOSTIC_PHASES),
        diagnostic_code(report.tls_error_code, DIAGNOSTIC_TLS_CODES),
        u8::from(report.authenticated),
        report.http[0],
        report.http[1],
        report.http[2],
        queued,
        attempts,
        bytes,
        drained,
        error
    );
    debug_assert!(text.len() <= MAX_FAILURE_LINE_BYTES);
    text
}

// END BOUNDED FAILURE DIAGNOSTIC

struct Config {
    peer: Address,
    name: String,
    path: String,
    issuer_spki: [u8; 32],
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N], &'static str> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical hex");
    }
    let mut out = [0; N];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| "hex")?, 16)
            .map_err(|_| "hex")?;
    }
    Ok(out)
}

fn config(text: &str) -> Result<Config, &'static str> {
    let rows: Vec<_> = text.lines().collect();
    if text.len() > 2048 || rows.len() != 4 {
        return Err("configuration shape");
    }
    let peer = rows[0].strip_prefix("peer=").ok_or("peer first")?;
    let address: std::net::SocketAddrV4 = peer.parse().map_err(|_| "IPv4 peer")?;
    if address.to_string() != peer || address.port() == 0 {
        return Err("noncanonical peer");
    }
    let name = rows[1].strip_prefix("name=").ok_or("name")?;
    rustls::pki_types::DnsName::try_from(name).map_err(|_| "DNS name")?;
    let path = rows[2].strip_prefix("path=").ok_or("path")?;
    if name.len() > 253
        || path.len() > 1024
        || !path.starts_with('/')
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        || !path
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'#')
    {
        return Err("name or request target bound");
    }
    Ok(Config {
        peer: Address {
            ip: address.ip().octets(),
            port: address.port(),
        },
        name: name.into(),
        path: path.into(),
        issuer_spki: unhex(rows[3].strip_prefix("issuer_spki=").ok_or("issuer pin")?)?,
    })
}

fn decimal(text: &str) -> Result<u64, &'static str> {
    if text.is_empty()
        || text.len() > 20
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err("noncanonical decimal");
    }
    text.parse().map_err(|_| "decimal overflow")
}

fn arguments(args: &[String]) -> Result<(Anchor, u64), &'static str> {
    let keys = [
        "--boot",
        "--pit-ms",
        "--rtc",
        "--utc-ms",
        "--uncertainty",
        "--grant-expiry",
    ];
    if args.len() != 12 {
        return Err("six attestation/grant arguments required");
    }
    let mut values: [Option<&str>; 6] = [None; 6];
    for pair in args.chunks_exact(2) {
        let i = keys
            .iter()
            .position(|key| *key == pair[0])
            .ok_or("unknown argument")?;
        if values[i].replace(&pair[1]).is_some() {
            return Err("duplicate argument");
        }
    }
    let v: Vec<_> = values
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or("missing argument")?;
    Ok((
        Anchor {
            boot: unhex(v[0])?,
            pit_ms: decimal(v[1])?,
            rtc_s: decimal(v[2])?,
            utc_ms: decimal(v[3])?,
            uncertainty_ms: decimal(v[4])?,
        },
        decimal(v[5])?,
    ))
}

fn bounded_file(path: &str, bound: u64) -> Result<Vec<u8>, &'static str> {
    let mut data = Vec::new();
    fs::File::open(path)
        .map_err(|_| "input open")?
        .take(bound + 1)
        .read_to_end(&mut data)
        .map_err(|_| "input read")?;
    if data.is_empty() || data.len() as u64 > bound {
        return Err("input bound");
    }
    Ok(data)
}

fn current_sample() -> Option<Sample> {
    #[cfg(target_os = "absd")]
    return Some(Sample {
        boot: absd_runtime::boot_id().ok()?,
        pit_ms: absd_runtime::boot_millis(),
        rtc_s: absd_runtime::hardware_rtc_seconds().ok()?,
    });
    #[cfg(not(target_os = "absd"))]
    None
}

fn publish(
    parent: &Path,
    id: &str,
    body: &[u8],
    receipt: &[u8],
    guard: impl Fn() -> Result<(), &'static str>,
) -> Result<PathBuf, &'static str> {
    if body.len() > 16_384 || receipt.len() > 4096 || id.len() != 32 || unhex::<16>(id).is_err() {
        return Err("publication bound");
    }
    let staging = parent.join(format!(".https-document-{id}.stage"));
    let final_path = parent.join(format!("https-document-{id}"));
    fs::create_dir(&staging).map_err(|_| "staging creation refused or unknown; no retry")?;
    let mut known = Vec::new();
    let written = (|| {
        for (name, bytes) in [("body", body), ("receipt", receipt)] {
            let path = staging.join(name);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|_| "file creation refused or unknown")?;
            known.push(path);
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "file write/sync refused or unknown")?;
        }
        guard()
    })();
    if let Err(error) = written {
        // Remove only successfully created files; never traverse or guess ownership.
        for path in known {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir(&staging);
        return Err(error);
    }
    #[cfg(target_os = "absd")]
    let committed = std::os::absd::fs::rename_noreplace(&staging, &final_path);
    #[cfg(not(target_os = "absd"))]
    let committed: std::io::Result<()> = Err(std::io::ErrorKind::Unsupported.into());
    committed.map_err(|_| "publication outcome refused or unknown; preserve paths, no retry")?;
    Ok(final_path.join("receipt"))
}

#[cfg(target_os = "absd")]
fn fetch(args: &[String]) -> Result<PathBuf, &'static str> {
    use absd_native_tls_fixture::{
        Hooks, Outcome, Settings,
        engine::{DocumentSettings, run_document},
    };
    let (anchor, expiry) = arguments(args)?;
    let start = absd_runtime::boot_millis();
    if expiry <= start || expiry > start.checked_add(15_000).ok_or("grant overflow")? {
        return Err("grant bound");
    }
    let boot = anchor.boot;
    let time = Arc::new(AppTime::new(anchor, current_sample)?);
    let config_bytes = bounded_file("/etc/https-document.conf", 2048)?;
    let cfg = config(std::str::from_utf8(&config_bytes).map_err(|_| "configuration UTF-8")?)?;
    let issuer = bounded_file("/etc/https-issuer.der", 4096)?;
    let (input, output) =
        absd_runtime::startup_stream_handles().ok_or("missing stream authority")?;
    if input == 0
        || output == 0
        || absd_runtime::nic::handle() != 0
        || absd_runtime::has_block_device()
    {
        return Err("unexpected authority");
    }
    let report = run_document(
        absd_net::datagram::channel::KernelPipe {
            request_reader: input,
            reply_writer: output,
        },
        &issuer,
        Settings {
            unix_seconds: None,
            child_start_ms: start,
            grant_expiry_ms: expiry,
            expected_body_len: 0,
        },
        Hooks {
            now_ms: absd_runtime::boot_millis,
            pause_ms: absd_runtime::sleep_ticks,
            cancelled: || false,
            io_event: |_| {},
            phase_event: |_| {},
        },
        &DocumentSettings {
            peer: cfg.peer,
            name: &cfg.name,
            path: &cfg.path,
            issuer_spki: cfg.issuer_spki,
            time: time.clone(),
        },
    );
    if report.outcome != Outcome::Success {
        eprint!(
            "{}",
            failure_diagnostic(&DiagnosticFailure {
                outcome: report.outcome.code(),
                phase: report.phase.code(),
                tls_error_code: report.tls_error_code,
                authenticated: report.authenticated,
                http: [
                    report.http_emitted,
                    report.preauth_http_emitted,
                    report.http_body
                ],
                output: report.error_output.as_ref().map(|o| DiagnosticOutput {
                    queued: o.queued,
                    attempts: o.attempts,
                    native_bytes_accepted: o.native_bytes_accepted,
                    queue_drained: o.queue_drained,
                    error: o.error.map(|e| e.code()),
                }),
            })
        );
        return Err("document transaction refused");
    }
    let body = report.document.ok_or("missing verified body")?;
    let leaf = report.leaf_der.ok_or("missing verified leaf")?;
    let verified = report.verified_time.ok_or("missing verified time")?;
    let bounds = time.bounds().ok_or("publication time refused")?;
    verify_direct(&issuer, &cfg.issuer_spki, &leaf, &cfg.name, bounds)?;
    let bounds = time
        .checked_after(bounds)
        .ok_or("publication verification interval crossed")?;
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| "RDRAND refused")?;
    let receipt = format!(
        "absd-https-document/1\npeer={}:{}\nname={}\npath={}\nissuer_spki={}\nboot={}\nverified_utc_ms={},{}\npublication_check_utc_ms={},{}\nbody_bytes={}\nbody_sha256={}\n",
        std::net::Ipv4Addr::from(cfg.peer.ip),
        cfg.peer.port,
        cfg.name,
        cfg.path,
        hex(&cfg.issuer_spki),
        hex(&boot),
        verified.0,
        verified.1,
        bounds.0,
        bounds.1,
        body.len(),
        hex(ring::digest::digest(&ring::digest::SHA256, &body).as_ref())
    );
    publish(
        Path::new("/home/operator"),
        &hex(&nonce),
        &body,
        receipt.as_bytes(),
        || {
            if absd_runtime::boot_millis() >= expiry {
                return Err("publication grant expired");
            }
            let bounds = time.bounds().ok_or("publication time refused")?;
            verify_direct(&issuer, &cfg.issuer_spki, &leaf, &cfg.name, bounds)?;
            time.checked_after(bounds)
                .ok_or("publication verification interval crossed")?;
            if absd_runtime::boot_millis() >= expiry {
                return Err("publication grant expired");
            }
            Ok(())
        },
    )
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args().skip(1).take(14).collect();
    let result = if args.len() == 1 && args[0] == "--sample" {
        current_sample().ok_or("clock sample refused").map(|s| {
            eprintln!(
                "absd-https-sample/1 boot={} pit_ms={} rtc={}",
                hex(&s.boot),
                s.pit_ms,
                s.rtc_s
            );
        })
    } else {
        #[cfg(target_os = "absd")]
        {
            fetch(&args).map(|path| eprintln!("{}", path.display()))
        }
        #[cfg(not(target_os = "absd"))]
        {
            Err("https-document requires ABSD")
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("https-document refused: {error}");
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod https_document_tests;

#[cfg(test)]
mod https_document_diagnostic_tests;
