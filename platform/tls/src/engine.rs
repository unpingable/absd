//! Single-use HTTPS fixture state machine, over an owned native stream.
use crate::{
    http::ResponseParser,
    time::FixtureTime,
    transport::{IoEvent, Metrics, NativeTransport},
};
use absd_net::{datagram::channel::Pipe, stream};
use rustls::{
    client::Resumption,
    pki_types::{CertificateDer, ServerName},
    time_provider::TimeProvider,
    version::TLS13,
    ClientConfig, ClientConnection, RootCertStore,
};
use std::{
    io::{self, Read, Write},
    sync::Arc,
};

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub unix_seconds: Option<u64>,
    pub child_start_ms: u64,
    pub grant_expiry_ms: u64,
    pub expected_body_len: usize,
}
#[derive(Clone, Copy, Debug)]
pub struct Hooks {
    pub now_ms: fn() -> u64,
    pub pause_ms: fn(u64),
    pub cancelled: fn() -> bool,
    pub io_event: fn(IoEvent),
    pub phase_event: fn(Phase),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Init,
    Handshake,
    Request,
    Headers,
    Body,
    Closing,
    ErrorClosing,
    Closed,
    Fenced,
}
impl Phase {
    pub fn code(self) -> &'static str {
        match self {
            Self::Init => "INIT",
            Self::Handshake => "HANDSHAKE",
            Self::Request => "REQUEST",
            Self::Headers => "HEADERS",
            Self::Body => "BODY",
            Self::Closing => "CLOSING",
            Self::ErrorClosing => "ERROR_CLOSING",
            Self::Closed => "CLOSED",
            Self::Fenced => "FENCED",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Config,
    Time,
    Cancelled,
    Timeout,
    Clock,
    Native,
    Tls,
    Certificate,
    Http,
    HttpIncomplete,
    Truncated,
    WireBudget,
    CloseIncomplete,
}
impl Outcome {
    pub fn code(self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Config => "CONFIG",
            Self::Time => "TIME",
            Self::Cancelled => "CANCELLED",
            Self::Timeout => "TIMEOUT",
            Self::Clock => "CLOCK",
            Self::Native => "NATIVE",
            Self::Tls => "TLS",
            Self::Certificate => "CERTIFICATE",
            Self::Http => "HTTP",
            Self::HttpIncomplete => "HTTP_INCOMPLETE",
            Self::Truncated => "TRUNCATED",
            Self::WireBudget => "WIRE_BUDGET",
            Self::CloseIncomplete => "CLOSE_INCOMPLETE",
        }
    }
}
/// Terminal pre-authentication queued TLS output, never proof of peer receipt.
#[derive(Debug)]
pub struct ErrorOutput {
    pub queued: bool,
    pub attempts: usize,
    pub native_write_calls: u64,
    pub native_bytes_accepted: u64,
    pub queue_drained: bool,
    pub error: Option<Outcome>,
}

#[derive(Debug)]
pub struct Report {
    pub outcome: Outcome,
    pub phase: Phase,
    pub metrics: Metrics,
    pub http_emitted: usize,
    pub preauth_http_emitted: usize,
    pub http_body: usize,
    pub authenticated: bool,
    pub peer_closed: bool,
    pub local_close_drained: bool,
    pub native_close_accepted: bool,
    pub protocol_version: Option<String>,
    pub cipher: Option<String>,
    pub group: Option<String>,
    pub native_error: Option<stream::Error>,
    pub tls_error_code: Option<&'static str>,
    pub http_error_code: Option<&'static str>,
    pub cleanup_error: Option<Outcome>,
    /// Secondary best-effort output; `outcome` keeps the original TLS failure.
    pub error_output: Option<ErrorOutput>,
    /// Maximum measured init/process/plaintext-write/close-notify wall-clock span.
    pub max_crypto_ms: u64,
}
impl Report {
    fn new() -> Self {
        Self {
            outcome: Outcome::Config,
            phase: Phase::Init,
            metrics: Metrics::default(),
            http_emitted: 0,
            preauth_http_emitted: 0,
            http_body: 0,
            authenticated: false,
            peer_closed: false,
            local_close_drained: false,
            native_close_accepted: false,
            protocol_version: None,
            cipher: None,
            group: None,
            native_error: None,
            tls_error_code: None,
            http_error_code: None,
            cleanup_error: None,
            error_output: None,
            max_crypto_ms: 0,
        }
    }
}

// These decisions are used by the live pump and bounded transition tests.
#[derive(Clone, Copy, Debug)]
struct Gate {
    phase: Phase,
    authenticated: bool,
    incomplete: bool,
}
impl Gate {
    fn new() -> Self {
        Self {
            phase: Phase::Init,
            authenticated: false,
            incomplete: false,
        }
    }
    fn io_allowed(self) -> bool {
        !matches!(self.phase, Phase::Init | Phase::Closed | Phase::Fenced)
    }
    fn verified(&mut self, tls13: bool, alpn: bool) -> bool {
        if self.phase != Phase::Handshake || !tls13 || !alpn {
            self.phase = Phase::Fenced;
            return false;
        }
        self.authenticated = true;
        self.phase = Phase::Request;
        true
    }
    fn request_allowed(self) -> bool {
        self.phase == Phase::Request && self.authenticated
    }
    fn eof(&mut self) -> Outcome {
        let result = if matches!(self.phase, Phase::Closing | Phase::ErrorClosing) {
            Outcome::CloseIncomplete
        } else {
            Outcome::Truncated
        };
        self.fail(result)
    }
    fn fail(&mut self, error: Outcome) -> Outcome {
        self.phase = Phase::Fenced;
        if self.incomplete {
            Outcome::HttpIncomplete
        } else {
            error
        }
    }
    fn short_http(&mut self) {
        self.incomplete = true;
        self.phase = if self.authenticated {
            Phase::ErrorClosing
        } else {
            Phase::Fenced
        };
    }
    fn finish(&mut self, peer: bool, drained: bool, closed: bool) -> Outcome {
        if !self.authenticated
            || !peer
            || !drained
            || !closed
            || !matches!(self.phase, Phase::Closing | Phase::ErrorClosing)
        {
            return self.fail(Outcome::CloseIncomplete);
        }
        self.phase = Phase::Closed;
        if self.incomplete {
            Outcome::HttpIncomplete
        } else {
            Outcome::Success
        }
    }
}

// Maximum wall-clock span among these measured calls, not all crypto CPU or
// a preemption bound. A rewound sample refuses continuation.
fn observe_crypto_span(start: u64, hooks: Hooks, report: &mut Report) -> Result<(), Outcome> {
    let elapsed = (hooks.now_ms)().checked_sub(start).ok_or(Outcome::Clock)?;
    report.max_crypto_ms = report.max_crypto_ms.max(elapsed);
    Ok(())
}

fn classify(error: &rustls::Error) -> (Outcome, &'static str) {
    use rustls::{CertificateError as C, Error as E};
    match error {
        E::FailedToGetCurrentTime => (Outcome::Time, "TIME_UNAVAILABLE"),
        E::FailedToGetRandomBytes => (Outcome::Tls, "ENTROPY_UNAVAILABLE"),
        E::AlertReceived(rustls::AlertDescription::NoApplicationProtocol) => {
            (Outcome::Tls, "ALPN_UNAVAILABLE")
        }
        E::InvalidCertificate(e) => (
            Outcome::Certificate,
            match e {
                C::UnknownIssuer => "UNKNOWN_ISSUER",
                C::BadSignature => "BAD_SIGNATURE",
                C::Expired | C::ExpiredContext { .. } => "EXPIRED",
                C::NotValidYet | C::NotValidYetContext { .. } => "NOT_YET_VALID",
                C::NotValidForName | C::NotValidForNameContext { .. } => "WRONG_NAME",
                _ => "CERTIFICATE_INVALID",
            },
        ),
        _ => (Outcome::Tls, "TLS_PROTOCOL"),
    }
}

fn prepare(
    root: &[u8],
    settings: Settings,
    hooks: Hooks,
    report: &mut Report,
) -> Result<(ClientConnection, ResponseParser, u64), Outcome> {
    let now = (hooks.now_ms)();
    if now < settings.child_start_ms {
        return Err(Outcome::Clock);
    }
    let end = settings
        .child_start_ms
        .checked_add(10_000)
        .ok_or(Outcome::Config)?;
    let latest = settings
        .child_start_ms
        .checked_add(15_000)
        .ok_or(Outcome::Config)?;
    if settings.grant_expiry_ms > latest {
        return Err(Outcome::Config);
    }
    let deadline = end.min(settings.grant_expiry_ms);
    if now >= deadline {
        return Err(Outcome::Timeout);
    }
    if root.is_empty() || root.len() > 4096 {
        return Err(Outcome::Config);
    }
    let parser = ResponseParser::new(settings.expected_body_len).map_err(|_| Outcome::Config)?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root.to_vec()))
        .map_err(|_| Outcome::Config)?;
    let time = Arc::new(
        FixtureTime::new(
            settings.unix_seconds,
            settings.child_start_ms,
            settings.grant_expiry_ms,
            hooks.now_ms,
        )
        .ok_or(Outcome::Time)?,
    );
    time.current_time().ok_or(Outcome::Time)?;
    let mut config = ClientConfig::builder_with_details(
        Arc::new(rustls::crypto::ring::default_provider()),
        time,
    )
    .with_protocol_versions(&[&TLS13])
    .map_err(|_| Outcome::Config)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_fragment_size = Some(1024);
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    let start = (hooks.now_ms)();
    let initialized = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(crate::SERVER_NAME)
            .map_err(|_| Outcome::Config)?
            .to_owned(),
    );
    observe_crypto_span(start, hooks, report)?;
    let mut tls = initialized.map_err(|e| {
        let (outcome, code) = classify(&e);
        report.tls_error_code = Some(code);
        outcome
    })?;
    tls.set_buffer_limit(Some(8192));
    Ok((tls, parser, deadline))
}

const ERROR_OUTPUT_ATTEMPTS: usize = 16;
const ERROR_OUTPUT_BYTES: u64 = 1024;

// The default Write::write_vectored submits only the first nonempty slice.
// Pinned rustls write_tls performs one such call per attempt. Clamp before
// submission, so even the first externally visible effect respects the cap.
struct ErrorWriter<'a, P: Pipe> {
    transport: &'a mut NativeTransport<P>,
    remaining: usize,
}
impl<P: Pipe> Write for ErrorWriter<'_, P> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self
            .transport
            .write(&bytes[..bytes.len().min(self.remaining)])?;
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.transport.flush()
    }
}

fn drain_error_output<P: Pipe>(
    tls: &mut ClientConnection,
    transport: &mut NativeTransport<P>,
    hooks: Hooks,
) -> ErrorOutput {
    let start_calls = transport.metrics.write_calls;
    let start_bytes = transport.metrics.write_accepted;
    let mut output = ErrorOutput {
        queued: tls.wants_write(),
        attempts: 0,
        native_write_calls: 0,
        native_bytes_accepted: 0,
        queue_drained: false,
        error: None,
    };
    while tls.wants_write() {
        // check() retains the original deadline, cancellation and monotonic
        // samples. It never reconstructs a spent client or authority.
        if transport.check().is_err() {
            output.error = Some(transport.outcome.unwrap_or(Outcome::Native));
            break;
        }
        let accepted = transport.metrics.write_accepted - start_bytes;
        if output.attempts >= ERROR_OUTPUT_ATTEMPTS || accepted >= ERROR_OUTPUT_BYTES {
            output.error = Some(Outcome::WireBudget);
            break;
        }
        output.attempts += 1;
        let result = tls.write_tls(&mut ErrorWriter {
            transport,
            remaining: ERROR_OUTPUT_BYTES.saturating_sub(accepted) as usize,
        });
        // A successful or uncertain first effect cannot be recalled. Refuse
        // all later submissions if the I/O straddled a clock/cancel boundary.
        if transport.check().is_err() {
            output.error = Some(transport.outcome.unwrap_or(Outcome::Native));
            break;
        }
        match result {
            Ok(0) => {
                output.error = Some(Outcome::Native);
                break;
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (hooks.pause_ms)(5),
            Err(_) => {
                output.error = Some(transport.outcome.unwrap_or(Outcome::Native));
                break;
            }
        }
    }
    output.native_write_calls = transport.metrics.write_calls - start_calls;
    output.native_bytes_accepted = transport.metrics.write_accepted - start_bytes;
    output.queue_drained = !tls.wants_write();
    transport.fence();
    output
}

pub fn run<P: Pipe>(pipe: P, root_der: &[u8], settings: Settings, hooks: Hooks) -> Report {
    run_with_ipv6_peer(pipe, root_der, settings, hooks, None)
}

/// Run the same bounded fixture over an explicitly selected IPv6 stream grant.
/// TLS SNI, HTTP Host, trust, time and budgets retain the existing fixture policy.
/// An IPv6 address neither grants an endpoint nor enables routing or fallback.
pub fn run_ipv6<P: Pipe>(
    pipe: P,
    peer: absd_net::ipv6::Address,
    root_der: &[u8],
    settings: Settings,
    hooks: Hooks,
) -> Report {
    run_with_ipv6_peer(pipe, root_der, settings, hooks, Some(peer))
}

fn run_with_ipv6_peer<P: Pipe>(
    pipe: P,
    root_der: &[u8],
    settings: Settings,
    hooks: Hooks,
    peer: Option<absd_net::ipv6::Address>,
) -> Report {
    let mut report = Report::new();
    (hooks.phase_event)(Phase::Init);
    let (mut tls, mut parser, deadline) = match prepare(root_der, settings, hooks, &mut report) {
        Ok(value) => value,
        Err(error) => {
            drop(pipe);
            report.outcome = error;
            report.phase = Phase::Fenced;
            report.metrics.pipe_fenced = true;
            (hooks.phase_event)(Phase::Fenced);
            return report;
        }
    };
    let mut transport = match peer {
        Some(peer) => NativeTransport::new_ipv6(pipe, peer, deadline, hooks),
        None => NativeTransport::new(pipe, deadline, hooks),
    };
    let mut gate = Gate::new();
    gate.phase = Phase::Handshake;
    (hooks.phase_event)(gate.phase);
    let mut last_phase = gate.phase;
    let mut request_at = 0;
    let request=b"GET /native-network HTTP/1.1\r\nHost: absd-fixture.test:4443\r\nConnection: close\r\n\r\n";
    let mut sent_close = false;
    if transport.connect().is_err() {
        report.outcome = gate.fail(transport.outcome.unwrap_or(Outcome::Native));
    } else {
        'pump: while gate.io_allowed() {
            if transport.check().is_err() {
                let cause = transport.outcome.unwrap_or(Outcome::Native);
                if gate.incomplete {
                    report.cleanup_error = Some(cause);
                }
                report.outcome = gate.fail(cause);
                break;
            }
            let mut progress = false;
            if gate.request_allowed() && !tls.wants_write() {
                let before = (hooks.now_ms)();
                let wrote = tls.writer().write(&request[request_at..]);
                // Accepted plaintext remains counted even if the following clock
                // observation refuses continuation. No ciphertext is replayed.
                if let Ok(n) = &wrote {
                    if !gate.authenticated {
                        report.preauth_http_emitted += *n;
                    }
                    report.http_emitted += *n;
                    request_at += *n;
                }
                if let Err(cause) = observe_crypto_span(before, hooks, &mut report) {
                    report.outcome = gate.fail(cause);
                    break;
                }
                match wrote {
                    Ok(0) => {
                        report.outcome = gate.fail(Outcome::Tls);
                        break;
                    }
                    Ok(_) => {
                        progress = true;
                        if request_at == request.len() {
                            gate.phase = Phase::Headers;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        report.outcome = gate.fail(Outcome::Tls);
                        break;
                    }
                }
            }
            if gate.phase != last_phase && (gate.phase != Phase::Headers || !tls.wants_write()) {
                (hooks.phase_event)(gate.phase);
                last_phase = gate.phase;
            }
            if tls.wants_write() {
                match tls.write_tls(&mut transport) {
                    Ok(n) => progress |= n > 0,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        let cause = transport.outcome.unwrap_or(Outcome::Native);
                        if gate.incomplete {
                            report.cleanup_error = Some(cause);
                        }
                        report.outcome = gate.fail(cause);
                        break;
                    }
                }
            }
            // The Headers marker proves all GET ciphertext was accepted, before response reads.
            if gate.phase == Phase::Headers && last_phase != Phase::Headers && !tls.wants_write() {
                (hooks.phase_event)(gate.phase);
                last_phase = gate.phase;
            }
            if tls.wants_read() {
                match tls.read_tls(&mut transport) {
                    Ok(0) => {
                        if transport.metrics.native_eof && !report.peer_closed {
                            if gate.incomplete {
                                report.cleanup_error = Some(Outcome::CloseIncomplete);
                            }
                            report.outcome = gate.eof();
                            break;
                        }
                    }
                    Ok(n) => {
                        progress |= n > 0;
                        let before = (hooks.now_ms)();
                        let processed = tls.process_new_packets();
                        if let Err(cause) = observe_crypto_span(before, hooks, &mut report) {
                            if gate.incomplete {
                                report.cleanup_error = Some(cause);
                            }
                            report.outcome = gate.fail(cause);
                            break;
                        }
                        match processed {
                            Ok(state) => report.peer_closed |= state.peer_has_closed(),
                            Err(e) => {
                                let (cause, code) = classify(&e);
                                report.tls_error_code = Some(code);
                                // The shared TLS queue may include earlier output.
                                // After HTTP generation it is not an alert-only
                                // queue: preserve immediate fencing in that case.
                                if gate.phase == Phase::Handshake && report.http_emitted == 0 {
                                    report.error_output =
                                        Some(drain_error_output(&mut tls, &mut transport, hooks));
                                }
                                report.outcome = gate.fail(cause);
                                break;
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        let cause = transport.outcome.unwrap_or(Outcome::Native);
                        if gate.incomplete {
                            report.cleanup_error = Some(cause);
                        }
                        report.outcome = gate.fail(cause);
                        break;
                    }
                }
            }
            if gate.phase == Phase::Handshake && !tls.is_handshaking() {
                let tls13 = tls.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
                let alpn = tls.alpn_protocol() == Some(b"http/1.1".as_slice());
                report.protocol_version =
                    tls.protocol_version().map(|version| format!("{version:?}"));
                if !gate.verified(tls13, alpn) {
                    report.outcome = Outcome::Tls;
                    report.tls_error_code = Some(if !tls13 {
                        "TLS_VERSION_UNSUPPORTED"
                    } else {
                        "ALPN_UNAVAILABLE"
                    });
                    break;
                }
                report.authenticated = true;
                report.cipher = tls
                    .negotiated_cipher_suite()
                    .map(|s| format!("{:?}", s.suite()));
                report.group = tls
                    .negotiated_key_exchange_group()
                    .map(|g| format!("{:?}", g.name()));
            }
            if gate.authenticated {
                let mut scratch = [0u8; 1024];
                loop {
                    match tls.reader().read(&mut scratch) {
                        Ok(0) => break,
                        Ok(n) => {
                            progress = true;
                            if gate.phase == Phase::Request {
                                report.outcome = gate.fail(Outcome::Http);
                                report.http_error_code = Some("UNSOLICITED_RESPONSE");
                                break 'pump;
                            }
                            if let Err(e) = parser.feed(&scratch[..n]) {
                                report.http_error_code = Some(e.code());
                                report.outcome = gate.fail(Outcome::Http);
                                break 'pump;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                            report.outcome = gate.eof();
                            break 'pump;
                        }
                        Err(_) => {
                            report.outcome = gate.fail(Outcome::Tls);
                            break 'pump;
                        }
                    }
                }
                if matches!(gate.phase, Phase::Headers | Phase::Body) {
                    if parser.is_complete() {
                        gate.phase = Phase::Closing;
                    } else if parser.headers_complete() {
                        gate.phase = Phase::Body;
                    }
                }
                if report.peer_closed && !parser.is_complete() {
                    report.http_error_code = parser.finish().err().map(|e| e.code());
                    gate.short_http();
                }
            }
            if matches!(gate.phase, Phase::Closing | Phase::ErrorClosing) {
                if !sent_close {
                    let before = (hooks.now_ms)();
                    tls.send_close_notify();
                    sent_close = true;
                    if let Err(cause) = observe_crypto_span(before, hooks, &mut report) {
                        if gate.incomplete {
                            report.cleanup_error = Some(cause);
                        }
                        report.outcome = gate.fail(cause);
                        break;
                    }
                    progress = true;
                }
                report.local_close_drained = sent_close && !tls.wants_write();
                if report.peer_closed && report.local_close_drained {
                    let result = transport.close();
                    report.native_close_accepted = result.is_ok();
                    if result.is_err() && gate.incomplete {
                        report.cleanup_error = Some(transport.outcome.unwrap_or(Outcome::Native));
                    }
                    report.outcome = gate.finish(
                        report.peer_closed,
                        report.local_close_drained,
                        report.native_close_accepted,
                    );
                    break;
                }
            }
            if gate.phase != last_phase && (gate.phase != Phase::Headers || !tls.wants_write()) {
                (hooks.phase_event)(gate.phase);
                last_phase = gate.phase;
            }
            if !progress {
                (hooks.pause_ms)(5);
            }
        }
    }
    if gate.phase != Phase::Closed {
        transport.fence();
    }
    report.phase = gate.phase;
    report.metrics = transport.metrics;
    report.native_error = transport.native_error;
    report.http_body = parser.body_len();
    (hooks.phase_event)(report.phase);
    report
}

#[cfg(test)]
mod alert_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_authentication_and_terminal_transition_cases() {
        for phase in [
            Phase::Init,
            Phase::Handshake,
            Phase::Request,
            Phase::Headers,
            Phase::Body,
            Phase::Closing,
            Phase::ErrorClosing,
            Phase::Closed,
            Phase::Fenced,
        ] {
            for tls13 in [false, true] {
                for alpn in [false, true] {
                    let mut g = Gate {
                        phase,
                        authenticated: false,
                        incomplete: false,
                    };
                    let accepted = g.verified(tls13, alpn);
                    assert_eq!(accepted, phase == Phase::Handshake && tls13 && alpn);
                    assert_eq!(g.request_allowed(), accepted);
                }
            }
        }
        for phase in [Phase::Closed, Phase::Fenced] {
            let g = Gate {
                phase,
                authenticated: true,
                incomplete: false,
            };
            assert!(!g.io_allowed());
            assert!(!g.request_allowed());
        }
    }
    #[test]
    fn uncertainty_and_eof_spend_the_state_without_timeout_or_replay() {
        for phase in [
            Phase::Handshake,
            Phase::Request,
            Phase::Headers,
            Phase::Body,
        ] {
            let mut g = Gate {
                phase,
                authenticated: true,
                incomplete: false,
            };
            assert_eq!(g.eof(), Outcome::Truncated);
            assert!(!g.io_allowed());
            assert!(!g.request_allowed());
            let mut g = Gate {
                phase,
                authenticated: true,
                incomplete: false,
            };
            assert_eq!(g.fail(Outcome::Native), Outcome::Native);
            assert_eq!(g.phase, Phase::Fenced);
            assert!(!g.io_allowed());
        }
    }
    #[test]
    fn incomplete_http_survives_every_cleanup_outcome() {
        for peer in [false, true] {
            for drained in [false, true] {
                for closed in [false, true] {
                    let mut g = Gate {
                        phase: Phase::Body,
                        authenticated: true,
                        incomplete: false,
                    };
                    g.short_http();
                    assert_eq!(g.phase, Phase::ErrorClosing);
                    assert_eq!(g.finish(peer, drained, closed), Outcome::HttpIncomplete);
                    assert!(!g.io_allowed());
                }
            }
        }
        let mut g = Gate {
            phase: Phase::Body,
            authenticated: true,
            incomplete: false,
        };
        g.short_http();
        assert_eq!(g.fail(Outcome::Timeout), Outcome::HttpIncomplete);
    }

    #[test]
    fn standard_verifier_checks_fixture_chain_signature_name_time_and_der() {
        use rustls::{
            client::{danger::ServerCertVerifier, WebPkiServerVerifier},
            pki_types::UnixTime,
        };
        use std::{path::PathBuf, time::Duration};
        let root = PathBuf::from(
            std::env::var("ABSD_TLS_ROOT_DER")
                .expect("sealed public PKI required before host tests"),
        );
        let directory = root.parent().unwrap();
        let anchor: u64 = std::env::var("ABSD_TLS_UNIX_SECONDS")
            .expect("owner fixture time required")
            .parse()
            .unwrap();
        let now = UnixTime::since_unix_epoch(Duration::from_secs(anchor));
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(std::fs::read(&root).unwrap()))
            .unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let name = ServerName::try_from(crate::SERVER_NAME).unwrap();
        for (file, expected) in [
            ("valid.der", None),
            ("untrusted.der", Some("UNKNOWN_ISSUER")),
            ("signature-failure.der", Some("BAD_SIGNATURE")),
            ("wrong-name.der", Some("WRONG_NAME")),
            ("expired.der", Some("EXPIRED")),
            ("future.der", Some("NOT_YET_VALID")),
        ] {
            let leaf = CertificateDer::from(std::fs::read(directory.join(file)).unwrap());
            let result = verifier.verify_server_cert(&leaf, &[], &name, &[], now);
            match expected {
                None => {
                    assert!(result.is_ok(), "{file}: {result:?}");
                }
                Some(code) => {
                    let error = result.unwrap_err();
                    assert_eq!(
                        classify(&error),
                        (Outcome::Certificate, code),
                        "{file}: {error:?}"
                    );
                }
            }
        }
        let malformed = CertificateDer::from(vec![0x30, 0x01, 0x00]);
        assert!(RootCertStore::empty().add(malformed.clone()).is_err());
        let valid = CertificateDer::from(std::fs::read(directory.join("valid.der")).unwrap());
        // The direct issuer is already trusted. An unused malformed intermediate
        // may be ignored; this observation is never a malformed-chain refusal claim.
        match verifier.verify_server_cert(&valid, &[malformed.clone()], &name, &[], now) {
            Ok(_) => println!("TLS HOST UNUSED MALFORMED INTERMEDIATE IGNORED"),
            Err(error) => {
                assert_eq!(classify(&error).0, Outcome::Certificate);
                println!("TLS HOST UNUSED MALFORMED INTERMEDIATE REFUSED {:?}", error);
            }
        }
        let error = verifier
            .verify_server_cert(&malformed, &[], &name, &[], now)
            .unwrap_err();
        assert_eq!(classify(&error).0, Outcome::Certificate);
    }

    #[test]
    fn invalid_local_inputs_drop_owned_pipe_without_connect_or_any_ipc() {
        use std::{cell::Cell, rc::Rc};
        struct NoIo(Rc<Cell<bool>>);
        impl Pipe for NoIo {
            fn read(&mut self, _: &mut [u8]) -> Result<Option<usize>, i64> {
                panic!("input refusal must precede READ")
            }
            fn write(&mut self, _: &[u8]) -> Result<Option<usize>, i64> {
                panic!("input refusal must precede CONNECT")
            }
            fn now_ms(&self) -> u64 {
                100
            }
        }
        impl Drop for NoIo {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let root = std::fs::read(
            std::env::var("ABSD_TLS_ROOT_DER")
                .expect("sealed public PKI required before host tests"),
        )
        .unwrap();
        let hooks = Hooks {
            now_ms: || 100,
            pause_ms: |_| {},
            cancelled: || false,
            io_event: |_| panic!("unexpected I/O event"),
            phase_event: |_| {},
        };
        let baseline = Settings {
            unix_seconds: Some(1_700_000_000),
            child_start_ms: 100,
            grant_expiry_ms: 15_100,
            expected_body_len: 0,
        };
        let oversized_root = [0u8; 4097];
        for (settings, bytes, expected) in [
            (baseline, &b"bad DER"[..], Outcome::Config),
            (baseline, &b""[..], Outcome::Config),
            (baseline, &oversized_root[..], Outcome::Config),
            (
                Settings {
                    unix_seconds: None,
                    ..baseline
                },
                &root[..],
                Outcome::Time,
            ),
            (
                Settings {
                    expected_body_len: 16385,
                    ..baseline
                },
                &root[..],
                Outcome::Config,
            ),
            (
                Settings {
                    grant_expiry_ms: 100,
                    ..baseline
                },
                &root[..],
                Outcome::Timeout,
            ),
            (
                Settings {
                    child_start_ms: 101,
                    ..baseline
                },
                &root[..],
                Outcome::Clock,
            ),
        ] {
            let dropped = Rc::new(Cell::new(false));
            let report = run(NoIo(dropped.clone()), bytes, settings, hooks);
            assert_eq!(report.outcome, expected);
            assert_eq!(report.phase, Phase::Fenced);
            assert!(dropped.get());
            assert!(report.metrics.pipe_fenced);
            assert_eq!(report.metrics.connect_calls, 0);
            assert_eq!(report.http_emitted, 0);
            assert_eq!(report.preauth_http_emitted, 0);
        }
    }
}
