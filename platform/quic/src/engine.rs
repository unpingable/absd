//! Caller-driven QUIC v1, one authenticated echo stream and one held transmit.
use crate::{
    ALPN, BODY_LEN, PEER, SERVER_NAME, entropy,
    transport::{Failure, Metrics, NativeTransport, Peer},
};
use absd_native_tls_fixture::time::FixtureTime;
use absd_net::datagram::{self as d, channel::Pipe};
use bytes::{Bytes, BytesMut};
use quinn_proto::{
    ClientConfig, DatagramEvent, Dir, Endpoint, EndpointConfig, Event, ReadError, ReadableError,
    StreamEvent, VarInt, WriteError,
};
use ring::{digest, hmac};
use rustls::{
    RootCertStore, client::Resumption, pki_types::CertificateDer, time_provider::TimeProvider,
    version::TLS13,
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

pub const SEND_MTU: usize = 1200;
pub const PACKET_LIMIT: u64 = 256;
pub const TX_LIMIT: u64 = PACKET_LIMIT * SEND_MTU as u64;
pub const RX_LIMIT: u64 = PACKET_LIMIT * d::MAX_DATAGRAM as u64;
const EVENT_LIMIT: usize = 32;
const IO_CHUNK: usize = 512;

/// Origin of a transport-level close observation, not an authentication verdict.
/// A peer can report the same numeric code as a local protocol failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportCloseOrigin {
    Local,
    Peer,
}
impl TransportCloseOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Peer => "peer",
        }
    }
}

fn connection_transport_close(
    reason: &quinn_proto::ConnectionError,
) -> Option<(TransportCloseOrigin, u64)> {
    match reason {
        quinn_proto::ConnectionError::TransportError(error) => {
            Some((TransportCloseOrigin::Local, error.code.into()))
        }
        quinn_proto::ConnectionError::ConnectionClosed(error) => {
            Some((TransportCloseOrigin::Peer, error.error_code.into()))
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
pub struct Hooks {
    pub now_ms: fn() -> u64,
    pub pause_ms: fn(u64),
    pub cancelled: fn() -> bool,
    pub phase: fn(Phase),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Init,
    QueueFull,
    Handshake,
    Authenticated,
    Stream,
    Closing,
    Fenced,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Complete,
    Config,
    Time,
    Entropy,
    Native,
    Protocol,
    Alpn,
    Echo,
    Bounds,
}
#[derive(Clone, Copy)]
pub struct Settings {
    pub unix_seconds: Option<u64>,
    pub child_start_ms: u64,
    pub grant_expiry_ms: u64,
    pub queue_control: bool,
}
#[derive(Debug)]
pub struct Report {
    pub outcome: Outcome,
    pub phase: Phase,
    pub detail: String,
    pub native_failure: Option<Failure>,
    pub authenticated: bool,
    pub sent_stream: usize,
    pub received_stream: usize,
    pub request_fin: bool,
    pub peer_fin: bool,
    pub request_acked: bool,
    pub connection_drained: bool,
    pub transport_error_code: Option<u64>,
    pub transport_close_origin: Option<TransportCloseOrigin>,
    pub queue_fills: u64,
    pub queue_retry_accepted: u64,
    pub pending_exhausted_sha256: Option<[u8; 32]>,
    pub pending_retry_sha256: Option<[u8; 32]>,
    pub engine_transmits: u64,
    pub endpoint_responses_discarded: u64,
    pub ecn_hints_omitted: u64,
    pub max_timer_lateness_ms: u64,
    pub max_turn_span_ms: u64,
    pub native: Metrics,
}
impl Report {
    pub fn new() -> Self {
        Self {
            outcome: Outcome::Config,
            phase: Phase::Init,
            detail: String::new(),
            native_failure: None,
            authenticated: false,
            sent_stream: 0,
            received_stream: 0,
            request_fin: false,
            peer_fin: false,
            request_acked: false,
            connection_drained: false,
            transport_error_code: None,
            transport_close_origin: None,
            queue_fills: 0,
            queue_retry_accepted: 0,
            pending_exhausted_sha256: None,
            pending_retry_sha256: None,
            engine_transmits: 0,
            endpoint_responses_discarded: 0,
            ecn_hints_omitted: 0,
            max_timer_lateness_ms: 0,
            max_turn_span_ms: 0,
            native: Metrics::default(),
        }
    }
    fn enter(&mut self, phase: Phase, hooks: Hooks) {
        self.phase = phase;
        (hooks.phase)(phase);
    }
    fn record_connection_lost(&mut self, reason: &quinn_proto::ConnectionError) {
        // Both observations come from one variant match. Numeric zero and
        // peer crypto codes retain their origin; neither implies success.
        // As before, a later nontransport event cannot erase an observed code.
        if let Some((origin, code)) = connection_transport_close(reason) {
            self.transport_error_code = Some(code);
            self.transport_close_origin = Some(origin);
        }
    }
}

struct Clock {
    start: u64,
    last: u64,
    until: u64,
    origin: Instant,
    hooks: Hooks,
}
impl Clock {
    fn now(&mut self) -> Result<Instant, Failure> {
        let raw = (self.hooks.now_ms)();
        if raw < self.last || raw < self.start {
            return Err(Failure::Clock);
        }
        self.last = raw;
        if raw >= self.until {
            return Err(Failure::Deadline);
        }
        if (self.hooks.cancelled)() {
            return Err(Failure::Cancelled);
        }
        self.origin
            .checked_add(Duration::from_millis(raw - self.start))
            .ok_or(Failure::Clock)
    }
    fn span(&mut self, before: u64, report: &mut Report) -> Result<(), Failure> {
        self.now()?;
        let length = self.last.checked_sub(before).ok_or(Failure::Clock)?;
        report.max_turn_span_ms = report.max_turn_span_ms.max(length);
        Ok(())
    }
}

fn prepare(
    root_der: &[u8],
    settings: Settings,
    hooks: Hooks,
    max_datagram: usize,
) -> Result<(Endpoint, ClientConfig, Clock), (Outcome, &'static str)> {
    let start = (hooks.now_ms)();
    let maximum = settings
        .child_start_ms
        .checked_add(15_000)
        .ok_or((Outcome::Time, "expiry overflow"))?;
    if start < settings.child_start_ms
        || settings.grant_expiry_ms <= start
        || settings.grant_expiry_ms > maximum
    {
        return Err((Outcome::Time, "owner time or expiry"));
    }
    let deadline = settings
        .child_start_ms
        .checked_add(10_000)
        .ok_or((Outcome::Time, "deadline overflow"))?
        .min(settings.grant_expiry_ms);
    let time = Arc::new(
        FixtureTime::new(
            settings.unix_seconds,
            settings.child_start_ms,
            settings.grant_expiry_ms,
            hooks.now_ms,
        )
        .ok_or((Outcome::Time, "missing fixture time"))?,
    );
    time.current_time()
        .ok_or((Outcome::Time, "unusable fixture time"))?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .map_err(|_| (Outcome::Config, "root DER"))?;
    let mut tls = rustls::ClientConfig::builder_with_details(
        Arc::new(rustls::crypto::ring::default_provider()),
        time,
    )
    .with_protocol_versions(&[&TLS13])
    .map_err(|_| (Outcome::Config, "TLS 1.3"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.resumption = Resumption::disabled();
    tls.enable_early_data = false;
    tls.enable_secret_extraction = false;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.cert_compressors.clear();
    tls.cert_decompressors.clear();
    let crypto = quinn_proto::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|_| (Outcome::Config, "Initial suite"))?;
    let material = entropy::Material::acquire().map_err(|message| (Outcome::Entropy, message))?;
    let mut endpoint =
        EndpointConfig::new(Arc::new(hmac::Key::new(hmac::HMAC_SHA256, &material.reset)));
    let cid_seed = material.cid;
    endpoint.cid_generator(move || Box::new(entropy::SeededIds::new(cid_seed)));
    endpoint.rng_seed(Some(material.endpoint));
    endpoint.supported_versions(vec![1]);
    endpoint
        .max_udp_payload_size(max_datagram as u16)
        .map_err(|_| (Outcome::Config, "receive datagram bound"))?;
    let mut transport = quinn_proto::TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(0));
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.stream_receive_window(VarInt::from_u32(8192));
    transport.receive_window(VarInt::from_u32(8192));
    transport.send_window(8192);
    transport.crypto_buffer_size(16_384);
    transport.initial_mtu(SEND_MTU as u16);
    transport.min_mtu(SEND_MTU as u16);
    transport.mtu_discovery_config(None);
    transport.enable_segmentation_offload(false);
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    transport.keep_alive_interval(None);
    transport.allow_spin(false);
    transport.max_idle_timeout(Some(VarInt::from_u32(10_000).into()));
    transport
        .congestion_controller_factory(Arc::new(quinn_proto::congestion::NewRenoConfig::default()));
    let mut client = ClientConfig::new(Arc::new(crypto));
    let initial = material.initial;
    client.initial_dst_cid_provider(Arc::new(move || quinn_proto::ConnectionId::new(&initial)));
    client.token_store(Arc::new(quinn_proto::NoneTokenStore));
    client.transport_config(Arc::new(transport));
    client.version(1);
    let anchor = (hooks.now_ms)();
    if anchor < start || anchor >= deadline {
        return Err((Outcome::Time, "construction time or expiry"));
    }
    let clock = Clock {
        start: anchor,
        last: anchor,
        until: deadline,
        origin: Instant::now(),
        hooks,
    };
    // This configuration/factory is consumed by exactly one endpoint generation.
    Ok((
        Endpoint::new(Arc::new(endpoint), None, false, None),
        client,
        clock,
    ))
}

fn pattern(offset: usize) -> u8 {
    b'a' + (offset % 26) as u8
}

fn exchange<P: Pipe>(
    endpoint: &mut Endpoint,
    config: ClientConfig,
    clock: &mut Clock,
    queue_control: bool,
    peer: SocketAddr,
    transport: &mut NativeTransport<P>,
    report: &mut Report,
) -> Result<(), (Outcome, String)> {
    let native = |failure| (Outcome::Native, format!("{failure:?}"));
    if queue_control {
        for ordinal in 0..4u8 {
            let mut bytes = *b"ABSD-QUEUE-00000";
            bytes[15] = ordinal;
            if !transport.send(&bytes).map_err(native)? {
                return Err((Outcome::Bounds, "queue filled before four datagrams".into()));
            }
            report.queue_fills += 1;
        }
    }
    let now = clock.now().map_err(native)?;
    report.enter(Phase::Handshake, clock.hooks);
    // Upstream rustls QUIC constructor errors can panic inside Quinn here.
    // A successful entropy preflight does not guarantee later TLS RNG success.
    // The external parent owns fatal-child fencing/reap and resource checks.
    let (handle, mut connection) = endpoint
        .connect(now, config, peer, SERVER_NAME)
        .map_err(|error| (Outcome::Protocol, format!("connect {error:?}")))?;
    let mut pending: Option<Vec<u8>> = None;
    let mut scratch = Vec::with_capacity(d::MAX_DATAGRAM);
    let mut input = [0; d::MAX_DATAGRAM];
    let mut stream = None;
    let mut closing = false;
    for _turn in 0..4096 {
        let now = clock.now().map_err(native)?;
        transport.check().map_err(native)?;
        let before = clock.last;
        if let Some(deadline) = connection
            .poll_timeout()
            .filter(|deadline| *deadline <= now)
        {
            report.max_timer_lateness_ms = report.max_timer_lateness_ms.max(
                now.duration_since(deadline)
                    .as_millis()
                    .min(u64::MAX as u128) as u64,
            );
            connection.handle_timeout(now);
        }
        // At most one input per turn. Endpoint responses are deliberately
        // discarded in this one-client profile; they never replace held bytes.
        if let Some(length) = transport.receive(&mut input).map_err(native)? {
            scratch.clear();
            match endpoint.handle(
                now,
                peer,
                None,
                None,
                BytesMut::from(&input[..length]),
                &mut scratch,
            ) {
                Some(DatagramEvent::ConnectionEvent(target, event)) if target == handle => {
                    connection.handle_event(event)
                }
                Some(DatagramEvent::Response(_)) => report.endpoint_responses_discarded += 1,
                Some(_) => return Err((Outcome::Protocol, "unexpected endpoint event".into())),
                None => {}
            }
        }
        let mut work = 0;
        while let Some(event) = connection.poll_endpoint_events() {
            work += 1;
            if work > EVENT_LIMIT {
                return Err((Outcome::Bounds, "endpoint event bound".into()));
            }
            if let Some(event) = endpoint.handle_event(handle, event) {
                connection.handle_event(event);
            }
        }
        while let Some(event) = connection.poll() {
            work += 1;
            if work > EVENT_LIMIT {
                return Err((Outcome::Bounds, "application event bound".into()));
            }
            match event {
                Event::Connected => {
                    let handshake = connection
                        .crypto_session()
                        .handshake_data()
                        .and_then(|data| {
                            data.downcast::<quinn_proto::crypto::rustls::HandshakeData>()
                                .ok()
                        })
                        .ok_or((Outcome::Alpn, "missing handshake data".into()))?;
                    if handshake.protocol.as_deref() != Some(ALPN) {
                        return Err((Outcome::Alpn, "ALPN mismatch".into()));
                    }
                    report.authenticated = true;
                    report.enter(Phase::Authenticated, clock.hooks);
                }
                Event::ConnectionLost { reason } => {
                    report.record_connection_lost(&reason);
                    if !closing {
                        return Err((Outcome::Protocol, format!("connection {reason:?}")));
                    }
                }
                Event::Stream(StreamEvent::Opened { .. }) => {
                    return Err((Outcome::Protocol, "peer stream".into()));
                }
                Event::Stream(StreamEvent::Stopped { .. }) => {
                    return Err((Outcome::Protocol, "stream stopped".into()));
                }
                Event::Stream(StreamEvent::Finished { id }) if stream == Some(id) => {
                    report.request_acked = true
                }
                Event::DatagramReceived => {
                    return Err((Outcome::Protocol, "application datagram".into()));
                }
                _ => {}
            }
        }
        if report.authenticated && !closing {
            if stream.is_none() {
                stream = connection.streams().open(Dir::Bi);
                if stream.is_some() {
                    report.enter(Phase::Stream, clock.hooks);
                }
            }
            if let Some(id) = stream {
                if report.sent_stream < BODY_LEN {
                    let mut bytes = [0; IO_CHUNK];
                    let count = (BODY_LEN - report.sent_stream).min(bytes.len());
                    for (index, byte) in bytes[..count].iter_mut().enumerate() {
                        *byte = pattern(report.sent_stream + index);
                    }
                    match connection.send_stream(id).write(&bytes[..count]) {
                        Ok(count) if count > 0 => report.sent_stream += count,
                        Ok(_) | Err(WriteError::Blocked) => {}
                        Err(error) => return Err((Outcome::Protocol, format!("write {error:?}"))),
                    }
                }
                if report.sent_stream == BODY_LEN && !report.request_fin {
                    connection
                        .send_stream(id)
                        .finish()
                        .map_err(|error| (Outcome::Protocol, format!("finish {error:?}")))?;
                    report.request_fin = true;
                }
                if !report.peer_fin {
                    let mut receive = connection.recv_stream(id);
                    match receive.read(true) {
                        Ok(mut chunks) => {
                            let result = chunks.next(IO_CHUNK);
                            let _ = chunks.finalize();
                            match result {
                                Ok(Some(chunk)) => {
                                    if chunk.offset != report.received_stream as u64
                                        || report
                                            .received_stream
                                            .checked_add(chunk.bytes.len())
                                            .is_none_or(|n| n > BODY_LEN)
                                        || chunk.bytes.iter().enumerate().any(|(index, byte)| {
                                            *byte != pattern(report.received_stream + index)
                                        })
                                    {
                                        return Err((
                                            Outcome::Echo,
                                            "echo bytes or offsets".into(),
                                        ));
                                    }
                                    report.received_stream += chunk.bytes.len();
                                }
                                Ok(None) if report.received_stream == BODY_LEN => {
                                    report.peer_fin = true
                                }
                                Ok(None) => return Err((Outcome::Echo, "short echo FIN".into())),
                                Err(ReadError::Blocked) => {}
                                Err(error) => {
                                    return Err((Outcome::Protocol, format!("read {error:?}")));
                                }
                            }
                        }
                        Err(ReadableError::ClosedStream) => {
                            return Err((Outcome::Echo, "closed receive before FIN".into()));
                        }
                        Err(error) => {
                            return Err((Outcome::Protocol, format!("readable {error:?}")));
                        }
                    }
                }
            }
        }
        if report.peer_fin
            && report.request_fin
            && report.request_acked
            && !closing
            && pending.is_none()
        {
            connection.close(now, VarInt::from_u32(0), Bytes::new());
            closing = true;
            report.enter(Phase::Closing, clock.hooks);
        }
        if pending.is_none() {
            scratch.clear();
            if let Some(transmit) = connection.poll_transmit(now, 1, &mut scratch) {
                if transmit.destination != peer
                    || transmit.src_ip.is_some()
                    || transmit.segment_size.is_some()
                    || transmit.size != scratch.len()
                    || transmit.size == 0
                    || transmit.size > SEND_MTU
                {
                    return Err((
                        Outcome::Bounds,
                        "transmit authority or datagram shape".into(),
                    ));
                }
                if report.engine_transmits >= PACKET_LIMIT {
                    return Err((Outcome::Bounds, "produced packet bound".into()));
                }
                report.engine_transmits += 1;
                if transmit.ecn.is_some() {
                    report.ecn_hints_omitted += 1;
                }
                pending = Some(std::mem::replace(
                    &mut scratch,
                    Vec::with_capacity(d::MAX_DATAGRAM),
                ));
            }
        }
        if let Some(bytes) = &pending {
            if transport.send(bytes).map_err(native)? {
                if report.pending_exhausted_sha256.is_some()
                    && report.pending_retry_sha256.is_none()
                {
                    let hash: [u8; 32] = digest::digest(&digest::SHA256, bytes)
                        .as_ref()
                        .try_into()
                        .unwrap();
                    if Some(hash) != report.pending_exhausted_sha256 {
                        return Err((Outcome::Bounds, "held Initial changed".into()));
                    }
                    report.pending_retry_sha256 = Some(hash);
                    report.queue_retry_accepted = 1;
                }
                pending = None;
            } else if queue_control && report.pending_exhausted_sha256.is_none() {
                if report.engine_transmits != 1 || bytes.len() != SEND_MTU {
                    return Err((
                        Outcome::Bounds,
                        "queue control did not hold first Initial".into(),
                    ));
                }
                report.pending_exhausted_sha256 = Some(
                    digest::digest(&digest::SHA256, bytes)
                        .as_ref()
                        .try_into()
                        .unwrap(),
                );
                report.enter(Phase::QueueFull, clock.hooks);
            }
        }
        clock.span(before, report).map_err(native)?;
        if connection.is_drained() && pending.is_none() {
            report.connection_drained = true;
            if !closing {
                return Err((Outcome::Protocol, "drained before echo completion".into()));
            }
            transport.close().map_err(native)?;
            return Ok(());
        }
        // poll_timeout is reevaluated each turn. IPC can delay its actual
        // observation; timer lateness is reported rather than hidden.
        (clock.hooks.pause_ms)(1);
    }
    Err((Outcome::Bounds, "turn bound".into()))
}

pub fn run<P: Pipe>(pipe: P, root_der: &[u8], settings: Settings, hooks: Hooks) -> Report {
    run_with_peer(pipe, Peer::V4(PEER), root_der, settings, hooks)
}

/// Run the same bounded QUIC engine over an explicitly selected, scoped IPv6
/// channel. The pipe owner grants the peer; this address does not grant it.
/// There is no implicit family retry, address discovery or route installation.
pub fn run_ipv6<P: Pipe>(
    pipe: P,
    peer: absd_net::ipv6::Address,
    root_der: &[u8],
    settings: Settings,
    hooks: Hooks,
) -> Report {
    run_with_peer(pipe, Peer::V6(peer), root_der, settings, hooks)
}

fn run_with_peer<P: Pipe>(
    pipe: P,
    peer: Peer,
    root_der: &[u8],
    settings: Settings,
    hooks: Hooks,
) -> Report {
    let mut report = Report::new();
    report.enter(Phase::Init, hooks);
    let prepared = prepare(root_der, settings, hooks, peer.max_datagram());
    let (mut endpoint, config, mut clock) = match prepared {
        Ok(value) => value,
        Err((outcome, message)) => {
            drop(pipe);
            report.outcome = outcome;
            report.detail = message.into();
            report.native.pipe_fenced = true;
            return report;
        }
    };
    let mut transport = NativeTransport::from_peer(pipe, peer, clock.until, hooks.cancelled);
    match exchange(
        &mut endpoint,
        config,
        &mut clock,
        settings.queue_control,
        peer.socket_addr(),
        &mut transport,
        &mut report,
    ) {
        Ok(()) => {
            report.outcome = Outcome::Complete;
            report.detail = "authenticated echo, FIN, acknowledgment and bounded drain".into();
        }
        Err((outcome, message)) => {
            report.outcome = outcome;
            report.detail = message;
        }
    }
    report.native_failure = transport.failure;
    if report.outcome == Outcome::Native && report.native_failure.is_none() {
        report.native_failure = transport.check().err();
    }
    transport.fence();
    report.native = transport.metrics;
    report.enter(Phase::Fenced, hooks);
    report
}

#[cfg(test)]
mod error_report_tests {
    use super::{Outcome, Report, TransportCloseOrigin};
    use bytes::Bytes;
    use quinn_proto::{
        ApplicationClose, ConnectionClose, ConnectionError, TransportErrorCode, VarInt,
    };

    #[test]
    fn local_unknown_issuer_keeps_transport_code304() {
        let error = ConnectionError::TransportError(TransportErrorCode::crypto(48).into());
        let mut report = Report::new();
        report.record_connection_lost(&error);
        assert_eq!(report.transport_error_code, Some(304));
        assert_eq!(
            report.transport_close_origin,
            Some(TransportCloseOrigin::Local)
        );
        assert_eq!(report.transport_close_origin.unwrap().as_str(), "local");
    }
    #[test]
    fn peer_no_common_alpn_keeps_transport_code376() {
        let error = ConnectionError::ConnectionClosed(ConnectionClose {
            error_code: TransportErrorCode::crypto(120),
            frame_type: None,
            reason: Bytes::from_static(b"No common ALPN protocols"),
        });
        let mut report = Report::new();
        report.record_connection_lost(&error);
        assert_eq!(report.transport_error_code, Some(376));
        assert_eq!(
            report.transport_close_origin,
            Some(TransportCloseOrigin::Peer)
        );
        assert_eq!(report.transport_close_origin.unwrap().as_str(), "peer");
    }
    #[test]
    fn application_error_or_timeout_cannot_supply_transport_code() {
        for error in [
            ConnectionError::ApplicationClosed(ApplicationClose {
                error_code: VarInt::from_u32(376),
                reason: Bytes::from_static(b"application status"),
            }),
            ConnectionError::TimedOut,
            ConnectionError::Reset,
            ConnectionError::LocallyClosed,
            ConnectionError::VersionMismatch,
            ConnectionError::CidsExhausted,
        ] {
            let mut report = Report::new();
            report.record_connection_lost(&error);
            assert_eq!(report.transport_error_code, None, "{error:?}");
            assert_eq!(report.transport_close_origin, None, "{error:?}");
        }
    }
    #[test]
    fn nontransport_events_cannot_erase_an_observed_close_cause() {
        for reason in [
            ConnectionError::TransportError(TransportErrorCode::crypto(48).into()),
            ConnectionError::ConnectionClosed(ConnectionClose {
                error_code: TransportErrorCode::NO_ERROR,
                frame_type: None,
                reason: Bytes::new(),
            }),
        ] {
            let mut report = Report::new();
            report.record_connection_lost(&reason);
            let expected = (report.transport_close_origin, report.transport_error_code);
            for later in [ConnectionError::LocallyClosed, ConnectionError::TimedOut] {
                report.record_connection_lost(&later);
                assert_eq!(
                    (report.transport_close_origin, report.transport_error_code),
                    expected
                );
            }
        }
    }
    #[test]
    fn peer_code304_is_distinct_from_local_unknown_issuer() {
        let mut local = Report::new();
        local.record_connection_lost(&ConnectionError::TransportError(
            TransportErrorCode::crypto(48).into(),
        ));
        let mut peer = Report::new();
        peer.record_connection_lost(&ConnectionError::ConnectionClosed(ConnectionClose {
            error_code: TransportErrorCode::crypto(48),
            frame_type: None,
            reason: Bytes::from_static(b"peer code304"),
        }));
        assert_eq!(local.transport_error_code, peer.transport_error_code);
        assert_eq!(local.transport_error_code, Some(304));
        assert_eq!(
            local.transport_close_origin,
            Some(TransportCloseOrigin::Local)
        );
        assert_eq!(
            peer.transport_close_origin,
            Some(TransportCloseOrigin::Peer)
        );
    }
    #[test]
    fn peer_no_error_close_keeps_zero_and_peer_origin_without_selecting_outcome() {
        let mut report = Report::new();
        report.record_connection_lost(&ConnectionError::ConnectionClosed(ConnectionClose {
            error_code: TransportErrorCode::NO_ERROR,
            frame_type: None,
            reason: Bytes::new(),
        }));
        assert_eq!(report.transport_error_code, Some(0));
        assert_eq!(
            report.transport_close_origin,
            Some(TransportCloseOrigin::Peer)
        );
        // This records an observation only. The existing exchange control
        // flow and independent checker still decide the terminal outcome.
        assert_eq!(report.outcome, Outcome::Config);
        assert!(!report.authenticated);
    }
}
