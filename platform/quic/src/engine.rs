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

/// Q04-only observation of one accepted UDP datagram, using public Quinn
/// transmitted STREAM-frame counters. This diagnostic is not an IPC/handle ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamTransmitObservation {
    pub engine_ordinal: u64,
    pub native_request_ordinal: u64,
    pub accepted_ordinal: u64,
    pub bytes: usize,
    pub sha256: [u8; 32],
    pub stream_frames_before: u64,
    pub stream_frames_after: u64,
    pub authenticated: bool,
}

/// Q13/Q16-only public STREAM-frame processing around one actual received
/// datagram. This is not an AEAD rejection counter or an IPC/handle ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TagReceiveObservation {
    pub at_ms: u64,
    pub receive_ordinal: u64,
    pub bytes: usize,
    pub sha256: [u8; 32],
    pub stream_frames_before: u64,
    pub stream_frames_after: u64,
    pub authenticated_before: bool,
    pub target_handled: bool,
}

fn observe_tag_receive(
    observer: Option<fn(TagReceiveObservation)>,
    counters: Option<(u64, u64, bool)>,
    target_handled: bool,
    bytes: &[u8],
    receive_ordinal: u64,
    at_ms: u64,
) -> Result<(), (Outcome, String)> {
    let Some(observer) = observer else {
        return Ok(());
    };
    let (before, after, authenticated_before) =
        counters.ok_or((Outcome::Bounds, "missing tag receive counters".into()))?;
    if after < before
        || after - before > bytes.len() as u64
        || bytes.is_empty()
        || bytes.len() > d::MAX_DATAGRAM
        || receive_ordinal == 0
        || receive_ordinal > PACKET_LIMIT
        || (!target_handled && after != before)
    {
        return Err((Outcome::Bounds, "tag receive observation shape".into()));
    }
    // Retain zero deltas and pre-authentication/non-target inputs too. Only
    // the independent Q13 checker decides which exact pair can establish M1.
    observer(TagReceiveObservation {
        at_ms,
        receive_ordinal,
        bytes: bytes.len(),
        sha256: digest::digest(&digest::SHA256, bytes)
            .as_ref()
            .try_into()
            .unwrap(),
        stream_frames_before: before,
        stream_frames_after: after,
        authenticated_before,
        target_handled,
    });
    Ok(())
}

/// Q06-only public flow-control observations. Existing Settings, Hooks and
/// Report layouts and ordinary run entry points are unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowControlObservation {
    Blocked {
        at_ms: u64,
        sent_stream: usize,
        requested: usize,
        authenticated: bool,
        max_data_received: u64,
        max_stream_data_received: u64,
    },
    Transmit {
        engine_ordinal: u64,
        native_request_ordinal: u64,
        accepted_ordinal: u64,
        bytes: usize,
        sha256: [u8; 32],
        data_blocked_before: u64,
        data_blocked_after: u64,
        authenticated: bool,
    },
    Credit {
        at_ms: u64,
        receive_ordinal: u64,
        bytes: usize,
        sha256: [u8; 32],
        max_data_before: u64,
        max_data_after: u64,
        max_stream_data_before: u64,
        max_stream_data_after: u64,
    },
    Resumed {
        at_ms: u64,
        sent_before: usize,
        written: usize,
        max_data_received: u64,
        max_stream_data_received: u64,
    },
}

fn observe_flow_transmit(
    observer: Option<fn(FlowControlObservation)>,
    counters: Option<(u64, u64, bool)>,
    bytes: &[u8],
    engine_ordinal: u64,
    native_request_ordinal: u64,
    accepted_ordinal: u64,
) -> Result<(), (Outcome, String)> {
    let Some(observer) = observer else {
        return Ok(());
    };
    let (before, after, authenticated) =
        counters.ok_or((Outcome::Bounds, "missing flow transmit counters".into()))?;
    if after < before {
        return Err((Outcome::Bounds, "flow transmit counter rewind".into()));
    }
    if after == before {
        return Ok(());
    }
    if !authenticated
        || bytes.is_empty()
        || bytes.len() > SEND_MTU
        || after - before > bytes.len() as u64
    {
        return Err((Outcome::Bounds, "DATA_BLOCKED observation shape".into()));
    }
    observer(FlowControlObservation::Transmit {
        engine_ordinal,
        native_request_ordinal,
        accepted_ordinal,
        bytes: bytes.len(),
        sha256: digest::digest(&digest::SHA256, bytes)
            .as_ref()
            .try_into()
            .unwrap(),
        data_blocked_before: before,
        data_blocked_after: after,
        authenticated,
    });
    Ok(())
}

fn observe_stream_transmit(
    observer: Option<fn(StreamTransmitObservation)>,
    counters: Option<(u64, u64, bool)>,
    bytes: &[u8],
    engine_ordinal: u64,
    native_request_ordinal: u64,
    accepted_ordinal: u64,
) -> Result<(), (Outcome, String)> {
    let Some(observer) = observer else {
        return Ok(());
    };
    let (before, after, authenticated) =
        counters.ok_or((Outcome::Bounds, "missing transmit counters".into()))?;
    if after < before {
        return Err((Outcome::Bounds, "transmit frame counter rewind".into()));
    }
    if after == before {
        return Ok(());
    }
    if !authenticated
        || bytes.is_empty()
        || bytes.len() > SEND_MTU
        || after - before > bytes.len() as u64
    {
        return Err((
            Outcome::Bounds,
            "STREAM observation shape or authentication".into(),
        ));
    }
    observer(StreamTransmitObservation {
        engine_ordinal,
        native_request_ordinal,
        accepted_ordinal,
        bytes: bytes.len(),
        sha256: digest::digest(&digest::SHA256, bytes)
            .as_ref()
            .try_into()
            .unwrap(),
        stream_frames_before: before,
        stream_frames_after: after,
        authenticated,
    });
    Ok(())
}

fn exchange<P: Pipe>(
    endpoint: &mut Endpoint,
    config: ClientConfig,
    clock: &mut Clock,
    queue_control: bool,
    peer: SocketAddr,
    transport: &mut NativeTransport<P>,
    report: &mut Report,
    stream_observer: Option<fn(StreamTransmitObservation)>,
    flow_observer: Option<fn(FlowControlObservation)>,
    tag_observer: Option<fn(TagReceiveObservation)>,
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
    let mut pending_stream_counters = None;
    let mut pending_flow_counters = None;
    let mut flow_blocked_observed = false;
    let mut flow_resumed_observed = false;
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
            let tag_before =
                tag_observer.map(|_| (connection.stats().frame_rx.stream, report.authenticated));
            let credit_before = flow_observer.map(|_| {
                let stats = connection.stats();
                (stats.frame_rx.max_data, stats.frame_rx.max_stream_data)
            });
            scratch.clear();
            let mut target_handled = false;
            match endpoint.handle(
                now,
                peer,
                None,
                None,
                BytesMut::from(&input[..length]),
                &mut scratch,
            ) {
                Some(DatagramEvent::ConnectionEvent(target, event)) if target == handle => {
                    connection.handle_event(event);
                    target_handled = true;
                }
                Some(DatagramEvent::Response(_)) => report.endpoint_responses_discarded += 1,
                Some(_) => return Err((Outcome::Protocol, "unexpected endpoint event".into())),
                None => {}
            }
            observe_tag_receive(
                tag_observer,
                tag_before.map(|(before, authenticated)| {
                    (before, connection.stats().frame_rx.stream, authenticated)
                }),
                target_handled,
                &input[..length],
                transport.metrics.received,
                clock.last,
            )?;
            if let (Some(observer), Some((data_before, stream_before))) =
                (flow_observer, credit_before)
            {
                let stats = connection.stats();
                if stats.frame_rx.max_data > data_before
                    || stats.frame_rx.max_stream_data > stream_before
                {
                    observer(FlowControlObservation::Credit {
                        at_ms: clock.last,
                        receive_ordinal: transport.metrics.received,
                        bytes: length,
                        sha256: digest::digest(&digest::SHA256, &input[..length])
                            .as_ref()
                            .try_into()
                            .unwrap(),
                        max_data_before: data_before,
                        max_data_after: stats.frame_rx.max_data,
                        max_stream_data_before: stream_before,
                        max_stream_data_after: stats.frame_rx.max_stream_data,
                    });
                }
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
                        Ok(count) if count > 0 => {
                            if let Some(observer) = flow_observer {
                                if flow_blocked_observed && !flow_resumed_observed {
                                    let stats = connection.stats();
                                    observer(FlowControlObservation::Resumed {
                                        at_ms: clock.last,
                                        sent_before: report.sent_stream,
                                        written: count,
                                        max_data_received: stats.frame_rx.max_data,
                                        max_stream_data_received: stats.frame_rx.max_stream_data,
                                    });
                                    flow_resumed_observed = true;
                                }
                            }
                            report.sent_stream += count;
                        }
                        Err(WriteError::Blocked) => {
                            if let Some(observer) = flow_observer {
                                if !flow_blocked_observed {
                                    let stats = connection.stats();
                                    observer(FlowControlObservation::Blocked {
                                        at_ms: clock.last,
                                        sent_stream: report.sent_stream,
                                        requested: count,
                                        authenticated: report.authenticated,
                                        max_data_received: stats.frame_rx.max_data,
                                        max_stream_data_received: stats.frame_rx.max_stream_data,
                                    });
                                    flow_blocked_observed = true;
                                }
                            }
                        }
                        Ok(_) => {}
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
            // With max_datagrams=1, no segment_size and exact scratch size below,
            // the public counter delta belongs to this one returned UDP datagram.
            let stream_before = stream_observer.map(|_| connection.stats().frame_tx.stream);
            let flow_before = flow_observer.map(|_| connection.stats().frame_tx.data_blocked);
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
                pending_stream_counters = stream_before.map(|before| {
                    (
                        before,
                        connection.stats().frame_tx.stream,
                        report.authenticated,
                    )
                });
                pending_flow_counters = flow_before.map(|before| {
                    (
                        before,
                        connection.stats().frame_tx.data_blocked,
                        report.authenticated,
                    )
                });
                report.engine_transmits += 1;
                if transmit.ecn.is_some() {
                    report.ecn_hints_omitted += 1;
                }
                pending = Some(std::mem::replace(
                    &mut scratch,
                    Vec::with_capacity(d::MAX_DATAGRAM),
                ));
            } else if stream_before
                .is_some_and(|before| connection.stats().frame_tx.stream != before)
            {
                return Err((
                    Outcome::Bounds,
                    "STREAM counter advanced without a returned datagram".into(),
                ));
            } else if flow_before
                .is_some_and(|before| connection.stats().frame_tx.data_blocked != before)
            {
                return Err((
                    Outcome::Bounds,
                    "DATA_BLOCKED counter advanced without a returned datagram".into(),
                ));
            }
        }
        if let Some(bytes) = &pending {
            if transport.send(bytes).map_err(native)? {
                observe_stream_transmit(
                    stream_observer,
                    pending_stream_counters,
                    bytes,
                    report.engine_transmits,
                    transport.metrics.send_calls,
                    transport.metrics.send_accepted,
                )?;
                observe_flow_transmit(
                    flow_observer,
                    pending_flow_counters,
                    bytes,
                    report.engine_transmits,
                    transport.metrics.send_calls,
                    transport.metrics.send_accepted,
                )?;
                pending_stream_counters = None;
                pending_flow_counters = None;
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
    run_with_peer(
        pipe,
        Peer::V4(PEER),
        root_der,
        settings,
        hooks,
        None,
        None,
        None,
    )
}

/// Same IPv4 engine with an opt-in accepted-transmit diagnostic for Q04.
/// Existing run/run_ipv6, Hooks, Settings and Report layouts stay unchanged.
pub fn run_stream_observed<P: Pipe>(
    pipe: P,
    root_der: &[u8],
    settings: Settings,
    hooks: Hooks,
    observer: fn(StreamTransmitObservation),
) -> Report {
    run_with_peer(
        pipe,
        Peer::V4(PEER),
        root_der,
        settings,
        hooks,
        Some(observer),
        None,
        None,
    )
}

/// Same IPv4 engine with opt-in public blocking, accepted DATA_BLOCKED and
/// received credit observations for Q06. This changes no transport authority.
pub fn run_flow_observed<P: Pipe>(
    pipe: P,
    root_der: &[u8],
    settings: Settings,
    hooks: Hooks,
    observer: fn(FlowControlObservation),
) -> Report {
    run_with_peer(
        pipe,
        Peer::V4(PEER),
        root_der,
        settings,
        hooks,
        None,
        Some(observer),
        None,
    )
}

/// Same IPv4 engine with a Q13-only, per-input public STREAM processing
/// diagnostic. Ordinary entry points, Hooks, Settings and Report stay intact.
pub fn run_tag_observed<P: Pipe>(
    pipe: P,
    root_der: &[u8],
    settings: Settings,
    hooks: Hooks,
    observer: fn(TagReceiveObservation),
) -> Report {
    run_with_peer(
        pipe,
        Peer::V4(PEER),
        root_der,
        settings,
        hooks,
        None,
        None,
        Some(observer),
    )
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
    run_with_peer(
        pipe,
        Peer::V6(peer),
        root_der,
        settings,
        hooks,
        None,
        None,
        None,
    )
}

fn run_with_peer<P: Pipe>(
    pipe: P,
    peer: Peer,
    root_der: &[u8],
    settings: Settings,
    hooks: Hooks,
    stream_observer: Option<fn(StreamTransmitObservation)>,
    flow_observer: Option<fn(FlowControlObservation)>,
    tag_observer: Option<fn(TagReceiveObservation)>,
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
        stream_observer,
        flow_observer,
        tag_observer,
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

#[cfg(test)]
mod stream_observation_tests {
    use super::{StreamTransmitObservation, observe_stream_transmit};
    use ring::digest;
    fn unexpected(_: StreamTransmitObservation) {
        panic!("unexpected STREAM annotation");
    }
    fn accepted(value: StreamTransmitObservation) {
        assert_eq!(
            (
                value.engine_ordinal,
                value.native_request_ordinal,
                value.accepted_ordinal
            ),
            (2, 3, 2)
        );
        assert_eq!(
            (
                value.stream_frames_before,
                value.stream_frames_after,
                value.bytes
            ),
            (4, 6, 5)
        );
        assert!(value.authenticated);
        assert_eq!(
            value.sha256.as_slice(),
            digest::digest(&digest::SHA256, b"frame").as_ref()
        );
    }
    #[test]
    fn accepted_counter_delta_binds_exact_ciphertext_and_request() {
        observe_stream_transmit(Some(accepted), Some((4, 6, true)), b"frame", 2, 3, 2).unwrap();
    }
    #[test]
    fn ack_only_counter_does_not_emit_stream_observation() {
        observe_stream_transmit(Some(unexpected), Some((4, 4, true)), b"frame", 2, 3, 2).unwrap();
    }
    #[test]
    fn counter_rewind_refuses_before_callback() {
        assert!(
            observe_stream_transmit(Some(unexpected), Some((4, 3, true)), b"frame", 2, 3, 2)
                .is_err()
        );
    }
    #[test]
    fn unauthenticated_stream_counter_refuses() {
        assert!(
            observe_stream_transmit(Some(unexpected), Some((4, 5, false)), b"frame", 2, 3, 2)
                .is_err()
        );
    }
    #[test]
    fn positive_counter_requires_bounded_bytes_and_metadata() {
        let oversized = [0; super::SEND_MTU + 1];
        for (counters, bytes) in [
            (None, &b"frame"[..]),
            (Some((4, 5, true)), &b""[..]),
            (Some((4, 10, true)), &b"frame"[..]),
            (Some((4, 5, true)), &oversized[..]),
        ] {
            assert!(observe_stream_transmit(Some(unexpected), counters, bytes, 2, 3, 2).is_err());
        }
    }
    #[test]
    fn unobserved_default_does_not_need_transmit_metadata() {
        observe_stream_transmit(None, None, b"", 0, 0, 0).unwrap();
    }
}

#[cfg(test)]
mod tag_receive_observation_tests {
    use super::{TagReceiveObservation, observe_tag_receive};
    use ring::digest;

    fn unexpected(_: TagReceiveObservation) {
        panic!("unexpected tag input observation");
    }
    fn exact(value: TagReceiveObservation) {
        assert_eq!((value.at_ms, value.receive_ordinal, value.bytes), (7, 2, 5));
        assert_eq!(value.stream_frames_before, 4);
        assert!(value.authenticated_before && value.target_handled);
        assert_eq!(
            value.sha256.as_slice(),
            digest::digest(&digest::SHA256, b"frame").as_ref()
        );
    }
    fn zero(value: TagReceiveObservation) {
        exact(value);
        assert_eq!(value.stream_frames_after, 4);
    }
    fn positive(value: TagReceiveObservation) {
        exact(value);
        assert_eq!(value.stream_frames_after, 6);
    }
    fn unhandled(value: TagReceiveObservation) {
        assert!(!value.authenticated_before && !value.target_handled);
        assert_eq!(
            (value.stream_frames_before, value.stream_frames_after),
            (0, 0)
        );
    }
    #[test]
    fn zero_delta_still_records_exact_received_datagram() {
        observe_tag_receive(Some(zero), Some((4, 4, true)), true, b"frame", 2, 7).unwrap();
    }
    #[test]
    fn positive_delta_binds_same_received_datagram() {
        observe_tag_receive(Some(positive), Some((4, 6, true)), true, b"frame", 2, 7).unwrap();
    }
    #[test]
    fn earlier_inputs_keep_actual_authentication_and_target_flags() {
        observe_tag_receive(Some(unhandled), Some((0, 0, false)), false, b"frame", 1, 7).unwrap();
    }
    #[test]
    fn counter_rewind_or_unhandled_processing_refuses_before_callback() {
        for (counters, handled) in [(Some((4, 3, true)), true), (Some((4, 5, true)), false)] {
            assert!(
                observe_tag_receive(Some(unexpected), counters, handled, b"frame", 2, 7).is_err()
            );
        }
    }
    #[test]
    fn bounded_exact_metadata_is_required_only_when_observed() {
        let oversized = [0; super::d::MAX_DATAGRAM + 1];
        for (counters, bytes, ordinal) in [
            (None, &b"frame"[..], 2),
            (Some((4, 4, true)), &b""[..], 2),
            (Some((4, 10, true)), &b"frame"[..], 2),
            (Some((4, 4, true)), &oversized[..], 2),
            (Some((4, 4, true)), &b"frame"[..], 0),
            (Some((4, 4, true)), &b"frame"[..], 257),
        ] {
            assert!(
                observe_tag_receive(Some(unexpected), counters, true, bytes, ordinal, 7).is_err()
            );
        }
    }
    #[test]
    fn ordinary_none_path_is_inert_without_metadata() {
        observe_tag_receive(None, None, false, b"", 0, 0).unwrap();
    }
}

#[cfg(test)]
mod flow_observer_tests {
    use super::{FlowControlObservation, SEND_MTU, observe_flow_transmit};
    use ring::digest;

    fn unexpected(_: FlowControlObservation) {
        panic!("unexpected flow observation");
    }
    fn accepted(value: FlowControlObservation) {
        let FlowControlObservation::Transmit {
            engine_ordinal,
            native_request_ordinal,
            accepted_ordinal,
            bytes,
            sha256,
            data_blocked_before,
            data_blocked_after,
            authenticated,
        } = value
        else {
            panic!("wrong observation kind")
        };
        assert_eq!(
            (engine_ordinal, native_request_ordinal, accepted_ordinal),
            (2, 3, 2)
        );
        assert_eq!((data_blocked_before, data_blocked_after, bytes), (0, 1, 5));
        assert!(authenticated);
        assert_eq!(
            sha256.as_slice(),
            digest::digest(&digest::SHA256, b"frame").as_ref()
        );
    }
    #[test]
    fn accepted_data_blocked_counter_binds_actual_datagram_and_request() {
        observe_flow_transmit(Some(accepted), Some((0, 1, true)), b"frame", 2, 3, 2).unwrap();
    }
    #[test]
    fn ordinary_ack_or_stream_does_not_supply_data_blocked_observation() {
        observe_flow_transmit(Some(unexpected), Some((0, 0, true)), b"frame", 2, 3, 2).unwrap();
    }
    #[test]
    fn flow_counter_rewind_refuses_before_callback() {
        assert!(
            observe_flow_transmit(Some(unexpected), Some((2, 1, true)), b"frame", 2, 3, 2).is_err()
        );
    }
    #[test]
    fn unauthenticated_data_blocked_observation_refuses() {
        assert!(
            observe_flow_transmit(Some(unexpected), Some((0, 1, false)), b"frame", 2, 3, 2)
                .is_err()
        );
    }
    #[test]
    fn positive_flow_counter_requires_exact_bounded_metadata() {
        let oversized = [0; SEND_MTU + 1];
        for (counters, bytes) in [
            (None, &b"frame"[..]),
            (Some((0, 1, true)), &b""[..]),
            (Some((0, 6, true)), &b"frame"[..]),
            (Some((0, 1, true)), &oversized[..]),
        ] {
            assert!(observe_flow_transmit(Some(unexpected), counters, bytes, 2, 3, 2).is_err());
        }
    }
    #[test]
    fn unobserved_default_has_no_new_counter_precondition() {
        observe_flow_transmit(None, None, b"", 0, 0, 0).unwrap();
    }
}
