//! Real rustls error output over the actual framed native adapter. No private keys.
use super::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    rc::Rc,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

static LOCK: Mutex<()> = Mutex::new(());
static NOW: AtomicU64 = AtomicU64::new(100);
static CANCELLED: AtomicBool = AtomicBool::new(false);
const INVALID_RECORD: &[u8] = &[0xff, 3, 3, 0, 0];

fn now() -> u64 {
    NOW.load(Ordering::Relaxed)
}
fn reset() {
    NOW.store(100, Ordering::Relaxed);
    CANCELLED.store(false, Ordering::Relaxed);
}
fn hooks() -> Hooks {
    Hooks {
        now_ms: now,
        pause_ms: |ms| {
            NOW.fetch_add(ms, Ordering::Relaxed);
        },
        cancelled: || CANCELLED.load(Ordering::Relaxed),
        io_event: |_| {},
        phase_event: |_| {},
    }
}
fn root() -> Vec<u8> {
    std::fs::read(std::env::var("ABSD_TLS_ROOT_DER").expect("sealed public root required")).unwrap()
}
fn settings() -> Settings {
    Settings {
        unix_seconds: Some(1_700_000_000),
        child_start_ms: 100,
        grant_expiry_ms: 1100,
        expected_body_len: 0,
    }
}

#[derive(Default)]
struct Record {
    calls: Vec<u8>,
    submitted: Vec<Vec<u8>>,
    accepted: Vec<u8>,
    dropped: bool,
}
#[derive(Clone, Copy)]
enum Boundary {
    Expire,
    Rewind,
    Cancel,
}
impl Boundary {
    fn apply(self) {
        match self {
            Self::Expire => NOW.store(1100, Ordering::Relaxed),
            Self::Rewind => NOW.store(99, Ordering::Relaxed),
            Self::Cancel => CANCELLED.store(true, Ordering::Relaxed),
        }
    }
    fn outcome(self) -> Outcome {
        match self {
            Self::Expire => Outcome::Timeout,
            Self::Rewind => Outcome::Clock,
            Self::Cancel => Outcome::Cancelled,
        }
    }
}
enum Reply {
    Accept(usize),
    RawOvercount(usize),
    Again,
    Refuse(stream::Error),
    Lost,
    AfterAccept(Boundary),
}
struct Fixture {
    record: Rc<RefCell<Record>>,
    input: Vec<u8>,
    output: VecDeque<u8>,
    injected: bool,
    replies: VecDeque<Reply>,
    lost: bool,
    after_reply: Option<Boundary>,
}
impl Fixture {
    fn new() -> (Self, Rc<RefCell<Record>>) {
        let record = Rc::new(RefCell::new(Record::default()));
        (
            Self {
                record: record.clone(),
                input: Vec::new(),
                output: VecDeque::new(),
                injected: false,
                replies: VecDeque::new(),
                lost: false,
                after_reply: None,
            },
            record,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.record.borrow_mut().dropped = true;
    }
}
impl Pipe for Fixture {
    fn now_ms(&self) -> u64 {
        now()
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        // Pipe fragments are independent of native stream accepted-prefix counts.
        let n = bytes.len().min(7);
        self.input.extend_from_slice(&bytes[..n]);
        if self.input.len() >= 2 {
            let length = u16::from_be_bytes([self.input[0], self.input[1]]) as usize;
            if self.input.len() == length + 2 {
                let request = std::mem::take(&mut self.input);
                let op = request[3];
                self.record.borrow_mut().calls.push(op);
                let mut reply = request[2..14].to_vec();
                reply[10..12].fill(0);
                match op {
                    stream::CONNECT => {
                        reply[10..12].copy_from_slice(&1u16.to_be_bytes());
                        reply.push(1);
                    }
                    stream::READ => {
                        assert!(!self.injected, "no normal read after TLS error");
                        self.injected = true;
                        reply[10..12].copy_from_slice(&(INVALID_RECORD.len() as u16).to_be_bytes());
                        reply.extend_from_slice(INVALID_RECORD);
                    }
                    stream::WRITE => {
                        let data = &request[14..];
                        let mut accepted = data.len();
                        let mut reported = None;
                        if self.injected {
                            self.record.borrow_mut().submitted.push(data.to_vec());
                            match self
                                .replies
                                .pop_front()
                                .unwrap_or(Reply::Accept(data.len()))
                            {
                                Reply::Accept(n) => accepted = n.min(data.len()),
                                Reply::RawOvercount(n) => {
                                    accepted = 0;
                                    reported = Some(n);
                                }
                                Reply::Again => {
                                    accepted = 0;
                                    reply[2] = stream::Error::Again.code();
                                }
                                Reply::Refuse(error) => {
                                    accepted = 0;
                                    reply[2] = error.code();
                                }
                                Reply::Lost => self.lost = true,
                                Reply::AfterAccept(boundary) => self.after_reply = Some(boundary),
                            }
                            self.record
                                .borrow_mut()
                                .accepted
                                .extend_from_slice(&data[..accepted]);
                        }
                        if self.lost {
                            return Ok(Some(n));
                        }
                        reply[10..12]
                            .copy_from_slice(&(reported.unwrap_or(accepted) as u16).to_be_bytes());
                    }
                    _ => panic!("no close, reconnect or other transaction after TLS error"),
                }
                self.output.extend((reply.len() as u16).to_be_bytes());
                self.output.extend(reply);
            }
        }
        Ok(Some(n))
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.lost {
            return Err(-5);
        }
        let n = bytes.len().min(5).min(self.output.len());
        if n == 0 {
            return Ok(None);
        }
        for byte in &mut bytes[..n] {
            *byte = self.output.pop_front().unwrap();
        }
        if self.output.is_empty() {
            if let Some(boundary) = self.after_reply.take() {
                boundary.apply();
            }
        }
        Ok(Some(n))
    }
}

#[test]
fn processing_error_submits_actual_queued_fatal_output_without_http_or_more_reads() {
    let _lock = LOCK.lock().unwrap();
    reset();
    let (pipe, record) = Fixture::new();
    let report = run(pipe, &root(), settings(), hooks());
    assert_eq!(report.outcome, Outcome::Tls);
    assert_eq!(report.tls_error_code, Some("TLS_PROTOCOL"));
    assert_eq!(report.phase, Phase::Fenced);
    assert!(!report.authenticated);
    assert_eq!(report.http_emitted, 0);
    assert_eq!(report.preauth_http_emitted, 0);
    assert_eq!(report.metrics.read_calls, 1);
    assert!(report.metrics.pipe_fenced);
    let output = report.error_output.as_ref().unwrap();
    assert!(output.queued && output.queue_drained);
    assert_eq!(output.error, None);
    assert_eq!(output.native_bytes_accepted, 7);
    let record = record.borrow();
    // Before the correction this is empty: the processing-error arm drops output.
    assert!(!record.submitted.is_empty());
    assert_eq!(record.accepted[0], 21); // TLS Alert, actual engine output.
    assert_eq!(record.accepted[5], 2); // Fatal, not application data.
    assert_eq!(
        record.accepted.len(),
        5 + u16::from_be_bytes([record.accepted[3], record.accepted[4]]) as usize
    );
    assert_eq!(record.accepted.len(), 7);
    assert!(record.dropped);
}

fn queued_error(input: &[u8]) -> ClientConnection {
    let (mut tls, _, _) = prepare(&root(), settings(), hooks(), &mut Report::new()).unwrap();
    let mut hello = Vec::new();
    while tls.wants_write() {
        tls.write_tls(&mut hello).unwrap();
    }
    assert!(tls.read_tls(&mut io::Cursor::new(input)).unwrap() > 0);
    assert!(tls.process_new_packets().is_err());
    tls
}

fn connected(replies: Vec<Reply>) -> (NativeTransport<Fixture>, Rc<RefCell<Record>>) {
    let (mut pipe, record) = Fixture::new();
    pipe.injected = true;
    pipe.replies = replies.into();
    let mut transport = NativeTransport::new(pipe, 1100, hooks());
    transport.connect().unwrap();
    (transport, record)
}

fn no_later_submission(transport: &mut NativeTransport<Fixture>, record: &Rc<RefCell<Record>>) {
    let before = record.borrow().calls.len();
    assert!(transport.write(b"never replay").is_err());
    assert!(transport.read(&mut [0u8; 1]).is_err());
    assert!(transport.connect().is_err());
    assert_eq!(record.borrow().calls.len(), before);
    assert!(record.borrow().dropped);
}

#[test]
fn actual_error_output_accepts_prefixes_and_again_without_replaying_accepted_bytes() {
    let _lock = LOCK.lock().unwrap();
    reset();
    let mut tls = queued_error(INVALID_RECORD);
    let mut expected = Vec::new();
    tls.write_tls(&mut expected).unwrap();
    let mut tls = queued_error(INVALID_RECORD);
    let (mut transport, record) = connected(vec![Reply::Accept(2), Reply::Again, Reply::Accept(1)]);
    let output = drain_error_output(&mut tls, &mut transport, hooks());
    assert_eq!(output.error, None);
    assert!(output.queued && output.queue_drained);
    assert_eq!(output.attempts, 4);
    assert_eq!(output.native_write_calls, 4);
    assert_eq!(output.native_bytes_accepted as usize, expected.len());
    assert_eq!(record.borrow().accepted, expected);
    assert_eq!(record.borrow().submitted[1], expected[2..]);
    assert_eq!(record.borrow().submitted[2], expected[2..]);
    assert_eq!(record.borrow().submitted[3], expected[3..]);
    no_later_submission(&mut transport, &record);
}

#[test]
fn native_refusal_zero_and_uncertain_reply_fence_the_terminal_output() {
    let _lock = LOCK.lock().unwrap();
    for reply in [
        Reply::Refuse(stream::Error::Denied),
        Reply::Refuse(stream::Error::WriteClosed),
        Reply::Accept(0),
        Reply::Lost,
    ] {
        reset();
        let uncertain = matches!(reply, Reply::Lost);
        let mut tls = queued_error(INVALID_RECORD);
        let (mut transport, record) = connected(vec![reply]);
        let output = drain_error_output(&mut tls, &mut transport, hooks());
        assert_eq!(output.error, Some(Outcome::Native));
        assert_eq!(output.attempts, 1);
        assert_eq!(output.native_write_calls, 1);
        assert_eq!(output.native_bytes_accepted, 0);
        assert!(!output.queue_drained);
        assert_eq!(record.borrow().submitted.len(), 1);
        // Lost reply deliberately records a possible first external effect.
        assert_eq!(
            record.borrow().accepted.len(),
            if uncertain { 7 } else { 0 }
        );
        no_later_submission(&mut transport, &record);
    }
}

#[test]
fn original_tls_failure_survives_output_refusal() {
    let _lock = LOCK.lock().unwrap();
    reset();
    let (mut pipe, record) = Fixture::new();
    pipe.replies.push_back(Reply::Refuse(stream::Error::Denied));
    let report = run(pipe, &root(), settings(), hooks());
    assert_eq!(report.outcome, Outcome::Tls);
    assert_eq!(report.tls_error_code, Some("TLS_PROTOCOL"));
    assert_eq!(report.error_output.unwrap().error, Some(Outcome::Native));
    assert_eq!(report.native_error, Some(stream::Error::Denied));
    assert_eq!(report.http_emitted, 0);
    assert_eq!(report.metrics.read_calls, 1);
    assert!(record.borrow().dropped);
}

#[test]
fn prior_fence_expiry_rewind_or_cancellation_never_submits_output() {
    let _lock = LOCK.lock().unwrap();
    for boundary in [
        None,
        Some(Boundary::Expire),
        Some(Boundary::Rewind),
        Some(Boundary::Cancel),
    ] {
        reset();
        let mut tls = queued_error(INVALID_RECORD);
        let (mut transport, record) = connected(vec![]);
        if let Some(boundary) = boundary {
            boundary.apply();
        } else {
            transport.fence();
        }
        let output = drain_error_output(&mut tls, &mut transport, hooks());
        assert_eq!(
            output.error,
            Some(boundary.map_or(Outcome::Native, Boundary::outcome))
        );
        assert_eq!(output.attempts, 0);
        assert_eq!(output.native_write_calls, 0);
        assert_eq!(output.native_bytes_accepted, 0);
        assert!(!output.queue_drained);
        assert!(record.borrow().submitted.is_empty());
        no_later_submission(&mut transport, &record);
    }
}

#[test]
fn io_crossing_expiry_rewind_or_cancellation_preserves_first_effect_and_stops() {
    let _lock = LOCK.lock().unwrap();
    for boundary in [Boundary::Expire, Boundary::Rewind, Boundary::Cancel] {
        reset();
        let mut tls = queued_error(INVALID_RECORD);
        let (mut transport, record) = connected(vec![Reply::AfterAccept(boundary)]);
        let output = drain_error_output(&mut tls, &mut transport, hooks());
        assert_eq!(output.error, Some(boundary.outcome()));
        assert_eq!(output.attempts, 1);
        assert_eq!(output.native_write_calls, 1);
        assert_eq!(record.borrow().submitted.len(), 1);
        assert_eq!(record.borrow().accepted.len(), 7);
        assert_eq!(output.queue_drained, matches!(boundary, Boundary::Cancel));
        // Cancellation is sampled by the wrapper after a known accepted reply;
        // clock/deadline crossings retire the framed client before acceptance.
        assert_eq!(
            output.native_bytes_accepted,
            if matches!(boundary, Boundary::Cancel) {
                7
            } else {
                0
            }
        );
        no_later_submission(&mut transport, &record);
    }
}

#[test]
fn stalled_output_stops_at_the_call_budget_before_the_absolute_deadline() {
    let _lock = LOCK.lock().unwrap();
    reset();
    let mut tls = queued_error(INVALID_RECORD);
    let (mut transport, record) = connected(
        (0..ERROR_OUTPUT_ATTEMPTS + 1)
            .map(|_| Reply::Again)
            .collect(),
    );
    let output = drain_error_output(&mut tls, &mut transport, hooks());
    assert_eq!(output.error, Some(Outcome::WireBudget));
    assert_eq!(output.attempts, ERROR_OUTPUT_ATTEMPTS);
    assert_eq!(output.native_write_calls as usize, ERROR_OUTPUT_ATTEMPTS);
    assert_eq!(output.native_bytes_accepted, 0);
    assert_eq!(record.borrow().submitted.len(), ERROR_OUTPUT_ATTEMPTS);
    assert!(!output.queue_drained);
    assert!(now() < 1100);
    no_later_submission(&mut transport, &record);
}

#[test]
fn a_large_real_pre_authentication_queue_is_clamped_before_native_submission() {
    let _lock = LOCK.lock().unwrap();
    reset();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
    // A real queued ClientHello plus fatal error, not an invented alert-only queue.
    config.alpn_protocols = (0..8).map(|n| vec![b'a' + n; 255]).collect();
    let mut tls = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(crate::SERVER_NAME).unwrap(),
    )
    .unwrap();
    tls.read_tls(&mut io::Cursor::new(INVALID_RECORD)).unwrap();
    assert!(tls.process_new_packets().is_err());
    let (mut transport, record) = connected(vec![]);
    let output = drain_error_output(&mut tls, &mut transport, hooks());
    assert_eq!(output.error, Some(Outcome::WireBudget));
    assert_eq!(output.native_bytes_accepted, ERROR_OUTPUT_BYTES);
    assert_eq!(record.borrow().accepted.len() as u64, ERROR_OUTPUT_BYTES);
    assert!(!output.queue_drained);
    assert!(output.native_write_calls as usize <= ERROR_OUTPUT_ATTEMPTS);
    no_later_submission(&mut transport, &record);
}

#[test]
fn received_fatal_alert_has_no_reply_output_and_does_not_restart_io() {
    let _lock = LOCK.lock().unwrap();
    reset();
    let mut tls = queued_error(&[21, 3, 3, 0, 2, 2, 40]);
    assert!(!tls.wants_write());
    let (mut transport, record) = connected(vec![]);
    let output = drain_error_output(&mut tls, &mut transport, hooks());
    assert!(!output.queued);
    assert!(output.queue_drained);
    assert_eq!(output.attempts, 0);
    assert_eq!(output.native_write_calls, 0);
    assert_eq!(output.native_bytes_accepted, 0);
    assert_eq!(output.error, None);
    assert!(record.borrow().submitted.is_empty());
    no_later_submission(&mut transport, &record);
}

#[test]
fn overreported_native_acceptance_refuses_before_another_error_output_write() {
    let _lock = LOCK.lock().unwrap();
    reset();
    let mut tls = queued_error(INVALID_RECORD);
    let (mut transport, record) = connected(vec![Reply::RawOvercount(1025)]);
    let output = drain_error_output(&mut tls, &mut transport, hooks());
    assert_eq!(output.attempts, 1);
    assert_eq!(output.native_bytes_accepted, 0);
    assert_eq!(output.error, Some(Outcome::Native));
    assert_eq!(record.borrow().submitted.len(), 1);
    assert_eq!(record.borrow().submitted[0].len(), 7);
    no_later_submission(&mut transport, &record);
}
