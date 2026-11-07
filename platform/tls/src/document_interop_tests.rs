//! Host interoperability only: actual document engine and native client codec,
//! deterministic framed IPC adapter, independent Python ssl/OpenSSL server.
use crate::app_policy::{Anchor, AppTime, Sample};
use crate::{DocumentSettings, Hooks, Outcome, Phase, Report, Settings, run_document};
use absd_net::{
    datagram::{Address, channel::Pipe},
    stream,
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static SERIAL: Mutex<()> = Mutex::new(());
static NEXT: AtomicU64 = AtomicU64::new(0);
static NOW: AtomicU64 = AtomicU64::new(100);
static MODE: AtomicU8 = AtomicU8::new(0);
static CANCEL: AtomicBool = AtomicBool::new(false);
static BODY_SEEN: AtomicBool = AtomicBool::new(false);
fn now() -> u64 {
    NOW.load(Ordering::SeqCst)
}
fn sample() -> Option<Sample> {
    Some(Sample {
        boot: [7; 16],
        pit_ms: now(),
        rtc_s: 100 + (now() - 100) / 1000,
    })
}
fn pause(_: u64) {
    std::thread::sleep(Duration::from_millis(1));
    NOW.fetch_add(1, Ordering::SeqCst);
}
fn phase(phase: Phase) {
    if phase == Phase::Body {
        BODY_SEEN.store(true, Ordering::SeqCst);
        match MODE.load(Ordering::SeqCst) {
            1 => NOW.store(10_100, Ordering::SeqCst),
            2 => CANCEL.store(true, Ordering::SeqCst),
            _ => {}
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn input(name: &str) -> PathBuf {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("required operator input {name}"))
        .into()
}

struct Peer {
    child: Child,
    directory: PathBuf,
    port: u16,
}
impl Peer {
    fn start(mode: &str) -> Self {
        let directory = input("ABSD_DOCUMENT_INTEROP_DIR").join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&directory).unwrap();
        let error = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("peer.stderr"))
            .unwrap();
        let (certificate, leaf, key) = match mode {
            "indirect" | "crossing" => {
                let directory = input("ABSD_DOCUMENT_INTEROP_F7_DIR");
                let stem = if mode == "indirect" {
                    "indirect"
                } else {
                    "crossing"
                };
                (
                    directory.join(format!("{stem}.pem")),
                    directory.join(format!("{stem}.der")),
                    input("ABSD_DOCUMENT_INTEROP_F7_KEY"),
                )
            }
            _ => (
                input("ABSD_DOCUMENT_INTEROP_LEAF_PEM"),
                input("ABSD_DOCUMENT_INTEROP_LEAF_DER"),
                input("ABSD_DOCUMENT_INTEROP_KEY"),
            ),
        };
        let child = Command::new(input("ABSD_DOCUMENT_INTEROP_PYTHON"))
            .arg("-I")
            .arg(input("ABSD_DOCUMENT_INTEROP_PEER"))
            .arg("--directory")
            .arg(&directory)
            .arg("--certificate")
            .arg(certificate)
            .arg("--leaf-der")
            .arg(leaf)
            .arg("--key")
            .arg(key)
            .arg("--mode")
            .arg(mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(error)
            .spawn()
            .unwrap();
        let mut peer = Self {
            child,
            directory,
            port: 0,
        };
        let limit = Instant::now() + Duration::from_secs(4);
        while !peer.directory.join("READY").exists() {
            assert!(
                peer.child.try_wait().unwrap().is_none(),
                "peer ended before READY"
            );
            assert!(Instant::now() < limit, "peer READY timeout");
            std::thread::sleep(Duration::from_millis(1));
        }
        peer.port = fs::read_to_string(peer.directory.join("READY"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_ne!(peer.port, 0);
        peer
    }
    fn finish(&mut self) -> String {
        let limit = Instant::now() + Duration::from_secs(4);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < limit, "peer terminal timeout");
            std::thread::sleep(Duration::from_millis(1));
        }
        fs::read_to_string(self.directory.join("RESULT.json")).unwrap()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Default)]
struct Ledger {
    requests: Vec<Vec<u8>>,
    replies: Vec<Vec<u8>>,
    closes: usize,
    dropped: bool,
}
struct Bridge {
    peer: Address,
    port: u16,
    tcp: Option<TcpStream>,
    input: Vec<u8>,
    output: VecDeque<u8>,
    ledger: Rc<RefCell<Ledger>>,
    trace: PathBuf,
    started: Instant,
}
impl Bridge {
    fn check(&self) {
        assert!(
            self.started.elapsed() < Duration::from_secs(8),
            "bridge wall bound"
        );
    }
    fn dispatch(&mut self, request: &[u8]) -> Vec<u8> {
        assert!(self.ledger.borrow().requests.len() < 1024, "RPC bound");
        assert!((12..=stream::MAX_MESSAGE).contains(&request.len()));
        assert_eq!(&request[..1], &[stream::VERSION]);
        assert_eq!(&request[2..4], &[0, 0]);
        assert_eq!(&request[4..8], &self.peer.ip);
        assert_eq!(&request[8..10], &self.peer.port.to_be_bytes());
        let count = u16::from_be_bytes(request[10..12].try_into().unwrap()) as usize;
        assert_eq!(
            request.len(),
            12 + if request[1] == stream::WRITE {
                count
            } else {
                0
            }
        );
        assert!(count <= stream::MAX_IO);
        let mut reply = request[..12].to_vec();
        reply[10..12].fill(0);
        let outcome: std::io::Result<()> = (|| {
            match request[1] {
                stream::CONNECT => {
                    assert_eq!(count, 0);
                    assert!(self.tcp.is_none());
                    let tcp = TcpStream::connect_timeout(
                        &([127, 0, 0, 1], self.port).into(),
                        Duration::from_secs(1),
                    )?;
                    tcp.set_nonblocking(true)?;
                    self.tcp = Some(tcp);
                    reply[10..12].copy_from_slice(&1u16.to_be_bytes());
                    reply.push(1);
                }
                stream::STATUS => {
                    assert_eq!(count, 0);
                    assert!(self.tcp.is_some());
                    reply[10..12].copy_from_slice(&1u16.to_be_bytes());
                    reply.push(1);
                }
                stream::WRITE => {
                    assert!(count > 0);
                    let n = self.tcp.as_mut().unwrap().write(&request[12..])?;
                    assert!(n > 0);
                    reply[10..12].copy_from_slice(&(n as u16).to_be_bytes());
                }
                stream::READ => {
                    assert!(count > 0);
                    let mut bytes = [0; 19];
                    let n = self
                        .tcp
                        .as_mut()
                        .unwrap()
                        .read(&mut bytes[..count.min(19)])?;
                    if n == 0 {
                        reply[2] = stream::Error::Eof.code();
                    } else {
                        reply[10..12].copy_from_slice(&(n as u16).to_be_bytes());
                        reply.extend_from_slice(&bytes[..n]);
                    }
                }
                stream::CLOSE => {
                    assert_eq!(count, 0);
                    self.tcp.as_ref().unwrap().shutdown(Shutdown::Both)?;
                    self.ledger.borrow_mut().closes += 1;
                }
                _ => panic!("unexpected actual stream operation"),
            }
            Ok(())
        })();
        if let Err(error) = outcome {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::WouldBlock,
                "bridge TCP error"
            );
            reply.truncate(12);
            reply[10..12].fill(0);
            reply[2] = stream::Error::Again.code();
        }
        self.ledger.borrow_mut().requests.push(request.to_vec());
        self.ledger.borrow_mut().replies.push(reply.clone());
        reply
    }
}
impl Pipe for Bridge {
    fn now_ms(&self) -> u64 {
        now()
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        self.check();
        assert!(self.output.is_empty(), "more than one RPC in flight");
        let n = bytes.len().min(7);
        assert!(n > 0);
        self.input.extend_from_slice(&bytes[..n]);
        assert!(self.input.len() <= stream::MAX_MESSAGE + 2);
        if self.input.len() >= 2 {
            let length = usize::from(u16::from_be_bytes(self.input[..2].try_into().unwrap()));
            assert!((12..=stream::MAX_MESSAGE).contains(&length));
            assert!(self.input.len() <= length + 2);
            if self.input.len() == length + 2 {
                let request = std::mem::take(&mut self.input);
                let reply = self.dispatch(&request[2..]);
                self.output.extend((reply.len() as u16).to_be_bytes());
                self.output.extend(reply);
            }
        }
        Ok(Some(n))
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        self.check();
        let n = bytes.len().min(11).min(self.output.len());
        for byte in &mut bytes[..n] {
            *byte = self.output.pop_front().unwrap();
        }
        Ok(if n == 0 { None } else { Some(n) })
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        if let Some(tcp) = &self.tcp {
            let _ = tcp.shutdown(Shutdown::Both);
        }
        let mut ledger = self.ledger.borrow_mut();
        ledger.dropped = true;
        let mut trace = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&self.trace)
            .unwrap();
        for (request, reply) in ledger.requests.iter().zip(&ledger.replies) {
            writeln!(trace, "request={} reply={}", hex(request), hex(reply)).unwrap();
        }
    }
}

fn exercise(mode: &str, control: u8, name: &str, wrong_issuer: bool) -> (Report, String, usize) {
    NOW.store(100, Ordering::SeqCst);
    MODE.store(control, Ordering::SeqCst);
    CANCEL.store(false, Ordering::SeqCst);
    BODY_SEEN.store(false, Ordering::SeqCst);
    let mut peer = Peer::start(mode);
    let f7 = matches!(mode, "indirect" | "crossing");
    let issuer_path = if f7 {
        assert!(!wrong_issuer && name == "document.example");
        input("ABSD_DOCUMENT_INTEROP_F7_DIR").join("root.der")
    } else {
        input(if wrong_issuer {
            "ABSD_DOCUMENT_INTEROP_OTHER_ROOT_DER"
        } else {
            "ABSD_DOCUMENT_INTEROP_ROOT_DER"
        })
    };
    let issuer = fs::read(issuer_path).unwrap();
    let der = rustls::pki_types::CertificateDer::from(issuer.as_slice());
    let parsed = rustls::server::ParsedCertificate::try_from(&der).unwrap();
    let pin = ring::digest::digest(
        &ring::digest::SHA256,
        parsed.subject_public_key_info().as_ref(),
    )
    .as_ref()
    .try_into()
    .unwrap();
    let utc_ms = if mode == "crossing" {
        fs::read_to_string(input("ABSD_DOCUMENT_INTEROP_F7_DIR").join("crossing-time-ms.txt"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap()
    };
    let time = Arc::new(
        AppTime::new(
            Anchor {
                boot: [7; 16],
                pit_ms: 100,
                rtc_s: 100,
                utc_ms,
                uncertainty_ms: 0,
            },
            sample,
        )
        .unwrap(),
    );
    if f7 {
        verify_f7_fixture(mode, &issuer, &pin, &time);
    }
    let address = Address {
        ip: [192, 0, 2, 2],
        port: peer.port,
    };
    let settings = DocumentSettings {
        peer: address,
        name,
        path: "/document.bin?edition=1",
        issuer_spki: pin,
        time,
    };
    let ledger = Rc::new(RefCell::new(Ledger::default()));
    let report = run_document(
        Bridge {
            peer: address,
            port: peer.port,
            tcp: None,
            input: Vec::new(),
            output: VecDeque::new(),
            ledger: ledger.clone(),
            trace: peer.directory.join("RPC.txt"),
            started: Instant::now(),
        },
        &issuer,
        Settings {
            unix_seconds: None,
            child_start_ms: 100,
            grant_expiry_ms: 15_100,
            expected_body_len: 0,
        },
        Hooks {
            now_ms: now,
            pause_ms: pause,
            cancelled: || CANCEL.load(Ordering::SeqCst),
            io_event: |_| {},
            phase_event: phase,
        },
        &settings,
    );
    fs::write(peer.directory.join("REPORT.txt"), format!("{report:#?}\n")).unwrap();
    assert!(ledger.borrow().dropped && report.metrics.pipe_fenced);
    assert_eq!(report.preauth_http_emitted, 0);
    if control != 0 {
        assert!(
            BODY_SEEN.load(Ordering::SeqCst),
            "control never reached actual Body"
        );
    }
    let result = peer.finish();
    if !wrong_issuer && name == "document.example" && !f7 {
        let get = format!(
            "GET /document.bin?edition=1 HTTP/1.1\r\nHost: document.example:{}\r\nConnection: close\r\n\r\n",
            peer.port
        );
        assert!(result.contains(&format!("\"request_hex\":\"{}\"", hex(get.as_bytes()))));
        assert!(result.contains("\"complete_get\":true"));
        assert!(result.contains("\"sni\":\"document.example\""));
        assert_eq!(report.http_emitted, get.len());
        assert!(report.authenticated);
        assert!(result.contains("\"tls\":\"TLSv1.3\"") && result.contains("\"alpn\":\"http/1.1\""));
    } else {
        assert!(result.contains("\"request_hex\":\"\""));
        assert!(result.contains("\"complete_get\":false"));
        assert_eq!(report.http_emitted, 0);
        assert!(!report.authenticated);
    }
    let closes = ledger.borrow().closes;
    (report, result, closes)
}

fn verify_f7_fixture(mode: &str, issuer: &[u8], pin: &[u8; 32], time: &AppTime) {
    use rustls::{
        client::{WebPkiServerVerifier, danger::ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };
    let directory = input("ABSD_DOCUMENT_INTEROP_F7_DIR");
    let leaf = CertificateDer::from(fs::read(directory.join(format!("{mode}.der"))).unwrap());
    let intermediates = if mode == "indirect" {
        vec![CertificateDer::from(
            fs::read(directory.join("intermediate.der")).unwrap(),
        )]
    } else {
        Vec::new()
    };
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(crate::app_policy::pinned_roots(issuer, pin).unwrap()),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();
    let name = ServerName::try_from("document.example").unwrap();
    let bounds = time.bounds().unwrap();
    let lower = UnixTime::since_unix_epoch(Duration::from_secs(bounds.0 / 1000));
    // Both are real valid chains at the canonical handshake's point time.
    verifier
        .verify_server_cert(&leaf, &intermediates, &name, &[], lower)
        .unwrap();
    if mode == "crossing" {
        assert_eq!(
            (bounds.0 + 500) % 1000,
            0,
            "anchor must be NotAfter minus 500 ms"
        );
        assert!(bounds.1 > bounds.0 + 500);
        let upper = UnixTime::since_unix_epoch(Duration::from_secs((bounds.1 + 999) / 1000));
        assert!(matches!(
            verifier.verify_server_cert(&leaf, &[], &name, &[], upper),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
            ))
        ));
    }
    // Refusal is already necessary for actual uncertainty/directness, without
    // relying solely on the new conservative 15 second future coverage policy.
    assert!(
        crate::app_policy::verify_direct(issuer, pin, leaf.as_ref(), "document.example", bounds)
            .is_err()
    );
}
fn refused(report: &Report) {
    assert_ne!(report.outcome, Outcome::Success);
    assert!(
        report.document.is_none() && report.leaf_der.is_none() && report.verified_time.is_none()
    );
}
#[test]
fn independent_openssl_exact_binary_document_is_released_only_after_terminal_close() {
    let _serial = SERIAL.lock().unwrap();
    let (report, peer, closes) = exercise("happy", 0, "document.example", false);
    assert_eq!(report.outcome, Outcome::Success);
    assert_eq!(report.phase, Phase::Closed);
    assert_eq!(
        report.document.unwrap(),
        (0..=255).chain([0, 255, 13, 10]).collect::<Vec<u8>>()
    );
    assert_eq!(
        report.leaf_der.unwrap(),
        fs::read(input("ABSD_DOCUMENT_INTEROP_LEAF_DER")).unwrap()
    );
    assert!(
        report.verified_time.is_some()
            && report.authenticated
            && report.peer_closed
            && report.local_close_drained
            && report.native_close_accepted
    );
    assert_eq!(closes, 1);
    assert!(peer.contains("\"exception\":\"\""));
    assert!(peer.contains("\"tls_closed\":true"));
}
#[test]
fn independent_peer_wrong_issuer_emits_zero_http() {
    let _serial = SERIAL.lock().unwrap();
    let (r, _, _) = exercise("happy", 0, "document.example", true);
    refused(&r);
    assert_eq!(r.outcome, Outcome::Certificate);
    assert_eq!(r.tls_error_code, Some("UNKNOWN_ISSUER"));
}
#[test]
fn independent_peer_wrong_name_emits_zero_http() {
    let _serial = SERIAL.lock().unwrap();
    let (r, _, _) = exercise("happy", 0, "other.example", false);
    refused(&r);
    assert_eq!(r.outcome, Outcome::Certificate);
    assert_eq!(r.tls_error_code, Some("WRONG_NAME"));
}
#[test]
fn independent_peer_duplicate_length_releases_no_document() {
    let _serial = SERIAL.lock().unwrap();
    let (r, _, _) = exercise("duplicate", 0, "document.example", false);
    refused(&r);
    assert_eq!(r.outcome, Outcome::Http);
    assert_eq!(r.http_error_code, Some("duplicate_length"));
    assert_eq!(r.http_body, 0);
}
#[test]
fn independent_peer_short_http_releases_no_document() {
    let _serial = SERIAL.lock().unwrap();
    let (r, _, _) = exercise("short", 0, "document.example", false);
    refused(&r);
    assert_eq!(r.outcome, Outcome::HttpIncomplete);
    assert_eq!(r.http_body, 259);
    assert!(r.peer_closed && r.local_close_drained && r.native_close_accepted);
}
#[test]
fn independent_peer_abrupt_tls_eof_releases_no_document() {
    let _serial = SERIAL.lock().unwrap();
    let (r, _, _) = exercise("truncate", 0, "document.example", false);
    refused(&r);
    assert_eq!(r.outcome, Outcome::Truncated);
    assert_eq!(r.http_body, 259);
}
#[test]
fn independent_peer_extra_byte_releases_no_document() {
    let _serial = SERIAL.lock().unwrap();
    let (r, _, _) = exercise("extra", 0, "document.example", false);
    refused(&r);
    assert_eq!(r.outcome, Outcome::Http);
    assert_eq!(r.http_error_code, Some("extra_body"));
    assert_eq!(r.http_body, 260);
}
#[test]
fn independent_peer_expiry_after_body_prefix_releases_no_document() {
    let _serial = SERIAL.lock().unwrap();
    let (r, _, _) = exercise("partial", 1, "document.example", false);
    refused(&r);
    assert_eq!(r.outcome, Outcome::Timeout);
    assert_eq!(r.http_body, 7);
}
#[test]
fn independent_peer_cancellation_after_body_prefix_releases_no_document() {
    let _serial = SERIAL.lock().unwrap();
    let (r, _, _) = exercise("partial", 2, "document.example", false);
    refused(&r);
    assert_eq!(r.outcome, Outcome::Cancelled);
    assert_eq!(r.http_body, 7);
}

fn refused_after_canonical_handshake(mode: &str, certificate_count: usize) {
    let (report, peer, closes) = exercise(mode, 0, "document.example", false);
    refused(&report);
    assert_eq!(report.outcome, Outcome::Certificate);
    assert_eq!(report.tls_error_code, Some("DIRECT_ISSUER_COVERAGE"));
    assert_eq!(report.phase, Phase::Fenced);
    assert_eq!(report.metrics.connect_calls, 1);
    assert!(report.metrics.read_accepted > 0 && report.metrics.write_accepted > 0);
    assert_eq!(report.http_body, 0);
    assert_eq!(closes, 0);
    assert!(peer.contains(&format!("\"certificate_count\":{certificate_count}")));
    assert!(peer.contains("\"sni\":\"document.example\""));
    assert!(peer.contains("\"request_hex\":\"\"") && peer.contains("\"complete_get\":false"));
}

#[test]
fn independent_peer_valid_intermediate_chain_is_refused_before_http() {
    let _serial = SERIAL.lock().unwrap();
    refused_after_canonical_handshake("indirect", 2);
}

#[test]
fn independent_peer_actual_uncertainty_crosses_leaf_expiry_before_http() {
    let _serial = SERIAL.lock().unwrap();
    refused_after_canonical_handshake("crossing", 1);
}
