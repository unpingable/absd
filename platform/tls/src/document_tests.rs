use crate::{
    app_policy::{Anchor, AppTime, Sample},
    engine::{DocumentSettings, Hooks, Outcome, Phase, Settings, document_request},
    http::{Error, MAX_BODY, ResponseParser},
};
use std::{cell::Cell, rc::Rc, sync::Arc};

fn response(body: &[u8]) -> Vec<u8> {
    let mut bytes =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn arbitrary_document_survives_every_fragment_boundary_without_partial_release() {
    let body = b"\0\xff\r\n<html>native capability</html>\0";
    let bytes = response(body);
    for split in 0..=bytes.len() {
        let mut parser = ResponseParser::document();
        parser.feed(&bytes[..split]).unwrap();
        if split < bytes.len() {
            assert!(parser.take_document().is_none());
        }
        parser.feed(&bytes[split..]).unwrap();
        assert_eq!(parser.finish(), Ok(body.len()));
        assert_eq!(parser.take_document().unwrap(), body);
        assert!(parser.take_document().is_none());
        assert_eq!(parser.feed(b"x"), Err(Error::ExtraBody));
        assert!(!parser.is_complete());
    }
}

#[test]
fn zero_and_maximum_documents_are_exact_and_oversize_is_refused() {
    for len in [0, MAX_BODY] {
        let body: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        let bytes = response(&body);
        let mut parser = ResponseParser::document();
        for chunk in bytes.chunks(7) {
            parser.feed(chunk).unwrap();
        }
        assert_eq!(parser.finish(), Ok(len));
        assert_eq!(parser.take_document().unwrap(), body);
    }
    let mut parser = ResponseParser::document();
    assert_eq!(
        parser.feed(&response(&vec![0; MAX_BODY + 1])),
        Err(Error::BodyLimit)
    );
    assert!(parser.take_document().is_none());
}

#[test]
fn ambiguous_framing_redirects_and_encodings_never_release_a_document() {
    for (bytes, expected) in [
        (
            "HTTP/1.1 301 Moved\r\nContent-Length: 0\r\n\r\n",
            Error::InvalidStatus,
        ),
        ("HTTP/1.1 200 OK\r\n\r\n", Error::MissingLength),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
            Error::DuplicateLength,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 00\r\n\r\n",
            Error::InvalidLength,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            Error::TransferEncoding,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Encoding: gzip\r\n\r\n",
            Error::ContentEncoding,
        ),
        (
            "HTTP/1.1 200 OK\nContent-Length: 0\n\n",
            Error::InvalidLineEnding,
        ),
    ] {
        let mut parser = ResponseParser::document();
        assert_eq!(parser.feed(bytes.as_bytes()), Err(expected));
        assert_eq!(parser.feed(&response(b"valid later")), Err(expected));
        assert!(parser.take_document().is_none());
    }
}

#[test]
fn truncated_or_extra_data_cannot_become_success() {
    let bytes = response(b"complete");
    for end in 0..bytes.len() {
        let mut parser = ResponseParser::document();
        parser.feed(&bytes[..end]).unwrap();
        assert!(parser.finish().is_err());
        assert!(parser.take_document().is_none());
    }
    let mut parser = ResponseParser::document();
    let mut extra = bytes;
    extra.push(0);
    assert_eq!(parser.feed(&extra), Err(Error::ExtraBody));
    assert!(parser.take_document().is_none());
}

#[test]
fn fixture_constructor_keeps_its_original_pattern_contract() {
    let mut fixture = ResponseParser::new(3).unwrap();
    assert_eq!(fixture.feed(&response(b"xyz")), Err(Error::BodyMismatch));
    assert!(fixture.take_document().is_none());
    let mut fixture = ResponseParser::new(3).unwrap();
    fixture.feed(&response(b"abc")).unwrap();
    assert_eq!(fixture.finish(), Ok(3));
    assert!(fixture.take_document().is_none());
}

fn sample() -> Option<Sample> {
    Some(Sample {
        boot: [1; 16],
        pit_ms: 100,
        rtc_s: 100,
    })
}
fn document() -> DocumentSettings<'static> {
    DocumentSettings {
        peer: absd_net::datagram::Address {
            ip: [192, 0, 2, 2],
            port: 8443,
        },
        name: "document.example",
        path: "/doc?edition=1",
        issuer_spki: [0; 32],
        time: Arc::new(
            AppTime::new(
                Anchor {
                    boot: [1; 16],
                    pit_ms: 100,
                    rtc_s: 100,
                    utc_ms: 1_700_000_000_000,
                    uncertainty_ms: 1000,
                },
                sample,
            )
            .unwrap(),
        ),
    }
}

#[test]
fn configured_request_has_exact_identity_target_and_no_extra_headers() {
    assert_eq!(
        document_request(&document()).unwrap(),
        b"GET /doc?edition=1 HTTP/1.1\r\nHost: document.example:8443\r\nConnection: close\r\n\r\n"
    );
}

#[test]
fn cached_certificate_coverage_never_extends_the_actual_clock_interval() {
    let cfg = document();
    let bounds = cfg.time.bounds().unwrap();
    let coverage = (bounds.0 - 1000, bounds.1 + 15_000);
    assert_eq!(crate::engine::within_coverage(&cfg, coverage), Ok(bounds));
    assert_eq!(crate::engine::within_coverage(&cfg, bounds), Ok(bounds));
    for narrow in [
        (bounds.0 + 1, bounds.1),
        (bounds.0, bounds.1 - 1),
        (bounds.1, bounds.0),
    ] {
        assert_eq!(
            crate::engine::within_coverage(&cfg, narrow),
            Err(Outcome::Time)
        );
    }
}

struct NoIo(Rc<Cell<bool>>);
impl Drop for NoIo {
    fn drop(&mut self) {
        self.0.set(true);
    }
}
impl absd_net::datagram::channel::Pipe for NoIo {
    fn now_ms(&self) -> u64 {
        100
    }
    fn read(&mut self, _: &mut [u8]) -> Result<Option<usize>, i64> {
        panic!("unexpected READ")
    }
    fn write(&mut self, _: &[u8]) -> Result<Option<usize>, i64> {
        panic!("unexpected CONNECT/WRITE")
    }
}
fn hooks() -> Hooks {
    Hooks {
        now_ms: || 100,
        pause_ms: |_| {},
        cancelled: || false,
        io_event: |_| panic!("unexpected network I/O"),
        phase_event: |_| {},
    }
}

fn refuses_before_ipc(document: &DocumentSettings<'_>, issuer: &[u8]) {
    let dropped = Rc::new(Cell::new(false));
    let report = crate::run_document(
        NoIo(dropped.clone()),
        issuer,
        Settings {
            unix_seconds: None,
            child_start_ms: 100,
            grant_expiry_ms: 15100,
            expected_body_len: 0,
        },
        hooks(),
        document,
    );
    assert_eq!(report.outcome, Outcome::Config);
    assert_eq!(report.phase, Phase::Fenced);
    assert_eq!(report.metrics.connect_calls, 0);
    assert_eq!(report.http_emitted, 0);
    assert!(
        report.document.is_none() && report.leaf_der.is_none() && report.verified_time.is_none()
    );
    assert!(dropped.get() && report.metrics.pipe_fenced);
}

#[test]
fn bad_configuration_and_pin_refuse_before_connect_or_http() {
    let issuer = std::fs::read(std::env::var("ABSD_TLS_ROOT_DER").unwrap()).unwrap();
    let der = rustls::pki_types::CertificateDer::from(issuer.as_slice());
    let parsed = rustls::server::ParsedCertificate::try_from(&der).unwrap();
    let spki = parsed.subject_public_key_info();
    let pin: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, spki.as_ref())
        .as_ref()
        .try_into()
        .unwrap();
    for name in [
        "",
        "UPPER.example",
        "document.example\r\nOther: x",
        "bad name",
        "é.example",
    ] {
        let mut cfg = document();
        cfg.issuer_spki = pin;
        cfg.name = name;
        assert!(document_request(&cfg).is_err());
        refuses_before_ipc(&cfg, &issuer);
    }
    for path in [
        "",
        "relative",
        "/with space",
        "/\r\nOther: x",
        "/#fragment",
        "/\0",
    ] {
        let mut cfg = document();
        cfg.issuer_spki = pin;
        cfg.path = path;
        assert!(document_request(&cfg).is_err());
        refuses_before_ipc(&cfg, &issuer);
    }
    for ip in [[0, 0, 0, 0], [224, 0, 0, 1], [255, 255, 255, 255]] {
        let mut cfg = document();
        cfg.issuer_spki = pin;
        cfg.peer.ip = ip;
        assert!(document_request(&cfg).is_err());
        refuses_before_ipc(&cfg, &issuer);
    }
    let mut cfg = document();
    cfg.issuer_spki = pin;
    cfg.peer.port = 0;
    assert!(document_request(&cfg).is_err());
    refuses_before_ipc(&cfg, &issuer);
    refuses_before_ipc(&document(), &issuer); // actual parsed SPKI differs from all-zero pin
    refuses_before_ipc(&document(), b"malformed DER");
}

#[test]
fn local_post_close_work_cannot_outlive_cancel_expiry_or_clock_boundaries() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(100);
    static CANCEL: AtomicBool = AtomicBool::new(false);
    let mut events = hooks();
    events.now_ms = || NOW.load(Ordering::Relaxed);
    events.cancelled = || CANCEL.load(Ordering::Relaxed);
    let mut transport =
        crate::transport::NativeTransport::new(NoIo(Rc::new(Cell::new(false))), 200, events);
    transport.fence();
    assert_eq!(transport.terminal_check(), Ok(()));
    NOW.store(199, Ordering::Relaxed);
    assert_eq!(transport.terminal_check(), Ok(()));
    NOW.store(198, Ordering::Relaxed);
    assert_eq!(transport.terminal_check(), Err(Outcome::Clock));
    NOW.store(200, Ordering::Relaxed);
    assert_eq!(transport.terminal_check(), Err(Outcome::Timeout));
    CANCEL.store(true, Ordering::Relaxed);
    assert_eq!(transport.terminal_check(), Err(Outcome::Cancelled));
}
