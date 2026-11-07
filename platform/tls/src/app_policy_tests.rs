use crate::app_policy::{Anchor, AppTime, Sample, pinned_roots, verify_direct};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
    time_provider::TimeProvider,
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static SAMPLE: Mutex<Option<Sample>> = Mutex::new(None);
fn sample() -> Option<Sample> {
    *SAMPLE.lock().unwrap()
}
fn observe(pit_ms: u64, rtc_s: u64) {
    *SAMPLE.lock().unwrap() = Some(Sample {
        boot: [7; 16],
        pit_ms,
        rtc_s,
    });
}
fn anchor() -> Anchor {
    Anchor {
        boot: [7; 16],
        pit_ms: 10_000,
        rtc_s: 50_000,
        utc_ms: 1_800_000_000_000,
        uncertainty_ms: 100,
    }
}
fn time() -> AppTime {
    observe(anchor().pit_ms, anchor().rtc_s);
    AppTime::new(anchor(), sample).unwrap()
}

#[test]
fn operator_interval_advances_with_pit_and_conservative_rtc_upper_bound() {
    let _guard = TEST_LOCK.lock().unwrap();
    let t = time();
    let utc = anchor().utc_ms;
    assert_eq!(t.bounds(), Some((utc - 100, utc + 1100)));
    observe(10_900, 50_001);
    assert_eq!(t.bounds(), Some((utc - 100, utc + 2100)));
    assert_eq!(t.current_time().unwrap().as_secs(), utc / 1000 - 1);
    observe(12_500, 50_002);
    assert_eq!(t.bounds(), Some((utc + 900, utc + 3100)));
    assert_eq!(t.current_time().unwrap().as_secs(), utc / 1000);
}

#[test]
fn pit_can_be_the_larger_elapsed_clock_without_losing_uncertainty() {
    let _guard = TEST_LOCK.lock().unwrap();
    let t = time();
    observe(12_000, 50_000);
    assert_eq!(
        t.bounds(),
        Some((anchor().utc_ms - 100, anchor().utc_ms + 2100))
    );
}

#[test]
fn either_clock_regression_permanently_refuses_later_good_samples() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (pit, rtc) in [(10_999, 50_001), (11_000, 50_000)] {
        let t = time();
        observe(11_000, 50_001);
        assert!(t.bounds().is_some());
        observe(pit, rtc);
        assert!(t.bounds().is_none());
        observe(12_000, 50_002);
        assert!(t.bounds().is_none());
        assert!(t.current_time().is_none());
    }
}

#[test]
fn reboot_requires_a_new_attestation_and_cannot_revive_old_time() {
    let _guard = TEST_LOCK.lock().unwrap();
    let t = time();
    *SAMPLE.lock().unwrap() = Some(Sample {
        boot: [8; 16],
        pit_ms: 10_000,
        rtc_s: 50_000,
    });
    assert!(t.bounds().is_none());
    observe(10_000, 50_000);
    assert!(t.bounds().is_none());
    assert!(AppTime::new(anchor(), sample).is_ok());
}

#[test]
fn missing_clock_sample_is_sticky_and_never_uses_system_time() {
    let _guard = TEST_LOCK.lock().unwrap();
    let t = time();
    *SAMPLE.lock().unwrap() = None;
    assert!(t.current_time().is_none());
    observe(11_000, 50_001);
    assert!(t.bounds().is_none());
    *SAMPLE.lock().unwrap() = None;
    assert!(AppTime::new(anchor(), sample).is_err());
}

#[test]
fn contradictory_clocks_refuse_in_either_direction() {
    let _guard = TEST_LOCK.lock().unwrap();
    for (pit, rtc) in [(13_000, 50_000), (10_000, 50_003)] {
        let t = time();
        observe(pit, rtc);
        assert!(t.bounds().is_none());
        observe(13_000, 50_003);
        assert!(t.bounds().is_none());
    }
}

#[test]
fn fifteen_minute_upper_age_includes_rtc_quantization_and_anchor_uncertainty() {
    let _guard = TEST_LOCK.lock().unwrap();
    let t = time();
    observe(908_000, 50_898);
    assert!(t.bounds().is_some());
    observe(909_000, 50_899);
    assert!(t.bounds().is_none());
    observe(10_000, 50_000);
    assert!(t.bounds().is_none());
}

#[test]
fn malformed_imprecise_and_overflowing_anchors_refuse_before_use() {
    let _guard = TEST_LOCK.lock().unwrap();
    for a in [
        Anchor {
            utc_ms: 0,
            ..anchor()
        },
        Anchor {
            utc_ms: 100,
            uncertainty_ms: 100,
            ..anchor()
        },
        Anchor {
            uncertainty_ms: 1001,
            ..anchor()
        },
        Anchor {
            utc_ms: u64::MAX - 1000,
            ..anchor()
        },
    ] {
        observe(a.pit_ms, a.rtc_s);
        assert!(AppTime::new(a, sample).is_err(), "{a:?}");
    }
    observe(9999, 50_000);
    assert!(AppTime::new(anchor(), sample).is_err());
    observe(10_000, 49_999);
    assert!(AppTime::new(anchor(), sample).is_err());
}

#[test]
fn elapsed_rtc_multiplication_overflow_is_a_terminal_refusal() {
    let _guard = TEST_LOCK.lock().unwrap();
    let t = time();
    observe(10_000, u64::MAX);
    assert!(t.bounds().is_none());
    observe(10_000, 50_000);
    assert!(t.bounds().is_none());
}

#[test]
fn post_verification_bounds_may_reach_but_never_cross_the_checked_second() {
    let _guard = TEST_LOCK.lock().unwrap();
    let t = time();
    let verified = t.bounds().unwrap();
    let utc = anchor().utc_ms;
    assert_eq!(verified, (utc - 100, utc + 1100));
    // The actual verified upper endpoint is ceil(utc+1100 ms), or utc+2000.
    observe(11_500, 50_000);
    assert_eq!(t.checked_after(verified), Some((utc - 100, utc + 1600)));
    observe(11_900, 50_000);
    assert_eq!(t.checked_after(verified), Some((utc - 100, utc + 2000)));
    observe(11_901, 50_000);
    assert!(t.checked_after(verified).is_none());
    // Coverage refusal is terminal for the caller, but not a bad clock sample.
    let next = t.bounds().unwrap();
    assert_eq!(next.1, utc + 2001);
    assert_eq!(t.checked_after(next), Some(next));
    observe(12_000, 50_001);
    assert!(t.checked_after(verified).is_none());
}

#[test]
fn post_verification_check_requires_valid_bounds_and_both_endpoint_inclusions() {
    let _guard = TEST_LOCK.lock().unwrap();
    let t = time();
    let utc = anchor().utc_ms;
    for verified in [
        (0, 1),
        (2, 1),
        (utc, utc + 5001),
        (u64::MAX - 1, u64::MAX),
        (utc + 1000, utc + 3000), // checked lower endpoint excludes actual lower
        (utc - 100, utc + 1000),  // checked upper endpoint excludes actual upper
    ] {
        assert!(t.checked_after(verified).is_none(), "{verified:?}");
    }
    let verified = t.bounds().unwrap();
    assert_eq!(t.checked_after(verified), Some(verified));
}

#[test]
fn post_verification_stale_or_missing_observation_remains_sticky() {
    let _guard = TEST_LOCK.lock().unwrap();
    let t = time();
    let verified = t.bounds().unwrap();
    observe(909_000, 50_899);
    assert!(t.checked_after(verified).is_none());
    observe(10_000, 50_000);
    assert!(t.checked_after(verified).is_none());
    let t = time();
    let verified = t.bounds().unwrap();
    *SAMPLE.lock().unwrap() = None;
    assert!(t.checked_after(verified).is_none());
    observe(10_000, 50_000);
    assert!(t.bounds().is_none());
}

fn public_pki() -> (PathBuf, u64) {
    let root = PathBuf::from(
        std::env::var("ABSD_TLS_ROOT_DER").expect("sealed public TLS fixture required"),
    );
    let seconds = std::env::var("ABSD_TLS_UNIX_SECONDS")
        .expect("fixture UTC required")
        .parse()
        .unwrap();
    (root.parent().unwrap().to_path_buf(), seconds)
}
fn read(directory: &std::path::Path, name: &str) -> Vec<u8> {
    std::fs::read(directory.join(name)).unwrap()
}
fn spki_pin(issuer: &[u8]) -> [u8; 32] {
    let cert = CertificateDer::from(issuer);
    let parsed = ParsedCertificate::try_from(&cert).unwrap();
    ring::digest::digest(
        &ring::digest::SHA256,
        parsed.subject_public_key_info().as_ref(),
    )
    .as_ref()
    .try_into()
    .unwrap()
}

#[test]
fn direct_leaf_passes_with_the_spki_pin_but_not_the_whole_certificate_hash() {
    let (dir, seconds) = public_pki();
    let issuer = read(&dir, "root-A.der");
    let leaf = read(&dir, "valid.der");
    let pin = spki_pin(&issuer);
    assert!(pinned_roots(&issuer, &pin).is_ok());
    assert!(
        verify_direct(
            &issuer,
            &pin,
            &leaf,
            crate::SERVER_NAME,
            (seconds * 1000 - 100, seconds * 1000 + 1100)
        )
        .is_ok()
    );
    let der_hash: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &issuer)
        .as_ref()
        .try_into()
        .unwrap();
    assert_ne!(pin, der_hash);
    assert_eq!(
        pinned_roots(&issuer, &der_hash).unwrap_err(),
        "issuer SPKI pin mismatch"
    );
}

#[test]
fn same_name_wrong_issuer_key_cannot_replace_the_pin_or_sign_the_leaf() {
    let (dir, seconds) = public_pki();
    // The sealed fixture deliberately gives C the same subject and key identifier
    // as A, but a different public key; this leaf is signed only by C.
    let a = read(&dir, "root-A.der");
    let c = read(&dir, "root-C.der");
    let leaf = read(&dir, "signature-failure.der");
    let bounds = (seconds * 1000, seconds * 1000 + 1);
    assert_ne!(spki_pin(&a), spki_pin(&c));
    assert_eq!(
        pinned_roots(&c, &spki_pin(&a)).unwrap_err(),
        "issuer SPKI pin mismatch"
    );
    assert!(verify_direct(&a, &spki_pin(&a), &leaf, crate::SERVER_NAME, bounds).is_err());
    assert!(verify_direct(&c, &spki_pin(&c), &leaf, crate::SERVER_NAME, bounds).is_ok());
}

#[test]
fn canonical_hostname_signature_and_leaf_time_checks_remain_required() {
    let (dir, seconds) = public_pki();
    let issuer = read(&dir, "root-A.der");
    for file in [
        "wrong-name.der",
        "untrusted.der",
        "signature-failure.der",
        "expired.der",
        "future.der",
    ] {
        assert!(
            verify_direct(
                &issuer,
                &spki_pin(&issuer),
                &read(&dir, file),
                crate::SERVER_NAME,
                (seconds * 1000, seconds * 1000 + 1000)
            )
            .is_err(),
            "{file}"
        );
    }
    assert!(
        verify_direct(
            &issuer,
            &spki_pin(&issuer),
            &read(&dir, "valid.der"),
            "different.absd-fixture.test",
            (seconds * 1000, seconds * 1000)
        )
        .is_err()
    );
}

#[test]
fn entire_interval_must_precede_expiry_including_rounded_upper_endpoint() {
    let (dir, seconds) = public_pki();
    let issuer = read(&dir, "root-A.der");
    let leaf = read(&dir, "valid.der");
    let pin = spki_pin(&issuer);
    // The sealed recipe makes this leaf expire exactly 86400 s after its anchor.
    let end = (seconds + 86400) * 1000;
    assert!(
        verify_direct(
            &issuer,
            &pin,
            &leaf,
            crate::SERVER_NAME,
            (end - 2000, end - 1000)
        )
        .is_ok()
    );
    assert!(
        verify_direct(
            &issuer,
            &pin,
            &leaf,
            crate::SERVER_NAME,
            (end - 1000, end + 1)
        )
        .is_err()
    );
    // A single non-integral millisecond rounds the checked upper second upward.
    assert!(verify_direct(&issuer, &pin, &leaf, crate::SERVER_NAME, (end, end + 1)).is_err());
}

#[test]
fn rounded_lower_endpoint_cannot_start_before_leaf_validity() {
    let (dir, seconds) = public_pki();
    let issuer = read(&dir, "root-A.der");
    let leaf = read(&dir, "valid.der");
    let start = (seconds - 86400) * 1000;
    assert!(
        verify_direct(
            &issuer,
            &spki_pin(&issuer),
            &leaf,
            crate::SERVER_NAME,
            (start, start + 1000)
        )
        .is_ok()
    );
    assert!(
        verify_direct(
            &issuer,
            &spki_pin(&issuer),
            &leaf,
            crate::SERVER_NAME,
            (start - 1, start + 1000)
        )
        .is_err()
    );
}

#[test]
fn malformed_certificates_names_and_unbounded_intervals_refuse() {
    let (dir, seconds) = public_pki();
    let issuer = read(&dir, "root-A.der");
    let leaf = read(&dir, "valid.der");
    let pin = spki_pin(&issuer);
    for bad in [
        vec![],
        vec![0x30, 1, 0],
        issuer[..12].to_vec(),
        vec![0; 4097],
    ] {
        assert!(pinned_roots(&bad, &pin).is_err());
        assert!(
            verify_direct(
                &issuer,
                &pin,
                &bad,
                crate::SERVER_NAME,
                (seconds * 1000, seconds * 1000)
            )
            .is_err()
        );
    }
    for bounds in [(0, 1), (2, 1), (1, 5002), (u64::MAX - 1, u64::MAX)] {
        assert!(verify_direct(&issuer, &pin, &leaf, crate::SERVER_NAME, bounds).is_err());
    }
    assert!(
        verify_direct(
            &issuer,
            &pin,
            &leaf,
            "not a DNS name",
            (seconds * 1000, seconds * 1000)
        )
        .is_err()
    );
}

#[test]
fn a_valid_indirect_chain_is_refused_by_the_direct_issuer_policy() {
    let dir = PathBuf::from(
        std::env::var("ABSD_DOCUMENT_PKI_DIR")
            .expect("sealed public root/intermediate/leaf fixture required"),
    );
    let seconds: u64 = std::env::var("ABSD_DOCUMENT_UNIX_SECONDS")
        .expect("indirect fixture UTC required")
        .parse()
        .unwrap();
    let root = read(&dir, "root.der");
    let intermediate = read(&dir, "intermediate.der");
    let leaf = read(&dir, "leaf.der");
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.as_slice())).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();
    let name = ServerName::try_from(crate::SERVER_NAME).unwrap();
    assert!(
        verifier
            .verify_server_cert(
                &CertificateDer::from(leaf.as_slice()),
                &[CertificateDer::from(intermediate.as_slice())],
                &name,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(seconds))
            )
            .is_ok()
    );
    assert!(
        verify_direct(
            &root,
            &spki_pin(&root),
            &leaf,
            crate::SERVER_NAME,
            (seconds * 1000, seconds * 1000 + 1000)
        )
        .is_err()
    );
    // Direct trust of that actual intermediate is a distinct, explicit pin.
    assert!(
        verify_direct(
            &intermediate,
            &spki_pin(&intermediate),
            &leaf,
            crate::SERVER_NAME,
            (seconds * 1000, seconds * 1000 + 1000)
        )
        .is_ok()
    );
}
