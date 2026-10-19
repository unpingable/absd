//! Actual FixtureTime/standard-verifier countertrace, not a native TLS run.
use crate::time::FixtureTime;
use absd_net::{
    datagram,
    dns::{self, Transport},
    sntp::{Error, Query, Refusal},
};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    time_provider::TimeProvider,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

const ANCHOR_2026: u64 = 1_767_268_800;
const CLAIM_2036: u64 = 2_082_801_600;
const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
fn boot() -> u64 {
    1000
}
struct Reply;
impl Transport for Reply {
    fn now_ms(&self) -> u64 {
        boot()
    }
    fn pause(&mut self, _: u64) {
        panic!("one immediate fixture reply");
    }
    fn send(&mut self, bytes: &[u8], _: u64) -> Result<(), dns::Error> {
        assert_eq!(bytes.len(), 48);
        assert_eq!(bytes[40..48], NONCE);
        Ok(())
    }
    fn receive(
        &mut self,
        bytes: &mut [u8; datagram::MAX_DATAGRAM],
        _: u64,
    ) -> Result<Option<usize>, dns::Error> {
        bytes[..48].fill(0);
        bytes[0] = 0x24;
        bytes[1] = 10;
        bytes[24..32].copy_from_slice(&NONCE);
        let base = (CLAIM_2036 + 2_208_988_800) << 32;
        bytes[16..24].copy_from_slice(&(base - (1u64 << 32)).to_be_bytes());
        bytes[32..40].copy_from_slice(&(base + 1).to_be_bytes());
        bytes[40..48].copy_from_slice(&(base + 2).to_be_bytes());
        Ok(Some(48))
    }
}
#[test]
fn rejected_2036_claim_cannot_replace_the_2026_fixture_anchor_or_validate_future_leaf() {
    // These independent public inputs are made only by the separately admitted
    // recipe; no key/certificate generation or silent skip occurs in this test.
    let directory = PathBuf::from(
        std::env::var("ABSD_SNTP_TIME_DER_DIR")
            .expect("sealed SNTP time certificate inputs required"),
    );
    let read = |name: &str| CertificateDer::from(std::fs::read(directory.join(name)).unwrap());
    let mut roots = RootCertStore::empty();
    roots.add(read("root.der")).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();
    let name = ServerName::try_from(crate::SERVER_NAME).unwrap();
    let provider = FixtureTime::new(Some(ANCHOR_2026), 1000, 16000, boot).unwrap();
    let anchored = provider.current_time().unwrap();
    assert_eq!(anchored.as_secs(), ANCHOR_2026);
    assert!(
        verifier
            .verify_server_cert(&read("leaf-2026.der"), &[], &name, &[], anchored)
            .is_ok()
    );
    let future = read("leaf-2036.der");
    let verify =
        || verifier.verify_server_cert(&future, &[], &name, &[], provider.current_time().unwrap());
    assert!(matches!(
        verify(),
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidYet
                | rustls::CertificateError::NotValidYetContext { .. }
        ))
    ));
    let mut query = Query::new(Reply);
    assert_eq!(
        query.observe(
            |b| {
                b.copy_from_slice(&NONCE);
                Ok::<_, ()>(())
            },
            || Ok(CLAIM_2036)
        ),
        Err(Error::Refused(Refusal::EraUnknown))
    );
    assert_eq!(provider.current_time().unwrap().as_secs(), ANCHOR_2026);
    assert!(matches!(
        verify(),
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidYet
                | rustls::CertificateError::NotValidYetContext { .. }
        ))
    ));
    // Positive control: this exact signature/name/chain succeeds in 2036.
    // Therefore its 2026 refusal is not a bad certificate or absent trust root.
    let future_time = UnixTime::since_unix_epoch(Duration::from_secs(CLAIM_2036));
    assert!(
        verifier
            .verify_server_cert(&future, &[], &name, &[], future_time)
            .is_ok()
    );
}

const CLAIM_2030: u64 = 1_893_456_000;
struct Accepted2030Reply;
impl Transport for Accepted2030Reply {
    fn now_ms(&self) -> u64 {
        boot()
    }
    fn pause(&mut self, _: u64) {
        panic!("one immediate fixture reply");
    }
    fn send(&mut self, bytes: &[u8], deadline: u64) -> Result<(), dns::Error> {
        Reply.send(bytes, deadline)
    }
    fn receive(
        &mut self,
        bytes: &mut [u8; datagram::MAX_DATAGRAM],
        deadline: u64,
    ) -> Result<Option<usize>, dns::Error> {
        // Preserve the existing valid packet envelope and nonce; only its
        // civil stamps change from the refused era to an accepted 2030 claim.
        let length = Reply.receive(bytes, deadline)?;
        let base = (CLAIM_2030 + 2_208_988_800) << 32;
        bytes[16..24].copy_from_slice(&(base - (1u64 << 32)).to_be_bytes());
        bytes[32..40].copy_from_slice(&(base + 1).to_be_bytes());
        bytes[40..48].copy_from_slice(&(base + 2).to_be_bytes());
        Ok(length)
    }
}

#[test]
fn accepted_2030_claim_cannot_replace_the_2026_fixture_anchor_or_validate_future_leaf() {
    let directory = PathBuf::from(
        std::env::var("ABSD_SNTP_TIME_DER_DIR")
            .expect("sealed SNTP time certificate inputs required"),
    );
    let read = |name: &str| CertificateDer::from(std::fs::read(directory.join(name)).unwrap());
    let mut roots = RootCertStore::empty();
    roots.add(read("root.der")).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();
    let name = ServerName::try_from(crate::SERVER_NAME).unwrap();
    let provider = FixtureTime::new(Some(ANCHOR_2026), 1000, 16000, boot).unwrap();
    let anchored = provider.current_time().unwrap();
    assert_eq!(anchored.as_secs(), ANCHOR_2026);
    assert!(
        verifier
            .verify_server_cert(&read("leaf-2026.der"), &[], &name, &[], anchored)
            .is_ok()
    );
    let future = read("leaf-2036.der");
    let verify =
        || verifier.verify_server_cert(&future, &[], &name, &[], provider.current_time().unwrap());
    assert!(matches!(
        verify(),
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidYet
                | rustls::CertificateError::NotValidYetContext { .. }
        ))
    ));
    let rtc_reads = core::cell::Cell::new(0usize);
    let mut query = Query::new(Accepted2030Reply);
    let observed = query
        .observe(
            |b| {
                b.copy_from_slice(&NONCE);
                Ok::<_, ()>(())
            },
            || {
                rtc_reads.set(rtc_reads.get() + 1);
                Ok(CLAIM_2030)
            },
        )
        .expect("nonce-matched in-era 2030 claim must be accepted");
    assert_eq!(observed.claim.unix_seconds, CLAIM_2030);
    assert_eq!(observed.claim.fraction_2p32, 2);
    assert_eq!(observed.rtc, Ok(CLAIM_2030));
    assert_eq!(rtc_reads.get(), 1, "acceptance reaches the RTC observation");
    assert_eq!(observed.boot_sent_ms, 1000);
    assert_eq!(observed.boot_received_ms, 1000);
    assert_eq!(observed.boot_rtt_ms, 0);
    assert_eq!(provider.current_time().unwrap().as_secs(), ANCHOR_2026);
    assert!(matches!(
        verify(),
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidYet
                | rustls::CertificateError::NotValidYetContext { .. }
        ))
    ));
    // The same sealed public leaf is valid at an explicit future anchor.
    // An accepted unauthenticated observation supplies no such TLS anchor.
    let future_time = UnixTime::since_unix_epoch(Duration::from_secs(CLAIM_2036));
    assert!(
        verifier
            .verify_server_cert(&future, &[], &name, &[], future_time)
            .is_ok()
    );
}
