//! Application-local operator time and a pinned direct certificate issuer.
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
    time_provider::TimeProvider,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const MAX_AGE_MS: u64 = 15 * 60 * 1000;
const MAX_UNCERTAINTY_MS: u64 = 1000;
const MAX_CLOCK_DIFFERENCE_MS: u64 = 2000;
const MAX_INTERVAL_MS: u64 = 5000;

#[derive(Clone, Copy, Debug)]
pub struct Anchor {
    pub boot: [u8; 16],
    pub pit_ms: u64,
    pub rtc_s: u64,
    pub utc_ms: u64,
    pub uncertainty_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub boot: [u8; 16],
    pub pit_ms: u64,
    pub rtc_s: u64,
}

#[derive(Debug)]
pub struct AppTime {
    anchor: Anchor,
    sample: fn() -> Option<Sample>,
    last: Mutex<Option<Sample>>,
}

impl AppTime {
    pub fn new(anchor: Anchor, sample: fn() -> Option<Sample>) -> Result<Self, &'static str> {
        if anchor.utc_ms == 0 || anchor.uncertainty_ms > MAX_UNCERTAINTY_MS {
            return Err("invalid time anchor precision");
        }
        anchor
            .utc_ms
            .checked_sub(anchor.uncertainty_ms)
            .filter(|n| *n > 0)
            .ok_or("time anchor underflow")?;
        anchor
            .utc_ms
            .checked_add(MAX_AGE_MS)
            .and_then(|n| n.checked_add(anchor.uncertainty_ms))
            .ok_or("time anchor overflow")?;
        let time = Self {
            anchor,
            sample,
            last: Mutex::new(Some(Sample {
                boot: anchor.boot,
                pit_ms: anchor.pit_ms,
                rtc_s: anchor.rtc_s,
            })),
        };
        time.bounds().ok_or("unusable time observation")?;
        Ok(time)
    }

    /// Any missing, contradictory, expired or regressed observation is terminal.
    /// This assumes the attested clocks keep running; it does not set system time.
    pub fn bounds(&self) -> Option<(u64, u64)> {
        let mut last = self.last.lock().ok()?;
        let previous = (*last)?;
        let result = (|| {
            let now = (self.sample)()?;
            if now.boot != self.anchor.boot
                || now.pit_ms < previous.pit_ms
                || now.rtc_s < previous.rtc_s
            {
                return None;
            }
            let pit = now.pit_ms.checked_sub(self.anchor.pit_ms)?;
            let rtc = now
                .rtc_s
                .checked_sub(self.anchor.rtc_s)?
                .checked_mul(1000)?;
            if pit.abs_diff(rtc) > MAX_CLOCK_DIFFERENCE_MS {
                return None;
            }
            let upper_age = pit
                .max(rtc.checked_add(1000)?)
                .checked_add(self.anchor.uncertainty_ms)?;
            if upper_age >= MAX_AGE_MS {
                return None;
            }
            let lower_age = pit.min(rtc.saturating_sub(1000));
            let lower = self
                .anchor
                .utc_ms
                .checked_sub(self.anchor.uncertainty_ms)?
                .checked_add(lower_age)?;
            let upper = self.anchor.utc_ms.checked_add(upper_age)?;
            if upper.checked_sub(lower)? > MAX_INTERVAL_MS {
                return None;
            }
            Some((now, lower, upper))
        })();
        match result {
            Some((now, lower, upper)) => {
                *last = Some(now);
                Some((lower, upper))
            }
            None => {
                *last = None;
                None
            }
        }
    }

    /// The caller must already have verified the leaf over `verified`.
    /// Refuse if fresh bounds escape the checked, outward-rounded endpoints.
    pub fn checked_after(&self, verified: (u64, u64)) -> Option<(u64, u64)> {
        let fresh = self.bounds()?;
        let (lower, upper) = verified;
        if lower == 0 || upper < lower || upper - lower > MAX_INTERVAL_MS {
            return None;
        }
        let floor = (lower / 1000).checked_mul(1000)?;
        let ceiling = (upper.checked_add(999)? / 1000).checked_mul(1000)?;
        (fresh.0 >= floor && fresh.1 <= ceiling).then_some(fresh)
    }
}

impl TimeProvider for AppTime {
    fn current_time(&self) -> Option<UnixTime> {
        let (lower, _) = self.bounds()?;
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            lower / 1000,
        )))
    }
}

pub fn pinned_roots(issuer: &[u8], pin: &[u8; 32]) -> Result<RootCertStore, &'static str> {
    if issuer.is_empty() || issuer.len() > 4096 {
        return Err("invalid issuer size");
    }
    let der = CertificateDer::from(issuer);
    let parsed = ParsedCertificate::try_from(&der).map_err(|_| "malformed issuer")?;
    let spki = parsed.subject_public_key_info();
    if ring::digest::digest(&ring::digest::SHA256, spki.as_ref()).as_ref() != pin {
        return Err("issuer SPKI pin mismatch");
    }
    let mut roots = RootCertStore::empty();
    roots.add(der).map_err(|_| "invalid issuer trust anchor")?;
    Ok(roots)
}

pub fn verify_direct(
    issuer: &[u8],
    pin: &[u8; 32],
    leaf: &[u8],
    name: &str,
    bounds: (u64, u64),
) -> Result<(), &'static str> {
    let (lower, upper) = bounds;
    if lower == 0 || upper < lower || upper - lower > MAX_INTERVAL_MS {
        return Err("invalid certificate time interval");
    }
    if leaf.is_empty() || leaf.len() > 4096 {
        return Err("invalid leaf size");
    }
    let ceiling = upper.checked_add(999).ok_or("certificate time overflow")? / 1000;
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(pinned_roots(issuer, pin)?),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|_| "issuer verifier construction failed")?;
    let server_name = ServerName::try_from(name).map_err(|_| "invalid server name")?;
    let leaf = CertificateDer::from(leaf);
    // With one pinned anchor and no intermediates there is no alternate chain:
    // the same leaf must be directly signed by that key and valid at both ends.
    for seconds in [lower / 1000, ceiling] {
        let now = UnixTime::since_unix_epoch(Duration::from_secs(seconds));
        verifier
            .verify_server_cert(&leaf, &[], &server_name, &[], now)
            .map_err(|_| "direct issuer, hostname or interval verification failed")?;
    }
    Ok(())
}
