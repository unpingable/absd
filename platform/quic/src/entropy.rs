//! Explicit native entropy before construction; no ambient Quinn RNG route.
use quinn_proto::{ConnectionId, ConnectionIdGenerator};
use rand::{Rng, SeedableRng, rngs::StdRng};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

static MATERIAL_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
pub fn material_attempts() -> u64 {
    MATERIAL_ATTEMPTS.load(Ordering::Relaxed)
}

static UNEXPECTED_DRAWS: AtomicU64 = AtomicU64::new(0);
pub fn unexpected_draws() -> u64 {
    UNEXPECTED_DRAWS.load(Ordering::Relaxed)
}

#[cfg(all(target_os = "absd", not(getrandom_backend = "custom")))]
compile_error!("native QUIC requires the explicit refusing getrandom 0.4 custom backend");

// The selected rand dependency still compiles getrandom 0.4. Active protocol
// paths receive explicit seeds; an unexpected ambient call must refuse.
#[cfg(target_os = "absd")]
#[unsafe(no_mangle)]
unsafe fn __getrandom_v03_custom(
    _destination: *mut u8,
    _length: usize,
) -> Result<(), getrandom_new::Error> {
    UNEXPECTED_DRAWS.fetch_add(1, Ordering::Relaxed);
    Err(getrandom_new::Error::UNSUPPORTED)
}

pub struct Material {
    pub endpoint: [u8; 32],
    pub cid: [u8; 32],
    pub reset: [u8; 64],
    pub initial: [u8; 20],
}
impl Material {
    pub fn acquire() -> Result<Self, &'static str> {
        MATERIAL_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        let mut material = Self {
            endpoint: [0; 32],
            cid: [0; 32],
            reset: [0; 64],
            initial: [0; 20],
        };
        let rng = SystemRandom::new();
        for bytes in [
            &mut material.endpoint[..],
            &mut material.cid[..],
            &mut material.reset[..],
            &mut material.initial[..],
        ] {
            if rng.fill(bytes).is_err() {
                return Err("explicit ring entropy refused");
            }
        }
        Ok(material)
    }
}
impl Drop for Material {
    fn drop(&mut self) {
        self.endpoint.zeroize();
        self.cid.zeroize();
        self.reset.zeroize();
        self.initial.zeroize();
    }
}

// Fresh endpoint configuration is used once. No Debug implementation exposes
// this seed or RNG state, and no default/random/hashed CID generator is used.
pub struct SeededIds(StdRng);
impl SeededIds {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(StdRng::from_seed(seed))
    }
}
impl ConnectionIdGenerator for SeededIds {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes = [0; 16];
        self.0.fill_bytes(&mut bytes);
        ConnectionId::new(&bytes)
    }
    fn cid_len(&self) -> usize {
        16
    }
    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        None
    }
}
