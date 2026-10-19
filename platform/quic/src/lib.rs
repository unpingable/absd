#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! One development QUIC client over existing exact-peer UDP authority.
//! Explicit fixture trust, time and entropy do not establish Internet policy.
pub const BODY_LEN: usize = 4096;
pub const SERVER_NAME: &str = "absd-fixture.test";
pub const ALPN: &[u8] = b"absd-echo/1";
pub const PEER: absd_net::datagram::Address = absd_net::datagram::Address {
    ip: [10, 0, 2, 2],
    port: 4443,
};

pub mod engine;
pub mod entropy;
pub mod fixture_cases;
pub mod fixture_family;
pub mod service_lifecycle;
pub mod transport;

#[cfg(test)]
mod transport_tests;
