#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! Bounded TLS fixture and opt-in native document consumer over an exact-peer stream.
//! Preview 2 uses bounded RDRAND, without a production entropy or general trust claim.
//! See docs/NATIVE-HTTPS-DOCUMENT.md for operator time, issuer and pin contracts.
pub mod app_policy;
#[cfg(test)]
mod app_policy_tests;
#[cfg(test)]
mod document_interop_tests;
#[cfg(test)]
mod document_tests;
pub mod engine;
pub mod fixture_cases;
pub mod http;
pub mod ipv6_fixture;
pub mod link_observer;
pub mod time;
#[cfg(test)]
mod time_observation_tests;
pub mod transport;
#[cfg(test)]
mod transport_ipv6_tests;

pub use engine::{
    DocumentSettings, Hooks, Outcome, Phase, Report, Settings, run, run_document, run_ipv6,
};
pub use transport::{Direction, IoEvent, Metrics};
pub const PEER: absd_net::datagram::Address = absd_net::datagram::Address {
    ip: [10, 0, 2, 2],
    port: 4443,
};
pub const SERVER_NAME: &str = "absd-fixture.test";
