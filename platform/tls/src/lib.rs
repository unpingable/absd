#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! Bounded development fixture over one native exact-peer stream capability.
//! Fixture trust/time/RDRAND choices are not an Internet deployment policy.
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

pub use engine::{run, run_ipv6, Hooks, Outcome, Phase, Report, Settings};
pub use transport::{Direction, IoEvent, Metrics};
pub const PEER: absd_net::datagram::Address = absd_net::datagram::Address {
    ip: [10, 0, 2, 2],
    port: 4443,
};
pub const SERVER_NAME: &str = "absd-fixture.test";
