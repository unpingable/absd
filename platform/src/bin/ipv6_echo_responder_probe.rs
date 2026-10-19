#![feature(restricted_std)]
//! Explicit sole-NIC-owner activation; a Linux ping is the intended consumer.
use absd_net::{
    NicLink,
    ipv6::echo_responder::{self, Owner},
};
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    absd_runtime::link_anchor();
    let link = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut owner =
        Owner::acquire(link, start, getrandom_0_2::getrandom).map_err(|e| format!("DAD {e:?}"))?;
    let endpoint = owner
        .activate(echo_responder::fixture_peer())
        .map_err(|e| format!("activation {e:?}"))?;
    println!(
        "PING6 RESPONDER READY local=fd00:ab5d::15 peer=fd00:ab5d::2 scope=1 replies=1 max_icmp_bytes=1240 stop_ms={}",
        owner.stop_ms()
    );
    let result = loop {
        owner.poll(endpoint).map_err(|e| {
            format!(
                "poll {e:?} possible_effects={}",
                owner.possible_reply_effects()
            )
        })?;
        match owner.observe(endpoint) {
            Ok(observation) => break observation,
            Err(echo_responder::Error::Again) => {}
            Err(e) => return Err(format!("observation {e:?}")),
        }
        owner.wait().map_err(|e| format!("wait {e:?}"))?;
    };
    owner.retire();
    if owner.socket_count() != 0 || owner.possible_reply_effects() != 1 {
        return Err("terminal owner state".into());
    }
    println!(
        "PING6 RESPONDER PASS peer=fd00:ab5d::2 scope=1 identifier={} sequence={} icmp_bytes={} submitted_at_ms={} possible_effects=1 sockets=0 auth=none",
        result.identifier, result.sequence, result.icmp_bytes, result.submitted_at_ms
    );
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("PING6 RESPONDER ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
