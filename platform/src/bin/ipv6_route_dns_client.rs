#![feature(restricted_std)]
//! Fixed routed-DNS consumer: pipe only, no NIC or spawn grant.
#[path = "../ipv6_route_fixture.rs"]
mod fixture;
#[path = "../ipv6_route_guard.rs"]
mod guarded;
use absd_net::{
    dns::Resolver,
    ipv6::{
        self as v6,
        channel::{KernelPipe, transact},
        session::*,
    },
};
use guarded::{BoundPipe, Guard};
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let start: u64 = std::env::var("ABSD_ROUTE6_START_MS")
        .map_err(|_| "start missing")?
        .parse()
        .map_err(|_| "start invalid")?;
    let stop: u64 = std::env::var("ABSD_ROUTE6_STOP_MS")
        .map_err(|_| "stop missing")?
        .parse()
        .map_err(|_| "stop invalid")?;
    let guard = Guard::new(start, stop)?;
    let (input, output) = absd_runtime::standard_stream_handles();
    if absd_runtime::nic::handle() != 0 || absd_runtime::nic::info(input).is_ok() {
        return Err("NIC authority expanded".into());
    }
    guard.check()?;
    let mut bootstrap = [0; fixture::BOOTSTRAP_LEN];
    let mut at = 0;
    while at < bootstrap.len() {
        let r = absd_runtime::read_within(input, &mut bootstrap[at..], guard.check()?.min(250));
        guard.check()?;
        let n = r.map_err(|e| format!("bootstrap {e}"))?;
        if n == 0 || n > bootstrap.len() - at {
            return Err("bootstrap EOF/count".into());
        }
        at += n;
    }
    fixture::decode(&bootstrap, start, stop)?;
    let peer = v6::Address {
        ip: fixture::PEER,
        scope: fixture::SCOPE,
        port: fixture::PORT,
    };
    let mut pipe = BoundPipe {
        inner: KernelPipe {
            request_reader: input,
            reply_writer: output,
        },
        guard: guard.clone(),
    };
    // These are real framed service denials, not wire packet substitutions.
    for changed in 0..3 {
        let mut request = [0; HEADER];
        request[..4].copy_from_slice(&[VERSION, SEND, 0, FAMILY]);
        request[4..20].copy_from_slice(&peer.ip);
        request[20..24].copy_from_slice(&peer.scope.to_be_bytes());
        request[24..26].copy_from_slice(&peer.port.to_be_bytes());
        request[[19, 23, 25][changed]] ^= 1;
        let mut reply = [0; MAX_MESSAGE];
        let n = transact(&mut pipe, &request, &mut reply, guard.check()?.min(1000))
            .map_err(|e| format!("framed denial {e}"))?;
        guard.check()?;
        if n != HEADER
            || reply[..4] != [VERSION, SEND, v6::Error::Denied.code(), FAMILY]
            || reply[4..HEADER] != [0; HEADER - 4]
        {
            return Err("framed authority expanded".into());
        }
    }
    eprintln!("ROUTE6 CLIENT AUTHORITY PASS nic=0 framed-denied=3");
    let mut resolver = Resolver::with_entropy(
        v6::dns::Datagram::new(pipe, peer, absd_runtime::sleep_ticks),
        getrandom_0_2::getrandom,
    )
    .map_err(|e| format!("entropy {e:?}"))?;
    guard.check()?;
    let answer = resolver
        .lookup("a.example")
        .map_err(|e| format!("DNS A {e:?}"))?;
    guard.check()?;
    if answer.count != 1 || answer.addresses[0] != [192, 0, 2, 9] {
        return Err("DNS A answer".into());
    }
    eprintln!("ROUTE6 DNS A PASS address=192.0.2.9");
    let answer = resolver
        .lookup_aaaa("aaaa.example")
        .map_err(|e| format!("DNS AAAA {e:?}"))?;
    guard.check()?;
    if answer.count != 1
        || answer.addresses[0] != [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]
    {
        return Err("DNS AAAA answer".into());
    }
    eprintln!("ROUTE6 DNS AAAA PASS address=2001:db8::9");
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ROUTE6 CLIENT ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
