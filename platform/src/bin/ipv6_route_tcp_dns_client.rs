#![feature(restricted_std)]
//! Fixed paired routed-DNS consumer: pipe only, no NIC or spawn grant.
#[path = "../ipv6_route_tcp_fixture.rs"]
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
struct Borrowed<'a, P>(&'a mut P);
impl<P: v6::channel::Pipe> v6::channel::Pipe for Borrowed<'_, P> {
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        self.0.read(bytes)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        self.0.write(bytes)
    }
}
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
    // TCP denial replies identify the already selected grant, never the
    // substituted request. No rejected CONNECT may start a socket or ND.
    for changed in 0..3 {
        let mut request = [0; HEADER];
        request[..4].copy_from_slice(&[VERSION, v6::stream::CONNECT, 0, FAMILY]);
        request[4..20].copy_from_slice(&peer.ip);
        request[20..24].copy_from_slice(&peer.scope.to_be_bytes());
        request[24..26].copy_from_slice(&peer.port.to_be_bytes());
        request[[19, 23, 25][changed]] ^= 1;
        let mut reply = [0; MAX_MESSAGE];
        let n = transact(&mut pipe, &request, &mut reply, guard.check()?.min(1000))
            .map_err(|e| format!("framed TCP denial {e}"))?;
        guard.check()?;
        if n != HEADER
            || reply[..4]
                != [
                    VERSION,
                    v6::stream::CONNECT,
                    v6::stream::Error::Denied.code(),
                    FAMILY,
                ]
            || reply[4..20] != peer.ip
            || reply[20..24] != peer.scope.to_be_bytes()
            || reply[24..26] != peer.port.to_be_bytes()
            || reply[26..HEADER] != [0; HEADER - 26]
        {
            return Err("framed TCP authority expanded".into());
        }
    }
    eprintln!("ROUTE6TCP CLIENT AUTHORITY PASS nic=0 udp-denied=3 tcp-denied=3");
    let mut resolver = Resolver::with_entropy(
        v6::dns_tcp::DatagramTcp::new(Borrowed(&mut pipe), peer, absd_runtime::sleep_ticks),
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
    eprintln!("ROUTE6TCP DNS A PASS address=192.0.2.9");
    let answer = resolver
        .lookup_aaaa("aaaa.example")
        .map_err(|e| format!("DNS AAAA {e:?}"))?;
    guard.check()?;
    if answer.count != 1
        || answer.addresses[0] != [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]
    {
        return Err("DNS AAAA answer".into());
    }
    eprintln!("ROUTE6TCP DNS AAAA PASS address=2001:db8::9");
    drop(resolver);
    let mut close = [0; HEADER];
    close[..4].copy_from_slice(&[VERSION, v6::stream::CLOSE, 0, FAMILY]);
    close[4..20].copy_from_slice(&peer.ip);
    close[20..24].copy_from_slice(&peer.scope.to_be_bytes());
    close[24..26].copy_from_slice(&peer.port.to_be_bytes());
    let mut reply = [0; MAX_MESSAGE];
    guard.check()?;
    let n = transact(&mut pipe, &close, &mut reply, guard.check()?.min(1000))
        .map_err(|e| format!("TCP close {e}"))?;
    guard.check()?;
    if n != HEADER || reply[..HEADER] != close {
        return Err("TCP close reply".into());
    }
    eprintln!("ROUTE6TCP DNS CLOSE PASS");
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ROUTE6TCP CLIENT ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
