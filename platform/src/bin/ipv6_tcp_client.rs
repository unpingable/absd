#![feature(restricted_std)]
//! A/AAAA DNS fallback over one explicitly paired scoped UDP/TCP capability.
use absd_net::{
    dns,
    ipv6::{
        self as v6,
        channel::{KernelPipe, Pipe, transact},
        session::*,
        stream,
    },
};
struct Borrowed<'a>(&'a mut KernelPipe);
impl Pipe for Borrowed<'_> {
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.0.read(b)
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.0.write(b)
    }
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
}
fn request(op: u8, peer: v6::Address) -> [u8; HEADER] {
    let mut b = [0; HEADER];
    b[0] = VERSION;
    b[1] = op;
    b[3] = FAMILY;
    b[4..20].copy_from_slice(&peer.ip);
    b[20..24].copy_from_slice(&peer.scope.to_be_bytes());
    b[24..26].copy_from_slice(&peer.port.to_be_bytes());
    b
}
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut bootstrap = [0; 22];
    let mut at = 0;
    while at < bootstrap.len() {
        let n = absd_runtime::read_within(input, &mut bootstrap[at..], 1000)
            .map_err(|e| format!("bootstrap {e}"))?;
        if n == 0 {
            return Err("bootstrap EOF".into());
        }
        at += n;
    }
    if absd_runtime::nic::handle() != 0 || absd_runtime::nic::info(input).is_ok() {
        return Err("unexpected NIC authority".into());
    }
    let peer = v6::Address {
        ip: bootstrap[..16].try_into().unwrap(),
        scope: u32::from_be_bytes(bootstrap[16..20].try_into().unwrap()),
        port: u16::from_be_bytes(bootstrap[20..22].try_into().unwrap()),
    };
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    let mut reply = [0; MAX_MESSAGE];
    for (op, bad) in [
        (
            stream::CONNECT,
            v6::Address {
                scope: peer.scope.wrapping_add(1),
                ..peer
            },
        ),
        (
            SEND,
            v6::Address {
                port: peer.port.wrapping_add(1),
                ..peer
            },
        ),
    ] {
        let n = transact(&mut pipe, &request(op, bad), &mut reply, 1000)
            .map_err(|e| format!("authority refusal {e}"))?;
        if n != HEADER || reply[2] != stream::Error::Denied.code() {
            return Err("paired authority expanded".into());
        }
    }
    eprintln!("IPV6 TCP CLIENT AUTHORITY PASS scope-and-peer-refused no-nic");
    let mut resolver = dns::Resolver::with_entropy(
        v6::dns_tcp::DatagramTcp::new(Borrowed(&mut pipe), peer, absd_runtime::sleep_ticks),
        getrandom_0_2::getrandom,
    )
    .map_err(|e| format!("DNS entropy {e:?}"))?;
    for name in ["a.example", "tc.example"] {
        let answer = resolver
            .lookup(name)
            .map_err(|e| format!("DNS A {name} {e:?}"))?;
        if answer.count != 1 || answer.addresses[0] != [192, 0, 2, 9] {
            return Err(format!("DNS A answer {answer:?}"));
        }
        eprintln!("IPV6 TCP DNS A PASS name={name} address=192.0.2.9");
    }
    let answer = resolver
        .lookup_aaaa("tcaaaa.example")
        .map_err(|e| format!("DNS AAAA fallback {e:?}"))?;
    let expected = core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9).octets();
    if answer.count != 1 || answer.addresses[0] != expected {
        return Err(format!("DNS AAAA answer {answer:?}"));
    }
    eprintln!("IPV6 TCP DNS AAAA PASS name=tcaaaa.example address=2001:db8::9");
    drop(resolver);
    let close = request(stream::CLOSE, peer);
    let n = transact(&mut pipe, &close, &mut reply, 1000).map_err(|e| format!("TCP close {e}"))?;
    if n != HEADER || reply[..HEADER] != close {
        return Err("TCP close reply".into());
    }
    eprintln!("IPV6 TCP DNS CLOSE PASS");
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("IPV6 TCP CLIENT ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
