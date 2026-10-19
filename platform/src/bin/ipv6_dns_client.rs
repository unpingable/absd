#![feature(restricted_std)]
//! A DNS consumer with one IPv6 UDP pipe grant and no NIC/spawn authority.
use absd_net::{
    dns::Resolver,
    ipv6::{
        self as v6,
        channel::{KernelPipe, transact},
        session::*,
    },
};

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
    let mut request = [0; HEADER];
    request[0] = VERSION;
    request[1] = SEND;
    request[3] = FAMILY;
    request[4..20].copy_from_slice(&peer.ip);
    request[20..24].copy_from_slice(&peer.scope.wrapping_add(1).to_be_bytes());
    request[24..26].copy_from_slice(&peer.port.to_be_bytes());
    let mut reply = [0; MAX_MESSAGE];
    let n = transact(&mut pipe, &request, &mut reply, 1000)
        .map_err(|e| format!("scope refusal {e}"))?;
    if n != HEADER || reply[2] != v6::Error::Denied.code() {
        return Err("scope authority expanded".into());
    }
    request[20..24].copy_from_slice(&peer.scope.to_be_bytes());
    request[24..26].copy_from_slice(&peer.port.wrapping_add(1).to_be_bytes());
    let n =
        transact(&mut pipe, &request, &mut reply, 1000).map_err(|e| format!("peer refusal {e}"))?;
    if n != HEADER || reply[2] != v6::Error::Denied.code() {
        return Err("peer authority expanded".into());
    }
    eprintln!("IPV6 CLIENT AUTHORITY PASS scope-and-peer-refused no-nic");
    let mut resolver = Resolver::with_entropy(
        v6::dns::Datagram::new(pipe, peer, absd_runtime::sleep_ticks),
        getrandom_0_2::getrandom,
    )
    .map_err(|e| format!("DNS entropy {e:?}"))?;
    let answer = resolver
        .lookup("a.example")
        .map_err(|e| format!("DNS over IPv6 {e:?}"))?;
    if answer.count != 1 || answer.addresses[0] != [192, 0, 2, 9] {
        return Err(format!("unexpected DNS answer {answer:?}"));
    }
    eprintln!("IPV6 DNS A PASS address=192.0.2.9");
    let answer = resolver
        .lookup_aaaa("aaaa.example")
        .map_err(|e| format!("AAAA over IPv6 {e:?}"))?;
    let expected = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    if answer.count != 1 || answer.addresses[0] != expected {
        return Err(format!("unexpected AAAA answer {answer:?}"));
    }
    eprintln!("IPV6 DNS AAAA PASS address=2001:db8::9");
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("IPV6 CLIENT ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
