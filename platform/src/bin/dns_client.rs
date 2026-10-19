#![feature(restricted_std)]
//! A native hostname diagnostic. stdin/stdout carry one delegated datagram
//! channel, stderr carries human-readable results. No NIC or spawn authority.
use absd_net::{
    datagram::{
        self as d,
        channel::{KernelPipe, transact},
    },
    dns::{self, Datagram, Resolver},
};
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut bootstrap = [0; 7];
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
    if bootstrap[0] == 1 {
        absd_runtime::write_within(output, &[0], 50).map_err(|e| format!("partial {e}"))?;
        absd_runtime::sleep_ticks(600);
        return Ok(());
    }
    let peer = d::Address {
        ip: bootstrap[1..5].try_into().unwrap(),
        port: u16::from_be_bytes([bootstrap[5], bootstrap[6]]),
    };
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    // A request cannot expand the service's exact-peer grant.
    let mut denied = [0u8; 12];
    denied[0] = 1;
    denied[1] = d::SEND;
    denied[4..8].copy_from_slice(&peer.ip);
    denied[8..10].copy_from_slice(&peer.port.wrapping_add(1).to_be_bytes());
    let mut reply = [0; d::MAX_MESSAGE];
    transact(&mut pipe, &denied, &mut reply, 1000).map_err(|e| format!("denial {e}"))?;
    if reply[2] != d::Error::Denied.code() {
        return Err("peer authority expanded".into());
    }
    let mut resolver = Resolver::with_entropy(
        Datagram::new(pipe, peer, absd_runtime::sleep_ticks),
        getrandom_0_2::getrandom,
    )
    .map_err(|error| format!("DNS entropy {error}"))?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--icmp") {
        let result = resolver.lookup("icmp.example");
        eprintln!("ICMP DNS LOOKUP name=icmp.example result={result:?}");
        if result
            != Err(dns::Error::Transport(d::Error::Icmp(
                absd_net::icmp::Error::DestinationUnreachable { code: 3 },
            )))
        {
            return Err("expected native ICMP port-unreachable".into());
        }
    } else if args.first().map(String::as_str) == Some("--suite") {
        for (name, expected) in [
            ("a.example", None),
            ("cname.example", None),
            ("order.example", None),
            ("nx.example", Some(dns::Error::NxDomain)),
            ("empty.example", Some(dns::Error::NoAddress)),
            ("fail.example", Some(dns::Error::ServerFailure)),
            ("refused.example", Some(dns::Error::Refused)),
            ("tc.example", Some(dns::Error::Truncated)),
            ("bad.example", Some(dns::Error::Malformed)),
            ("loop.example", Some(dns::Error::CnameLoop)),
            ("match.example", None),
            ("retry.example", None),
            ("after.example", None),
            ("absent.example", Some(dns::Error::Timeout)),
        ] {
            let result = resolver.lookup(name);
            eprintln!("DNS LOOKUP name={name} result={result:?}");
            match (result, expected) {
                (Ok(a), None) if a.count == 1 && a.addresses[0] == [192, 0, 2, 9] => {}
                (Err(actual), Some(expected)) if actual == expected => {}
                _ => return Err(format!("unexpected result for {name}")),
            }
        }
        if resolver.lookup("a.example") != Err(dns::Error::Transport(d::Error::Stale)) {
            return Err("timed-out resolver revived".into());
        }
        eprintln!("DNS TIMEOUT FENCED fresh-channel-required");
    } else {
        let name = args.first().ok_or("expected hostname")?;
        let answer = resolver.lookup(name);
        eprintln!("DNS LOOKUP name={name} result={answer:?}");
        answer.map_err(|e| format!("lookup {e:?}"))?;
    }
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("DNS CLIENT ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
