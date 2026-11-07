#![feature(restricted_std)]
//! One pipe-only consumer of a separately granted inbound IPv6 connection.
use absd_net::{
    datagram::channel::KernelPipe,
    ipv6::{
        self as v6,
        stream::{self as s, server as v},
    },
};
fn vector(name: &str) -> Vec<u8> {
    let text = include_str!("../../fixtures/native-ipv6-tcp-server/wire-v3.txt");
    let hex = text
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .expect("literal name");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("literal hex"))
        .collect()
}
#[path = "../ipv6_tcp_server_boundary_wire.rs"]
mod boundary_wire;
fn negative(pipe: &mut KernelPipe, until: u64) -> Result<(), String> {
    let cases = boundary_wire::cases();
    if cases.len() != 9 {
        return Err("negative case count".into());
    }
    let mut reply = [0; v::MAX_MESSAGE];
    for (name, request, expected) in cases {
        let left = until
            .checked_sub(absd_runtime::boot_millis())
            .filter(|n| *n > 0)
            .ok_or("negative deadline")?;
        let n = v::transact(pipe, &request[2..], &mut reply, left.min(1000))
            .map_err(|e| format!("negative {name} {e}"))?;
        let mut actual = (n as u16).to_be_bytes().to_vec();
        actual.extend_from_slice(&reply[..n]);
        if actual != expected {
            return Err(format!("negative typed reply {name}"));
        }
    }
    let left = until
        .checked_sub(absd_runtime::boot_millis())
        .filter(|n| *n > 0)
        .ok_or("negative listen deadline")?;
    let n = v::transact(pipe, &vector("listen")[2..], &mut reply, left.min(1000))
        .map_err(|e| format!("negative listen {e}"))?;
    let mut actual = (n as u16).to_be_bytes().to_vec();
    actual.extend_from_slice(&reply[..n]);
    if actual != vector("listening") {
        return Err("negative complete LISTEN reply".into());
    }
    eprintln!("IPV6 TCP SERVER NEG CHILD v=1 cases=9 listen=1 nic=0");
    let left = until
        .checked_sub(absd_runtime::boot_millis())
        .filter(|n| *n > 0)
        .ok_or("negative prefix deadline")?;
    if absd_runtime::write_within(pipe.reply_writer, &[0], left.min(50))
        .map_err(|e| format!("negative prefix {e}"))?
        != 1
    {
        return Err("negative short prefix write".into());
    }
    while absd_runtime::boot_millis() < until {
        absd_runtime::sleep_ticks(1);
    }
    Err("negative child not interrupted".into())
}
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let until = absd_runtime::boot_millis()
        .checked_add(8000)
        .ok_or("child overflow")?;
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut boot = [0; 23];
    let mut at = 0;
    while at < boot.len() {
        let now = absd_runtime::boot_millis();
        if now >= until {
            return Err("startup deadline".into());
        }
        let n = absd_runtime::read_within(input, &mut boot[at..], (until - now).min(1000))
            .map_err(|e| format!("bootstrap {e}"))?;
        if n == 0 {
            return Err("startup EOF".into());
        }
        at += n;
    }
    if boot[0] != v::VERSION
        || absd_runtime::nic::handle() != 0
        || absd_runtime::nic::info(input).is_ok()
    {
        return Err("startup authority".into());
    }
    let peer = v6::Address {
        ip: boot[1..17].try_into().unwrap(),
        scope: u32::from_be_bytes(boot[17..21].try_into().unwrap()),
        port: u16::from_be_bytes(boot[21..23].try_into().unwrap()),
    };
    let literal = vector("listen");
    if boot[1..] != literal[6..28] {
        return Err("literal/bootstrap peer correspondence".into());
    }
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    if std::env::args().nth(1).as_deref() == Some("--boundary-negative") {
        return negative(&mut pipe, until);
    }
    let mut reply = [0; v::MAX_MESSAGE];
    let wrong = vector("wrong-peer");
    let left = until
        .checked_sub(absd_runtime::boot_millis())
        .filter(|n| *n > 0)
        .ok_or("denial deadline")?;
    let n = v::transact(&mut pipe, &wrong[2..], &mut reply, left.min(1000))
        .map_err(|e| format!("denial {e}"))?;
    let mut framed = (n as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&reply[..n]);
    if framed != vector("denied") {
        return Err("peer authority expanded".into());
    }
    let mut client = v::Client::new(pipe, peer, absd_runtime::sleep_ticks);
    client.accept(until).map_err(|e| format!("accept {e:?}"))?;
    let mut total = 0;
    let mut bytes = [0; 511];
    loop {
        match client.read(&mut bytes, until) {
            Ok(n) => {
                total += n;
                if total > 3072 {
                    return Err("echo bound".into());
                }
                client
                    .write_all(&bytes[..n], until)
                    .map_err(|e| format!("echo {e:?}"))?;
            }
            Err(s::Error::Again) => absd_runtime::sleep_ticks(1),
            Err(s::Error::Eof) => break,
            Err(e) => return Err(format!("read {e:?}")),
        }
    }
    if total != 3072 {
        return Err(format!("body bytes {total}"));
    }
    // Peer EOF and all echoed bytes are complete. CLOSE both queues FIN and
    // spends the endpoint before the owner polls the FIN/ACK drain. A separate
    // SHUTDOWN_WRITE would leave a live endpoint that can reach Closed before
    // the subsequent CLOSE transaction and lose that transaction's reply.
    client.close(until).map_err(|e| format!("close {e:?}"))?;
    eprintln!("IPV6 TCP SERVER ECHO PASS v=1 bytes=3072 denied=1 nic=0");
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("IPV6 TCP SERVER ECHO ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
