#![feature(restricted_std)]
//! Real DNS consumer with only its owner's dedicated pipe grant.
use absd_net::{
    datagram::{
        self as d,
        channel::{KernelPipe, transact},
    },
    dns::{Datagram, Resolver},
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
    if bootstrap[0] != 1
        || absd_runtime::nic::handle() != 0
        || absd_runtime::nic::info(input).is_ok()
    {
        return Err("bootstrap or NIC boundary".into());
    }
    let peer = d::Address {
        ip: bootstrap[1..5].try_into().unwrap(),
        port: u16::from_be_bytes([bootstrap[5], bootstrap[6]]),
    };
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    let mut request = [0; 12];
    request[0] = d::VERSION;
    request[1] = d::SEND;
    request[4..8].copy_from_slice(&peer.ip);
    request[8..10].copy_from_slice(&peer.port.wrapping_add(1).to_be_bytes());
    let mut reply = [0; d::MAX_MESSAGE];
    transact(&mut pipe, &request, &mut reply, 1000).map_err(|e| format!("denial {e}"))?;
    if reply[2] != d::Error::Denied.code() {
        return Err("resolver grant expanded".into());
    }
    let mut resolver = Resolver::with_entropy(
        Datagram::new(pipe, peer, absd_runtime::sleep_ticks),
        getrandom_0_2::getrandom,
    )
    .map_err(|e| format!("entropy {e}"))?;
    let answer = resolver
        .lookup("a.example")
        .map_err(|e| format!("DNS {e:?}"))?;
    if answer.count != 1 || answer.addresses[0] != [198, 51, 100, 9] {
        return Err("unexpected fixture answer".into());
    }
    eprintln!("DHCP DNS ANSWER 198.51.100.9 denied=1 nic=0");
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("DHCP DNS ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
