#![feature(restricted_std)]
//! One foreground unauthenticated observation through an exact UDP capability.
use absd_net::{
    datagram::{
        self as d,
        channel::{KernelPipe, transact},
    },
    dns::Datagram,
    sntp::{Error, Query, Refusal},
};

fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let until = start
        .checked_add(absd_net::sntp::TOTAL_MS)
        .ok_or("clock overflow")?;
    let mut last = start;
    let mut remaining = || -> Result<u64, String> {
        let now = absd_runtime::boot_millis();
        if now < last || now >= until {
            return Err("startup clock/deadline".into());
        }
        last = now;
        Ok(until - now)
    };
    absd_runtime::link_anchor();
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut bootstrap = [0; 7];
    let mut at = 0;
    while at < bootstrap.len() {
        let n = absd_runtime::read_within(input, &mut bootstrap[at..], remaining()?.min(1000))
            .map_err(|e| format!("bootstrap {e}"))?;
        remaining()?;
        if n == 0 {
            return Err("bootstrap EOF".into());
        }
        at += n;
    }
    let peer = d::Address {
        ip: bootstrap[1..5].try_into().unwrap(),
        port: u16::from_be_bytes([bootstrap[5], bootstrap[6]]),
    };
    if bootstrap[0] != 1
        || peer.port != 123
        || absd_runtime::nic::handle() != 0
        || absd_runtime::nic::info(input).is_ok()
    {
        return Err("bootstrap or NIC boundary".into());
    }
    let mut pipe = KernelPipe {
        request_reader: input,
        reply_writer: output,
    };
    let mut request = [0; 12];
    request[0] = d::VERSION;
    request[1] = d::SEND;
    request[4..8].copy_from_slice(&peer.ip);
    request[8..10].copy_from_slice(&124u16.to_be_bytes());
    let mut reply = [0; d::MAX_MESSAGE];
    transact(&mut pipe, &request, &mut reply, remaining()?.min(1000))
        .map_err(|e| format!("denial {e}"))?;
    remaining()?;
    if reply[2] != d::Error::Denied.code() {
        return Err("peer authority expanded".into());
    }
    let mut query = Query::with_start(
        Datagram::new(pipe, peer, absd_runtime::sleep_ticks),
        start,
        last,
    );
    let observed = match query.observe(getrandom_0_2::getrandom, absd_runtime::wall_clock_seconds) {
        Ok(observed) => observed,
        Err(Error::Refused(Refusal::EraUnknown)) => return Err("era=unknown".into()),
        Err(error) => return Err(format!("{error:?}")),
    };
    let rtc = match observed.rtc {
        Ok(seconds) => seconds.to_string(),
        Err(error) => format!("unavailable({error})"),
    };
    let difference = observed
        .unauthenticated_difference()
        .map_or("unknown".into(), |n| format!("{n}s"));
    eprintln!(
        "SNTP server_claimed_unix={} server_fraction_2p32={} rtc_unix={} boot_rtt_ms={} auth=none uncertainty=unknown unauthenticated_difference={} attempt={} denied=1 nic=0",
        observed.claim.unix_seconds,
        observed.claim.fraction_2p32,
        rtc,
        observed.boot_rtt_ms,
        difference,
        observed.attempt
    );
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("SNTP REFUSED {error} auth=none uncertainty=unknown");
            std::process::ExitCode::from(1)
        }
    }
}
