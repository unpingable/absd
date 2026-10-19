#![feature(restricted_std)]
//! Actual DNS query to an exact closed IPv6 UDP peer, through one pipe grant.
use absd_net::{
    dns,
    ipv6::{
        self as v6,
        channel::{KernelPipe, Pipe, transact},
        session::*,
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
fn left(until: u64, last: &mut u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    if now < *last || now >= until {
        return Err("original boot budget".into());
    }
    *last = now;
    Ok(until - now)
}
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let local_until = start.checked_add(8000).ok_or("budget overflow")?;
    let mut last = start;
    absd_runtime::link_anchor();
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut bootstrap = [0; 30];
    let mut at = 0;
    while at < bootstrap.len() {
        let n = absd_runtime::read_within(
            input,
            &mut bootstrap[at..],
            left(local_until, &mut last)?.min(1000),
        )
        .map_err(|e| format!("bootstrap {e}"))?;
        left(local_until, &mut last)?;
        if n == 0 {
            return Err("bootstrap EOF".into());
        }
        at += n;
    }
    let until = local_until.min(u64::from_be_bytes(bootstrap[22..30].try_into().unwrap()));
    left(until, &mut last)?;
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
    request[20..24].copy_from_slice(&peer.scope.to_be_bytes());
    request[24..26].copy_from_slice(&peer.port.wrapping_add(1).to_be_bytes());
    let mut reply = [0; MAX_MESSAGE];
    let n = transact(
        &mut pipe,
        &request,
        &mut reply,
        left(until, &mut last)?.min(1000),
    )
    .map_err(|e| format!("peer refusal {e}"))?;
    left(until, &mut last)?;
    if n != HEADER || reply[2] != v6::Error::Denied.code() {
        return Err("peer authority expanded".into());
    }
    request.fill(0);
    request[0] = VERSION;
    request[1] = FEEDBACK;
    request[3] = FAMILY;
    request[4] = 1;
    let n = transact(
        &mut pipe,
        &request,
        &mut reply,
        left(until, &mut last)?.min(1000),
    )
    .map_err(|e| format!("feedback selector refusal {e}"))?;
    left(until, &mut last)?;
    if n != HEADER || reply[2] != v6::Error::Invalid.code() {
        return Err("feedback selector accepted".into());
    }
    eprintln!("IPV6 FEEDBACK AUTHORITY PASS wrong-peer-and-selector-refused no-nic");
    let lookup_start = absd_runtime::boot_millis();
    let outcome = {
        let mut resolver = dns::Resolver::with_entropy(
            v6::dns::Datagram::with_feedback(Borrowed(&mut pipe), peer, absd_runtime::sleep_ticks),
            getrandom_0_2::getrandom,
        )
        .map_err(|e| format!("DNS entropy {e:?}"))?;
        resolver.lookup("closed.example")
    };
    left(until, &mut last)?;
    match outcome {
        Err(dns::Error::Ipv6Feedback(v6::feedback::Observation {
            kind: 1,
            code: 4,
            detail: 0,
        })) => {}
        other => {
            return Err(format!(
                "expected exact peer Port Unreachable, got {other:?}"
            ));
        }
    }
    let elapsed = absd_runtime::boot_millis()
        .checked_sub(lookup_start)
        .ok_or("clock rewind")?;
    if elapsed >= dns::LOOKUP_MS {
        return Err("feedback arrived after DNS deadline".into());
    }
    request.fill(0);
    request[0] = VERSION;
    request[1] = CLOSE;
    request[3] = FAMILY;
    let n = transact(
        &mut pipe,
        &request,
        &mut reply,
        left(until, &mut last)?.min(1000),
    )
    .map_err(|e| format!("close {e}"))?;
    left(until, &mut last)?;
    if n != HEADER || reply[..HEADER] != request {
        return Err("close response".into());
    }
    eprintln!("IPV6 DNS FEEDBACK PASS type=1 code=4 detail=0 auth=none lookup_boot_ms={elapsed}");
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("IPV6 FEEDBACK CLIENT ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
