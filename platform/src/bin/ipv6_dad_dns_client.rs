#![feature(restricted_std)]
//! Bounded DNS A/AAAA child; only a dedicated pipe capability is inherited.
use absd_net::{
    dns::Resolver,
    ipv6::{
        self as v6,
        channel::{KernelPipe, Pipe, transact},
        dad,
        session::*,
    },
};
use core::cell::Cell;
struct BudgetPipe {
    pipe: KernelPipe,
    until: u64,
    last: Cell<u64>,
    live: Cell<bool>,
}
impl BudgetPipe {
    fn check(&self) -> Result<(), i64> {
        let now = absd_runtime::boot_millis();
        if !self.live.get() || now < self.last.get() || now >= self.until {
            self.live.set(false);
            return Err(-125);
        }
        self.last.set(now);
        Ok(())
    }
}
impl Pipe for BudgetPipe {
    fn now_ms(&self) -> u64 {
        let _ = self.check();
        absd_runtime::boot_millis()
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.check()?;
        let r = self.pipe.read(b);
        let after = self.check();
        if r.is_err() {
            self.live.set(false);
        }
        after?;
        r
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.check()?;
        let r = self.pipe.write(b);
        let after = self.check();
        if r.is_err() {
            self.live.set(false);
        }
        after?;
        r
    }
}
struct Borrowed<'a>(&'a mut BudgetPipe);
impl Pipe for Borrowed<'_> {
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.0.read(b)
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.0.write(b)
    }
}
fn run() -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let local_end = start
        .checked_add(dad::TOTAL_MS)
        .ok_or("startup clock overflow")?;
    let mut last = start;
    absd_runtime::link_anchor();
    let (input, output) = absd_runtime::standard_stream_handles();
    let mut b = [0; dad::BOOTSTRAP_LEN];
    let mut at = 0;
    while at < b.len() {
        let now = absd_runtime::boot_millis();
        if now < last || now >= local_end {
            return Err("startup budget".into());
        }
        last = now;
        let r = absd_runtime::read_within(input, &mut b[at..], (local_end - now).min(1000));
        let now = absd_runtime::boot_millis();
        if now < last || now >= local_end {
            return Err("startup post-read budget".into());
        }
        last = now;
        let n = r.map_err(|e| format!("bootstrap {e}"))?;
        if n == 0 {
            return Err("bootstrap EOF".into());
        }
        at += n;
    }
    let (peer, until) = dad::decode_bootstrap(&b, absd_runtime::boot_millis())
        .map_err(|e| format!("bootstrap policy {e:?}"))?;
    if absd_runtime::nic::handle() != 0 || absd_runtime::nic::info(input).is_ok() {
        return Err("unexpected NIC authority".into());
    }
    let mut pipe = BudgetPipe {
        pipe: KernelPipe {
            request_reader: input,
            reply_writer: output,
        },
        until,
        last: Cell::new(last),
        live: Cell::new(true),
    };
    pipe.check().map_err(|_| "original child budget")?;
    let mut request = [0; HEADER];
    request[..4].copy_from_slice(&[VERSION, SEND, 0, FAMILY]);
    request[4..20].copy_from_slice(&peer.ip);
    request[20..24].copy_from_slice(&peer.scope.to_be_bytes());
    request[24..26].copy_from_slice(&peer.port.wrapping_add(1).to_be_bytes());
    let mut reply = [0; MAX_MESSAGE];
    let n =
        transact(&mut pipe, &request, &mut reply, 1000).map_err(|e| format!("peer refusal {e}"))?;
    if n != HEADER || reply[2] != v6::Error::Denied.code() {
        return Err("peer authority expanded".into());
    }
    request[20..24].copy_from_slice(&peer.scope.wrapping_add(1).to_be_bytes());
    request[24..26].copy_from_slice(&peer.port.to_be_bytes());
    let n = transact(&mut pipe, &request, &mut reply, 1000)
        .map_err(|e| format!("scope refusal {e}"))?;
    if n != HEADER || reply[2] != v6::Error::Denied.code() {
        return Err("scope authority expanded".into());
    }
    eprintln!("IPV6 DAD CLIENT AUTHORITY PASS scope-and-peer-refused no-nic");
    {
        let mut resolver = Resolver::with_entropy(
            v6::dns::Datagram::new(Borrowed(&mut pipe), peer, absd_runtime::sleep_ticks),
            getrandom_0_2::getrandom,
        )
        .map_err(|e| format!("entropy {e:?}"))?;
        let a = resolver
            .lookup("a.example")
            .map_err(|e| format!("DNS A {e:?}"))?;
        if a.count != 1 || a.addresses[0] != [192, 0, 2, 9] {
            return Err("unexpected DNS A".into());
        }
        eprintln!("IPV6 DAD DNS A PASS address=192.0.2.9");
        let a = resolver
            .lookup_aaaa("aaaa.example")
            .map_err(|e| format!("DNS AAAA {e:?}"))?;
        if a.count != 1
            || a.addresses[0] != [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]
        {
            return Err("unexpected DNS AAAA".into());
        }
        eprintln!("IPV6 DAD DNS AAAA PASS address=2001:db8::9");
    }
    request.fill(0);
    request[..4].copy_from_slice(&[VERSION, CLOSE, 0, FAMILY]);
    let n = transact(&mut pipe, &request, &mut reply, 1000).map_err(|e| format!("close {e}"))?;
    pipe.check()
        .map_err(|_| "original child budget after close")?;
    if n != HEADER || reply[..HEADER] != request {
        return Err("close reply".into());
    }
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("IPV6 DAD CLIENT ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
