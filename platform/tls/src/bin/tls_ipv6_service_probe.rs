#![feature(restricted_std)]
//! Private static HTTPS owner. Only this process retains NIC authority.
use absd_native_tls_fixture::ipv6_fixture;
use absd_net::ipv6::channel::KernelPipe;
use absd_net::{
    Config, Link, NicLink, Stack,
    ipv6::{self, stream},
};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};
use std::cell::Cell;

const REPORT_LIMIT: usize = 65_536;

fn sys(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let result: i64;
    unsafe {
        core::arch::asm!("int 0x80", inlateout("rax") n => result,
            in("rdi") a, in("rsi") b, in("rdx") c, options(nostack, preserves_flags));
    }
    result
}
struct Handle(u64);
impl Handle {
    fn take(mut self) -> u64 {
        std::mem::replace(&mut self.0, 0)
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = absd_runtime::close(self.0);
        }
    }
}

// One original deadline checked at scheduled pre/post-call observations.
// This does not preempt a syscall or bound console/cleanup latency. Refusal
// is sticky; cleanup still reaps our child after the deadline expires.
struct Budget {
    last: Cell<u64>,
    end: u64,
    refused: Cell<bool>,
}
impl Budget {
    fn new() -> Result<Self, String> {
        let now = absd_runtime::boot_millis();
        Ok(Self {
            last: Cell::new(now),
            end: now.checked_add(20_000).ok_or("deadline overflow")?,
            refused: Cell::new(false),
        })
    }
    fn check(&self) -> Result<u64, String> {
        let now = absd_runtime::boot_millis();
        if self.refused.get() || now < self.last.get() || now >= self.end {
            self.refused.set(true);
            return Err("invocation clock or deadline".into());
        }
        self.last.set(now);
        Ok(now)
    }
}
fn pipe(budget: &Budget) -> Result<(Handle, Handle), String> {
    budget.check()?;
    let raw = sys(16, 0, 0, 0);
    let both = (raw >= 0).then(|| Handle(raw as u64));
    budget.check()?;
    let both = both.ok_or_else(|| format!("pipe {raw}"))?;
    let duplicate = |right| -> Result<Handle, String> {
        budget.check()?;
        let result = absd_runtime::duplicate(both.0, right).map(Handle);
        budget.check()?;
        result.map_err(|error| format!("pipe duplicate {error}"))
    };
    Ok((duplicate(RIGHT_READ)?, duplicate(RIGHT_WRITE)?))
}

struct Child {
    process: u64,
    io: Option<KernelPipe>,
    report: Handle,
    bytes: Vec<u8>,
}
impl Child {
    fn wait(&mut self, budget: &Budget) -> Result<Option<[u64; 4]>, String> {
        budget.check()?;
        let mut result = [0; 4];
        let code = sys(6, self.process, result.as_mut_ptr() as u64, 1);
        if code >= 0 {
            self.process = 0;
        }
        budget.check()?;
        match code {
            -110 => Ok(None),
            0.. => Ok(Some(result)),
            _ => Err(format!("child wait {code}")),
        }
    }
    fn read_report(&mut self, budget: &Budget) -> Result<usize, String> {
        budget.check()?;
        let mut bytes = [0; 1024];
        let result = absd_runtime::read_within(self.report.0, &mut bytes, 1);
        budget.check()?;
        match result {
            Ok(n)
                if self
                    .bytes
                    .len()
                    .checked_add(n)
                    .is_some_and(|size| size <= REPORT_LIMIT) =>
            {
                self.bytes.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            Ok(_) => Err("child report bound".into()),
            Err(-110) => Ok(0),
            Err(error) => Err(format!("child report {error}")),
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        drop(self.io.take());
        if self.process != 0 {
            let killed = sys(20, self.process, 0, 0);
            let mut outcome = [0; 4];
            let waited = sys(6, self.process, outcome.as_mut_ptr() as u64, 1000);
            if waited < 0 {
                eprintln!(
                    "TLS IPV6 CLEANUP process={} kill={} wait={}",
                    self.process, killed, waited
                );
                let _ = absd_runtime::close(self.process);
            }
            self.process = 0;
        }
    }
}

fn spawn(case: &str, unix: &str, expiry: u64, budget: &Budget) -> Result<Child, String> {
    let (child_in, parent_out) = pipe(budget)?;
    let (parent_in, child_out) = pipe(budget)?;
    let (report_reader, report_writer) = pipe(budget)?;
    let (startup_reader, startup_writer) = pipe(budget)?;
    let copies = [
        [startup_reader.0, RIGHT_READ, 0],
        [child_in.0, RIGHT_READ, 0],
        [child_out.0, RIGHT_WRITE, 0],
        [report_writer.0, RIGHT_WRITE, 0],
        [report_writer.0, RIGHT_WRITE, 1],
    ];
    let expiry_text = expiry.to_string();
    let args: [&[u8]; 8] = [
        b"--case",
        case.as_bytes(),
        b"--unix-time",
        unix.as_bytes(),
        b"--grant-expiry",
        expiry_text.as_bytes(),
        b"--expected-body",
        b"2048",
    ];
    let mut startup = [0; absd_broker::MAX_STARTUP];
    let n = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        args,
        [],
        b"/",
        b"https-get-ipv6",
        copies.len(),
        &mut startup,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    let image = include_bytes!(env!("ABSD_TLS_IPV6_CLIENT_ELF"));
    let request = [
        image.as_ptr() as u64,
        image.len() as u64,
        copies.as_ptr() as u64,
        copies.len() as u64,
    ];
    budget.check()?;
    let process = spawn_image_raw(request.as_ptr() as u64, SPAWN_NO_SPAWN, 0);
    let child = Child {
        process: if process >= 0 { process as u64 } else { 0 },
        io: Some(KernelPipe {
            request_reader: parent_in.take(),
            reply_writer: parent_out.take(),
        }),
        report: report_reader,
        bytes: Vec::new(),
    };
    budget.check()?;
    if process < 0 {
        return Err(format!("spawn {process}"));
    }
    drop((startup_reader, child_in, child_out, report_writer));
    budget.check()?;
    let wrote = absd_runtime::write_within(startup_writer.0, &startup[..n], 1000);
    budget.check()?;
    wrote.map_err(|e| format!("startup write {e}"))?;
    drop(startup_writer);
    // All channel/result writers held by the child are now absent in parent.
    if child.process == 0 {
        return Err("zero process handle".into());
    }
    Ok(child)
}

fn census(label: &str, budget: &Budget) -> Result<absd_runtime::ResourceCensus, String> {
    budget.check()?;
    let result = absd_runtime::resource_census();
    budget.check()?;
    let c = result.map_err(|e| format!("census {e}"))?;
    println!(
        "TLS IPV6 RESOURCES label={} processes={} handles={} pipes={} cells={} frames={}",
        label, c.processes, c.handles, c.pipes, c.cells, c.frames
    );
    Ok(c)
}

fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let budget = Budget::new()?;
    let profile = ipv6_fixture::selected().map_err(str::to_owned)?;
    let case = env!("ABSD_TLS_IPV6_CASE");
    if !matches!(case, "P01" | "P02" | "L07") {
        return Err("unsupported initial IPv6 TLS case".into());
    }
    let unix = env!("ABSD_TLS_UNIX_SECONDS");
    if unix.is_empty()
        || unix.len() > 20
        || unix.starts_with('0')
        || !unix.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("noncanonical fixture time".into());
    }
    let _ = unix.parse::<u64>().map_err(|_| "fixture time overflow")?;
    // Retire the known boot stdin writer before the strict resource baseline.
    budget.check()?;
    let input = absd_runtime::standard_stream_handles().0;
    let mut byte = [0];
    let eof = absd_runtime::read_within(input, &mut byte, 1000);
    budget.check()?;
    if eof != Ok(0) {
        return Err(format!("startup stdin EOF {eof:?}"));
    }
    budget.check()?;
    let link = NicLink::from_startup();
    budget.check()?;
    let link = link.map_err(|e| format!("NIC {e:?}"))?;
    let reading = link.read().ok_or("link reading unavailable")?;
    if reading.disabled || !reading.link_up {
        return Err("link unavailable".into());
    }
    let nic_ready = budget.check()?;
    let setup_end = nic_ready.checked_add(1100).ok_or("setup bound overflow")?;
    while budget.check()? < setup_end {
        absd_runtime::sleep_ticks(10);
        budget.check()?;
    }
    println!(
        "TLS IPV6 RX SETUP nic_ready_ms={} ready_ms={} continuous_vm_required=1",
        nic_ready,
        budget.check()?
    );
    let mut stack = Stack::open(link, Config::qemu_user()).map_err(|e| format!("stack {e:?}"))?;
    stack
        .configure_ipv6(ipv6::Config {
            address: profile.local,
            prefix_len: 64,
            scope: profile.peer.scope,
        })
        .map_err(|e| format!("IPv6 config {e:?}"))?;
    let grant = stream::Grant {
        local_port: 7401,
        peer: profile.peer,
        connect_timeout_ms: 2000,
        lifetime_ms: 15_000,
    };
    if let Some(router) = profile.router {
        if stack.ipv6_stream_grant(grant) != Err(stream::Error::Denied) || stack.socket_count() != 0
        {
            return Err("off-link TLS stream accepted without route".into());
        }
        stack
            .configure_ipv6_route(ipv6::routing::Route {
                router,
                peer: profile.peer,
            })
            .map_err(|e| format!("TLS explicit route {e:?}"))?;
        println!(
            "TLS IPV6 ROUTE READY local={}/64 router={} peer={} scope={} port={} path_mtu={} no_route_denied=1",
            std::net::Ipv6Addr::from(profile.local),
            std::net::Ipv6Addr::from(router),
            std::net::Ipv6Addr::from(profile.peer.ip),
            profile.peer.scope,
            profile.peer.port,
            stack.ip_mtu()
        );
    }
    let before = census("before", &budget)?;
    let issued = budget.check()?;
    let expiry = issued.checked_add(15_000).ok_or("grant expiry overflow")?;
    let mut channel =
        stream::channel::Channel::grant(&mut stack, grant).map_err(|e| format!("grant {e:?}"))?;
    let result: Result<(), String> = (|| {
        let mut child = spawn(case, unix, expiry, &budget)?;
        println!(
            "TLS IPV6 SERVICE READY case={} issued_ms={} expiry_ms={} invocation_deadline_ms={} local_port=7401 scope=1 peer_port=4443",
            case, issued, expiry, budget.end
        );
        let mut channel_ended = None;
        loop {
            budget.check()?;
            stack.poll();
            budget.check()?;
            if channel_ended.is_none() {
                let live = channel.poll(&mut stack, child.io.as_mut().ok_or("missing channel")?);
                let now = budget.check()?;
                if !live {
                    channel_ended = Some(now);
                }
            }
            child.read_report(&budget)?;
            if let Some(outcome) = child.wait(&budget)? {
                while child.read_report(&budget)? != 0 {}
                let report =
                    std::str::from_utf8(&child.bytes).map_err(|_| "non UTF8 child report")?;
                print!("{report}");
                if outcome[0] != 1 || outcome[1] != 0 {
                    return Err(format!("child disposition {outcome:?}"));
                }
                let prefix = format!("TLS RESULT case={case} ");
                let begin = format!("TLS IPV6 BEGIN case={case} ");
                if report
                    .lines()
                    .filter(|line| line.starts_with(&prefix))
                    .count()
                    != 1
                    || report
                        .lines()
                        .filter(|line| line.starts_with(&begin))
                        .count()
                        != 1
                    || report
                        .lines()
                        .filter(|line| {
                            line.starts_with("TLS IPV6 CLIENT AUTHORITY nic=0 block=false ")
                        })
                        .count()
                        != 1
                {
                    return Err("missing or repeated typed child report".into());
                }
                println!(
                    "TLS IPV6 CHILD DONE case={} kind={} status={}",
                    case, outcome[0], outcome[1]
                );
                break;
            }
            if channel_ended.is_some_and(|at| budget.last.get().saturating_sub(at) >= 250) {
                return Err("channel ended without bounded child exit".into());
            }
            budget.check()?;
            stack.wait(1);
            budget.check()?;
        }
        drop(child);
        Ok(())
    })();
    channel.revoke(&mut stack);
    // Match the existing IPv4 fixture's opportunity to poll an accepted
    // CLOSE before fencing this isolated owner. No new request authority
    // remains, and this does not establish a peer FIN acknowledgement.
    let close_result: Result<(), String> = (|| {
        if result.is_ok() {
            let until = budget
                .check()?
                .checked_add(100)
                .ok_or("close poll overflow")?;
            while budget.check()? < until {
                stack.poll();
                budget.check()?;
                stack.wait(1);
                budget.check()?;
            }
        }
        Ok(())
    })();
    if profile.router.is_some() {
        stack.ipv6_fence();
    } else {
        stack.ipv6_stream_fence();
    }
    result?;
    close_result?;
    if stack.socket_count() != 0 {
        return Err("stream sockets remain".into());
    }
    let after_reading = stack
        .link()
        .read()
        .ok_or("final link reading unavailable")?;
    budget.check()?;
    if after_reading.disabled
        || !after_reading.link_up
        || after_reading.rx_missed != reading.rx_missed
    {
        return Err("link loss or missed frames".into());
    }
    let after = census("after", &budget)?;
    if (before.processes, before.handles, before.pipes, before.cells)
        != (after.processes, after.handles, after.pipes, after.cells)
    {
        return Err("resource residue".into());
    }
    println!(
        "TLS IPV6 SERVICE DONE case={} sockets=0 rx_missed_before={} rx_missed_after={} at_ms={}",
        case,
        reading.rx_missed,
        after_reading.rx_missed,
        budget.check()?
    );
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("TLS IPV6 SERVICE ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
