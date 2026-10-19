#![feature(restricted_std)]
//! One static routed paired UDP/TCP DNS invocation. No default route or DAD claim.
#[path = "../ipv6_route_boundaries.rs"]
mod boundaries;
#[path = "../ipv6_route_tcp_fixture.rs"]
mod fixture;
#[path = "../ipv6_route_guard.rs"]
mod guarded;
use absd_net::{
    Config, NicLink, Stack,
    ipv6::{
        self as v6,
        channel::KernelPipe,
        dns_tcp::{Channel, Session},
        stream,
    },
};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};
use guarded::{BoundLink, BoundPipe, Guard};
struct Handle(u64);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = absd_runtime::close(self.0);
        }
    }
}
impl Handle {
    fn take(mut self) -> u64 {
        let h = self.0;
        self.0 = 0;
        h
    }
}
fn sys(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let out: i64;
    unsafe {
        core::arch::asm!("int 0x80", inlateout("rax") n=>out, in("rdi") a, in("rsi") b, in("rdx") c, options(nostack,preserves_flags));
    }
    out
}
fn pipe(guard: &Guard) -> Result<(Handle, Handle), String> {
    // Wrap each possible first effect before the post-I/O check, so a
    // boundary discards its owned handle instead of leaking the raw value.
    let both = guard
        .io(|_| {
            let result = sys(16, 0, 0, 0);
            if result < 0 {
                Err(result)
            } else {
                Ok(Handle(result as u64))
            }
        })
        .map_err(|e| format!("pipe {e}"))?;
    let reader = guard
        .io(|_| absd_runtime::duplicate(both.0, RIGHT_READ).map(Handle))
        .map_err(|e| format!("pipe reader {e}"))?;
    let writer = guard
        .io(|_| absd_runtime::duplicate(both.0, RIGHT_WRITE).map(Handle))
        .map_err(|e| format!("pipe writer {e}"))?;
    Ok((reader, writer))
}
fn empty_input(guard: &Guard) -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let end = start.checked_add(1000).ok_or("EOF overflow")?;
    let input = absd_runtime::standard_stream_handles().0;
    if input == 0 {
        return Err("missing stdin".into());
    }
    let before = absd_runtime::boot_millis();
    if before < start || before >= end {
        return Err("EOF clock/deadline".into());
    }
    let r = absd_runtime::read_within(input, &mut [0; 1], guard.check()?.min(end - before));
    let after = absd_runtime::boot_millis();
    guard.check()?;
    if after < before || after >= end {
        return Err("EOF clock/deadline".into());
    }
    match r {
        Ok(0) => Ok(()),
        _ => Err(format!("expected empty inherited stdin EOF {r:?}")),
    }
}
fn census(label: &str, guard: &Guard) -> Result<absd_runtime::ResourceCensus, String> {
    guard.check()?;
    let r = absd_runtime::resource_census();
    guard.check()?;
    let r = r.map_err(|e| format!("census {e}"))?;
    println!(
        "ROUTE6TCP CENSUS label={label} processes={} handles={} pipes={} cells={} frames={}",
        r.processes, r.handles, r.pipes, r.cells, r.frames
    );
    Ok(r)
}
fn peer() -> v6::Address {
    v6::Address {
        ip: fixture::PEER,
        scope: fixture::SCOPE,
        port: fixture::PORT,
    }
}
fn run() -> Result<(), String> {
    let ip_mtu = fixture::ip_mtu(option_env!("ABSD_ROUTE6_TCP_IP_MTU"))?;
    let start = absd_runtime::boot_millis();
    let stop = start
        .checked_add(fixture::TOTAL_MS)
        .ok_or("original budget overflow")?;
    absd_runtime::link_anchor();
    let guard = Guard::new(start, stop)?;
    empty_input(&guard)?;
    println!(
        "ROUTE6TCP SELECTOR local=fd00:ab5d:1::15/64 router=fd00:ab5d:1::2 peer=fd00:ab5d:2::9 udp=42010 scope=1 dad=unrun"
    );
    let before = census("before", &guard)?;
    let result = owned(&guard, start, stop, ip_mtu);
    absd_runtime::heap_free_pooled_pages();
    let after = census("after", &guard)?;
    if before.processes != after.processes
        || before.handles != after.handles
        || before.pipes != after.pipes
        || before.cells != after.cells
    {
        return Err(format!("resource restoration failed; original={result:?}"));
    }
    result?;
    guard.check()?;
    println!("ROUTE6TCP SERVICE PASS child=exited sockets=0 resources=restored");
    Ok(())
}
// Fixed local VM fixture preparation, before any Stack poll can emit NS and
// elicit an automatic Linux NA. This is not a driver readiness guarantee.
fn prepare_rx(guard: &Guard) -> Result<(), String> {
    let start = absd_runtime::boot_millis();
    let until = start.checked_add(1100).ok_or("RX preparation overflow")?;
    if guard.check()? <= 1100 {
        return Err("RX preparation cannot fit original budget".into());
    }
    for _ in 0..128 {
        guard.check()?;
        let now = absd_runtime::boot_millis();
        if now < start {
            return Err("RX preparation rewind".into());
        }
        if now >= until {
            guard.check()?;
            println!(
                "ROUTE6TCP RX SETUP elapsed_ms={} continuous-vm=assumed",
                now - start
            );
            return Ok(());
        }
        guard
            .io(|left| {
                absd_runtime::sleep_ticks(20.min(left));
                Ok(())
            })
            .map_err(|e| format!("RX preparation wait {e}"))?;
    }
    Err("RX preparation work bound".into())
}
fn owned(original: &Guard, start: u64, stop: u64, ip_mtu: usize) -> Result<(), String> {
    original.check()?;
    let link = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    original.check()?;
    let guard = original.with_nic(link.handle())?;
    let mut stack = Stack::open_with_ip_mtu(
        BoundLink {
            inner: link,
            guard: guard.clone(),
        },
        Config {
            gateway: None,
            ..Config::qemu_user()
        },
        ip_mtu,
    )
    .map_err(|e| format!("stack {e:?}"))?;
    stack
        .configure_ipv6(v6::Config {
            address: fixture::LOCAL,
            prefix_len: 64,
            scope: fixture::SCOPE,
        })
        .map_err(|e| format!("IPv6 {e:?}"))?;
    let grant = v6::Grant {
        local_port: fixture::LOCAL_PORT,
        peer: peer(),
    };
    if stack.ipv6_bind(grant) != Err(v6::Error::Denied) || stack.socket_count() != 0 {
        return Err("off-link grant accepted without route".into());
    }
    let tcp = stream::Grant {
        local_port: 7003,
        peer: peer(),
        connect_timeout_ms: 2000,
        lifetime_ms: fixture::TOTAL_MS,
    };
    if stack.ipv6_stream_grant(tcp) != Err(stream::Error::Denied) || stack.socket_count() != 0 {
        return Err("off-link TCP grant accepted without route".into());
    }
    println!("ROUTE6TCP NO-ROUTE REFUSAL PASS udp=denied tcp=denied sockets=0");
    stack
        .configure_ipv6_route(v6::routing::Route {
            router: fixture::ROUTER,
            peer: peer(),
        })
        .map_err(|e| format!("route {e:?}"))?;
    guard.check()?;
    boundaries::run(&mut stack)?;
    guard.check()?;
    boundaries::run_pipes(&mut stack, &guard)?;
    guard.check()?;
    prepare_rx(&guard)?;
    guard.check()?;
    // The already original outer guard surrounds every Link and pipe call.
    // This remaining interval cannot authorize I/O past that guard's stop.
    let tcp = stream::Grant {
        lifetime_ms: guard.check()?,
        ..tcp
    };
    let session = Session::grant(&mut stack, grant, tcp)
        .map_err(|e| format!("paired delegated grant {e:?}"))?;
    let mut channel = Channel::new(session);
    let result = child(&mut stack, &mut channel, &guard, start, stop);
    if result.is_ok() {
        let drain_start = absd_runtime::boot_millis();
        let mut completed = false;
        for _ in 0..1024 {
            guard.check()?;
            stack.poll();
            guard.check()?;
            let now = absd_runtime::boot_millis();
            if now < drain_start {
                return Err("close drain clock".into());
            }
            if now - drain_start >= 1000 {
                completed = true;
                break;
            }
            guard
                .io(|left| {
                    absd_runtime::sleep_ticks(left.min(2));
                    Ok(())
                })
                .map_err(|e| format!("close drain {e}"))?;
        }
        if !completed {
            return Err("close drain work bound".into());
        }
        println!(
            "ROUTE6TCP CLOSE DRAIN observed-ms={}",
            absd_runtime::boot_millis().saturating_sub(drain_start)
        );
    }
    channel.revoke(&mut stack);
    stack.ipv6_fence();
    let remaining = stack.socket_count();
    println!("ROUTE6TCP RETIRE sockets={remaining}");
    drop(channel);
    drop(stack);
    guard.check()?;
    if remaining != 0 {
        return Err("retained socket".into());
    }
    result
}
fn child(
    stack: &mut Stack<BoundLink>,
    channel: &mut Channel,
    guard: &Guard,
    start: u64,
    stop: u64,
) -> Result<(), String> {
    let image = include_bytes!(env!("ABSD_ROUTE6_TCP_CLIENT_ELF"));
    let (child_in, parent_out) = pipe(guard)?;
    let (parent_in, child_out) = pipe(guard)?;
    let (result_reader, result_writer) = pipe(guard)?;
    let (startup_reader, startup_writer) = pipe(guard)?;
    let copies = [
        [startup_reader.0, RIGHT_READ, 0],
        [child_in.0, RIGHT_READ, 0],
        [child_out.0, RIGHT_WRITE, 0],
        [result_writer.0, RIGHT_WRITE, 0],
        [child_out.0, RIGHT_WRITE, 1],
    ];
    let start_env = format!("ABSD_ROUTE6_START_MS={start}");
    let stop_env = format!("ABSD_ROUTE6_STOP_MS={stop}");
    let mut record = [0; absd_broker::MAX_STARTUP];
    let n = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        core::iter::empty::<&[u8]>(),
        [start_env.as_bytes(), stop_env.as_bytes()],
        b"/",
        b"ipv6-route-tcp-dns-client",
        copies.len(),
        &mut record,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    guard.check()?;
    let req = [
        image.as_ptr() as u64,
        image.len() as u64,
        copies.as_ptr() as u64,
        copies.len() as u64,
    ];
    let process = spawn_image_raw(req.as_ptr() as u64, SPAWN_NO_SPAWN, 0);
    drop((startup_reader, child_in, child_out, result_writer));
    if process < 0 {
        return Err(format!("spawn {process}"));
    }
    let mut process = Handle(process as u64);
    let result = (|| {
        guard.check()?;
        let written =
            absd_runtime::write_within(startup_writer.0, &record[..n], guard.check()?.min(1000));
        guard.check()?;
        if written != Ok(n) {
            return Err(format!("startup write {written:?}"));
        }
        drop(startup_writer);
        let bootstrap = fixture::bootstrap(start)?;
        let written =
            absd_runtime::write_within(parent_out.0, &bootstrap, guard.check()?.min(1000));
        guard.check()?;
        if written != Ok(bootstrap.len()) {
            return Err(format!("bootstrap write {written:?}"));
        }
        let mut io = BoundPipe {
            inner: KernelPipe {
                request_reader: parent_in.take(),
                reply_writer: parent_out.take(),
            },
            guard: guard.clone(),
        };
        let mut text = Vec::new();
        println!(
            "ROUTE6TCP SERVICE READY scope=1 udp-local-port=7002 tcp-local-port=7003 path-mtu={} peer=fd00:ab5d:2::9 peer-port=42010",
            stack.ip_mtu()
        );
        loop {
            guard.check()?;
            stack.poll();
            guard.check()?;
            let live = channel.poll(stack, &mut io);
            guard.check()?;
            let mut bytes = [0; 256];
            let r = absd_runtime::read_within(result_reader.0, &mut bytes, 1);
            guard.check()?;
            match r {
                Ok(n) if text.len() + n <= 4096 => text.extend_from_slice(&bytes[..n]),
                Err(-110 | -11) => {}
                _ => return Err(format!("result read {r:?}")),
            }
            let mut outcome = [0u64; 4];
            let waited = sys(
                6,
                process.0,
                outcome.as_mut_ptr() as u64,
                guard.check()?.min(if live { 1 } else { 50 }),
            );
            if waited >= 0 {
                process.0 = 0;
            }
            guard.check()?;
            if waited >= 0 {
                loop {
                    guard.check()?;
                    let r = absd_runtime::read_within(result_reader.0, &mut bytes, 1);
                    guard.check()?;
                    match r {
                        Ok(0) => break,
                        Ok(n) if text.len() + n <= 4096 => text.extend_from_slice(&bytes[..n]),
                        _ => return Err(format!("terminal result drain {r:?}")),
                    }
                }
                let text = String::from_utf8(text).map_err(|_| "result UTF8")?;
                guard.check()?;
                print!("{text}");
                if outcome[0] != 1
                    || outcome[1] != 0
                    || !text
                        .contains("ROUTE6TCP CLIENT AUTHORITY PASS nic=0 udp-denied=3 tcp-denied=3")
                    || !text.contains("ROUTE6TCP DNS A PASS address=192.0.2.9")
                    || !text.contains("ROUTE6TCP DNS AAAA PASS address=2001:db8::9")
                {
                    return Err(format!("child outcome={outcome:?}"));
                }
                return Ok(());
            }
            if waited != -110 {
                return Err(format!("wait {waited}"));
            }
            if !live {
                return Err("channel retired before child exit".into());
            }
            stack.wait(1);
            guard.check()?;
        }
    })();
    channel.revoke(stack);
    // Retirement may run after application budget expiry; it creates no new
    // network authority and is bounded by existing kill + immediate reap.
    if process.0 != 0 {
        let killed = sys(20, process.0, 0, 0);
        let mut outcome = [0u64; 4];
        let waited = sys(
            6,
            process.0,
            outcome.as_mut_ptr() as u64,
            if killed >= 0 { 0 } else { 1 },
        );
        if waited >= 0 {
            process.0 = 0;
        }
        if killed < 0 || waited < 0 {
            return Err(format!(
                "child cleanup kill={killed} wait={waited}; original={result:?}"
            ));
        }
    }
    result
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ROUTE6TCP SERVICE ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
