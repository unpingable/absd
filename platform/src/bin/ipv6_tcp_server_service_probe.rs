#![feature(restricted_std)]
//! Dedicated static on-link IPv6 listener and a pipe-only echo child.
use absd_net::datagram::channel::{KernelPipe, Pipe};
use absd_net::{
    Config, NicLink, Stack,
    ipv6::{self as v6, stream::server as v},
};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};
fn ip(last: u8) -> [u8; 16] {
    let mut a = [0; 16];
    a[..4].copy_from_slice(&[0xfd, 0, 0xab, 0x5d]);
    a[15] = last;
    a
}
fn sys(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let out: i64;
    unsafe {
        core::arch::asm!("int 0x80",inlateout("rax")n=>out,in("rdi")a,in("rsi")b,in("rdx")c,options(nostack,preserves_flags));
    }
    out
}
struct Handle(u64);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = absd_runtime::close(self.0);
        }
    }
}
fn handle(n: i64) -> Result<Handle, String> {
    if n < 0 {
        Err(format!("kernel {n}"))
    } else {
        Ok(Handle(n as u64))
    }
}
fn pipe() -> Result<(Handle, Handle), String> {
    let both = handle(sys(16, 0, 0, 0))?;
    let reader =
        Handle(absd_runtime::duplicate(both.0, RIGHT_READ).map_err(|e| format!("reader {e}"))?);
    let writer =
        Handle(absd_runtime::duplicate(both.0, RIGHT_WRITE).map_err(|e| format!("writer {e}"))?);
    Ok((reader, writer))
}
struct Child(Handle);
impl Child {
    fn wait(&mut self, ticks: u64) -> Result<Option<[u64; 4]>, String> {
        let mut record = [0; 4];
        let n = sys(6, self.0.0, record.as_mut_ptr() as u64, ticks);
        if n >= 0 {
            self.0.0 = 0;
            Ok(Some(record))
        } else if n == -110 {
            Ok(None)
        } else {
            Err(format!("wait {n}"))
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.0.0 != 0 {
            let _ = sys(20, self.0.0, 0, 0);
            let mut record = [0u64; 4];
            if sys(6, self.0.0, record.as_mut_ptr() as u64, 1000) >= 0 {
                self.0.0 = 0;
            }
        }
    }
}
fn spawn_child(negative: bool) -> Result<(Child, KernelPipe, Handle), String> {
    let args: &[&[u8]] = if negative {
        &[b"--boundary-negative"]
    } else {
        &[]
    };
    let (child_in, parent_out) = pipe()?;
    let (parent_in, child_out) = pipe()?;
    let (result_in, result_out) = pipe()?;
    let (startup_in, startup_out) = pipe()?;
    let copies = [
        [startup_in.0, RIGHT_READ, 0],
        [child_in.0, RIGHT_READ, 0],
        [child_out.0, RIGHT_WRITE, 0],
        [result_out.0, RIGHT_WRITE, 0],
        [child_out.0, RIGHT_WRITE, 1],
    ];
    let mut startup = [0; absd_broker::MAX_STARTUP];
    let length = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        args.iter().copied(),
        [],
        b"/",
        b"ipv6-tcp-server-echo",
        copies.len(),
        &mut startup,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    let image = include_bytes!(env!("ABSD_IPV6_TCP_SERVER_CHILD_ELF"));
    let request = [
        image.as_ptr() as u64,
        image.len() as u64,
        copies.as_ptr() as u64,
        copies.len() as u64,
    ];
    let child = Child(handle(spawn_image_raw(
        request.as_ptr() as u64,
        SPAWN_NO_SPAWN,
        0,
    ))?);
    drop((startup_in, child_in, child_out, result_out));
    absd_runtime::write_within(startup_out.0, &startup[..length], 1000)
        .map_err(|e| format!("startup write {e}"))?;
    drop(startup_out);
    let mut bootstrap = [0; 23];
    bootstrap[0] = v::VERSION;
    bootstrap[1..17].copy_from_slice(&ip(2));
    bootstrap[17..21].copy_from_slice(&1u32.to_be_bytes());
    bootstrap[21..23].copy_from_slice(&42030u16.to_be_bytes());
    let bootstrap_written = absd_runtime::write_within(parent_out.0, &bootstrap, 1000)
        .map_err(|e| format!("bootstrap {e}"))?;
    if negative {
        if bootstrap_written != bootstrap.len() {
            return Err("negative bootstrap short write".into());
        }
        let mut text = String::new();
        for byte in &bootstrap[..bootstrap_written] {
            use std::fmt::Write;
            let _ = write!(text, "{byte:02x}");
        }
        println!("IPV6 TCP SERVER NEG BOOTSTRAP v=1 bytes={bootstrap_written} hex={text}");
    }
    let pipe = KernelPipe {
        request_reader: parent_in.0,
        reply_writer: parent_out.0,
    };
    // KernelPipe takes ownership of exactly these two handles.
    core::mem::forget((parent_in, parent_out));
    Ok((child, pipe, result_in))
}

struct ObservedPipe {
    inner: KernelPipe,
    eof: bool,
    read_bytes: usize,
    written_bytes: usize,
}
impl Pipe for ObservedPipe {
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let r = self.inner.read(b);
        if let Ok(Some(n)) = r {
            self.eof |= n == 0;
            self.read_bytes += n;
        }
        r
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        let r = self.inner.write(b);
        if let Ok(Some(n)) = r {
            self.written_bytes += n;
        }
        r
    }
}
fn census(label: &str) -> Result<absd_runtime::ResourceCensus, String> {
    let c = absd_runtime::resource_census().map_err(|e| format!("census {e}"))?;
    println!(
        "IPV6 TCP SERVER CENSUS v=1 label={label} processes={} handles={} pipes={} cells={} frames={}",
        c.processes, c.handles, c.pipes, c.cells, c.frames
    );
    Ok(c)
}
#[path = "../ipv6_tcp_server_clock.rs"]
mod completion_clock;
fn boundary(stack: &mut Stack<NicLink>, previous: &mut u64, until: u64) -> Result<(), String> {
    completion_clock::observe(previous, until, absd_runtime::boot_millis()).map_err(|error| {
        stack.ipv6_stream_server_fence();
        error.into()
    })
}
#[path = "../ipv6_tcp_server_boundary_wire.rs"]
mod boundary_wire;
mod ipv6_tcp_server_boundary;
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let whole_start = absd_runtime::boot_millis();
    let whole_end = whole_start.checked_add(20000).ok_or("whole overflow")?;
    let nic = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut stack = Stack::open_with_ip_mtu(nic, Config::qemu_user(), 1500)
        .map_err(|e| format!("stack {e:?}"))?;
    stack
        .configure_ipv6(v6::Config {
            address: ip(1),
            prefix_len: 64,
            scope: 1,
        })
        .map_err(|e| format!("IPv6 config {e:?}"))?;
    println!(
        "IPV6 TCP SERVER NEG BEGIN v=1 whole_start_ms={whole_start} whole_until_ms={whole_end}"
    );
    ipv6_tcp_server_boundary::run(&mut stack, whole_end)?;
    if absd_runtime::boot_millis()
        .checked_add(10000)
        .is_none_or(|end| end > whole_end)
    {
        return Err("insufficient time for fresh positive grant".into());
    }
    let before = census("before")?;
    let start = absd_runtime::boot_millis();
    let until = start.checked_add(10000).ok_or("owner overflow")?;
    if until > whole_end {
        return Err("fresh positive grant exceeds whole bound".into());
    }
    let mut channel = v::Channel::grant(
        &mut stack,
        v::Grant {
            local_port: 7005,
            peer: v6::Address {
                ip: ip(2),
                port: 42030,
                scope: 1,
            },
            accept_timeout_ms: 5000,
            lifetime_ms: 10000,
        },
    )
    .map_err(|e| format!("grant {e:?}"))?;
    if stack.socket_count() != 0 {
        return Err("grant created socket".into());
    }
    println!(
        "IPV6 TCP SERVER GRANT v=1 local=[fd00:ab5d::1]:7005 peer=[fd00:ab5d::2]:42030 scope=1 mtu=1500 accept_ms=5000 lifetime_ms=10000 owner_start_ms={start} owner_until_ms={until} sockets=0"
    );
    let (mut child, inner, result_in) = spawn_child(false)?;
    let mut pipe = ObservedPipe {
        inner,
        eof: false,
        read_bytes: 0,
        written_bytes: 0,
    };
    let mut output = Vec::new();
    let mut announced = false;
    let mut previous = start;
    let mut result_eof = false;
    loop {
        let now = absd_runtime::boot_millis();
        if now < previous || now >= until {
            stack.ipv6_stream_server_fence();
            return Err("owner clock/deadline".into());
        }
        previous = now;
        let live = channel.poll(&mut stack, &mut pipe);
        if !announced && stack.socket_count() == 1 {
            println!("IPV6 TCP SERVER LISTEN READY v=1 sockets=1");
            announced = true;
        }
        stack.poll();
        let after = absd_runtime::boot_millis();
        if after < previous || after >= until {
            stack.ipv6_stream_server_fence();
            return Err("owner boundary after I/O".into());
        }
        previous = after;
        let mut bytes = [0; 256];
        let observed_result = absd_runtime::read_within(result_in.0, &mut bytes, 1);
        boundary(&mut stack, &mut previous, until)?;
        match observed_result {
            Ok(n) => {
                result_eof |= n == 0;
                if output.len() + n > 2048 {
                    return Err("result bound".into());
                }
                output.extend_from_slice(&bytes[..n]);
            }
            Err(-110 | -11) => {}
            Err(e) => return Err(format!("result {e}")),
        }
        let waited = child.wait(if live {
            1
        } else {
            (until - previous).min(1000)
        })?;
        boundary(&mut stack, &mut previous, until)?;
        if let Some(result) = waited {
            while !result_eof {
                let now = absd_runtime::boot_millis();
                if now < previous || now >= until {
                    return Err("result EOF boundary".into());
                }
                previous = now;
                let observed_result = absd_runtime::read_within(result_in.0, &mut bytes, 1);
                boundary(&mut stack, &mut previous, until)?;
                match observed_result {
                    Ok(0) => result_eof = true,
                    Ok(n) => {
                        if output.len() + n > 2048 {
                            return Err("result bound".into());
                        }
                        output.extend_from_slice(&bytes[..n]);
                    }
                    Err(-110 | -11) => {}
                    Err(e) => return Err(format!("result EOF {e}")),
                }
            }
            // A real protocol EOF must be observed after the bounded terminal
            // acknowledgement. Neither None nor a timeout is EOF.
            while channel.live() {
                let now = absd_runtime::boot_millis();
                if now < previous || now >= until {
                    return Err("protocol EOF boundary".into());
                }
                previous = now;
                channel.poll(&mut stack, &mut pipe);
            }
            if !pipe.eof || !result_eof || result[0] != 1 || result[1] != 0 {
                // Already bounded to 2048 bytes and drained to true result EOF.
                // Preserve the actual child diagnostics before failing; the
                // exit status and both EOF requirements remain unchanged.
                eprintln!(
                    "IPV6 TCP SERVER CONSUMER FAILURE v=1 kind={} status={} request_eof={} result_eof={} output_hex={}",
                    result[0],
                    result[1],
                    u8::from(pipe.eof),
                    u8::from(result_eof),
                    output
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                );
                boundary(&mut stack, &mut previous, until)?;
                return Err(format!("consumer/EOF {result:?}"));
            }
            let text = String::from_utf8(output).map_err(|_| "result UTF8")?;
            if text != "IPV6 TCP SERVER ECHO PASS v=1 bytes=3072 denied=1 nic=0\n" {
                return Err(format!("consumer output {text:?}"));
            }
            print!("{text}");
            println!(
                "IPV6 TCP SERVER REAP v=1 kind={} status={} request_eof=1 result_eof=1 pipe_read_bytes={} pipe_written_bytes={}",
                result[0], result[1], pipe.read_bytes, pipe.written_bytes
            );
            channel.revoke(&mut stack);
            drop((pipe, result_in, child, channel));
            let drain = absd_runtime::boot_millis()
                .checked_add(1000)
                .ok_or("drain overflow")?
                .min(until);
            while stack.socket_count() != 0 {
                let now = absd_runtime::boot_millis();
                if now < previous || now >= drain {
                    break;
                }
                previous = now;
                stack.poll();
                stack.wait(1);
            }
            stack.ipv6_stream_server_fence();
            if stack.socket_count() != 0 {
                return Err("sockets retained".into());
            }
            let after = census("after")?;
            boundary(&mut stack, &mut previous, until)?;
            if (before.processes, before.handles, before.pipes, before.cells)
                != (after.processes, after.handles, after.pipes, after.cells)
            {
                return Err("owned kernel objects not restored".into());
            }
            println!(
                "IPV6 TCP SERVER DONE v=1 child=exited sockets=0 authority=retired objects_restored=1"
            );
            return Ok(());
        }
        if !live {
            return Err("channel retired before child completion".into());
        }
        stack.wait(1);
    }
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("IPV6 TCP SERVER ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
