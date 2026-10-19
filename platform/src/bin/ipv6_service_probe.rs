#![feature(restricted_std)]
//! A static on-link IPv6 owner delegates a single UDP capability to DNS.
//! This diagnostic uses existing pipes/spawn/NIC calls, without an ABI change.
use absd_net::{
    Config, NicLink, Stack,
    ipv6::{
        self as v6,
        channel::{Channel, KernelPipe},
    },
};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};

#[path = "../ipv6_probe_boundaries.rs"]
mod ipv6_probe_boundaries;

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
        core::arch::asm!("int 0x80", inlateout("rax") n=>out,
        in("rdi") a, in("rsi") b, in("rdx") c, options(nostack,preserves_flags));
    }
    out
}
fn pipe() -> Result<(Handle, Handle), String> {
    let both = sys(16, 0, 0, 0);
    if both < 0 {
        return Err(format!("pipe {both}"));
    }
    let both = Handle(both as u64);
    let reader =
        Handle(absd_runtime::duplicate(both.0, RIGHT_READ).map_err(|e| format!("reader {e}"))?);
    let writer =
        Handle(absd_runtime::duplicate(both.0, RIGHT_WRITE).map_err(|e| format!("writer {e}"))?);
    Ok((reader, writer))
}

fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let link = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut stack = Stack::open(link, Config::qemu_user()).map_err(|e| format!("stack {e:?}"))?;
    // fd00:ab5d::15/64 and fd00:ab5d::2 are fixture-owned static addresses.
    let mut local = [0; 16];
    local[..4].copy_from_slice(&[0xfd, 0, 0xab, 0x5d]);
    local[15] = 0x15;
    let mut peer_ip = local;
    peer_ip[15] = 2;
    stack
        .configure_ipv6(v6::Config {
            address: local,
            prefix_len: 64,
            scope: 1,
        })
        .map_err(|e| format!("IPv6 config {e:?}"))?;
    ipv6_probe_boundaries::run(&mut stack)?;
    ipv6_probe_boundaries::run_pipes(&mut stack)?;
    let peer = v6::Address {
        ip: peer_ip,
        port: 42010,
        scope: 1,
    };
    let mut channel = Channel::grant(
        &mut stack,
        v6::Grant {
            local_port: 7002,
            peer,
        },
    )
    .map_err(|e| format!("grant {e:?}"))?;
    let result = run_child(&mut stack, &mut channel, peer);
    channel.revoke(&mut stack);
    result
}

fn run_child(
    stack: &mut Stack<NicLink>,
    channel: &mut Channel,
    peer: v6::Address,
) -> Result<(), String> {
    let image = include_bytes!(env!("ABSD_IPV6_CLIENT_ELF"));
    let (child_in, parent_out) = pipe()?;
    let (parent_in, child_out) = pipe()?;
    let (result_reader, result_writer) = pipe()?;
    let (startup_reader, startup_writer) = pipe()?;
    let copies = [
        [startup_reader.0, RIGHT_READ, 0],
        [child_in.0, RIGHT_READ, 0],
        [child_out.0, RIGHT_WRITE, 0],
        [result_writer.0, RIGHT_WRITE, 0],
        [child_out.0, RIGHT_WRITE, 1],
    ];
    let mut record = [0; absd_broker::MAX_STARTUP];
    let n = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        core::iter::empty::<&[u8]>(),
        core::iter::empty::<&[u8]>(),
        b"/",
        b"ipv6-dns-client",
        copies.len(),
        &mut record,
    )
    .map_err(|e| format!("startup {e:?}"))?;
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
    // Every error after spawn still stops/reaps the child before handles close.
    let result = (|| {
        absd_runtime::write_within(startup_writer.0, &record[..n], 1000)
            .map_err(|e| format!("startup write {e}"))?;
        drop(startup_writer);
        let mut bootstrap = [0; 22];
        bootstrap[..16].copy_from_slice(&peer.ip);
        bootstrap[16..20].copy_from_slice(&peer.scope.to_be_bytes());
        bootstrap[20..22].copy_from_slice(&peer.port.to_be_bytes());
        absd_runtime::write_within(parent_out.0, &bootstrap, 1000)
            .map_err(|e| format!("bootstrap {e}"))?;
        let mut io = KernelPipe {
            request_reader: parent_in.take(),
            reply_writer: parent_out.take(),
        };
        let mut result = Vec::new();
        let start = absd_runtime::boot_millis();
        println!("IPV6 SERVICE READY static-on-link scope=1 udp=7002 peer-port=42010");
        loop {
            stack.poll();
            let channel_live = channel.poll(stack, &mut io);
            let mut bytes = [0; 256];
            match absd_runtime::read_within(result_reader.0, &mut bytes, 1) {
                Ok(n) => {
                    if result.len() + n > 4096 {
                        return Err("result overflow".into());
                    }
                    result.extend_from_slice(&bytes[..n]);
                }
                Err(-110 | -11) => {}
                Err(e) => return Err(format!("result read {e}")),
            }
            let mut outcome = [0u64; 4];
            let waited = sys(
                6,
                process.0,
                outcome.as_mut_ptr() as u64,
                if channel_live { 1 } else { 50 },
            );
            if waited >= 0 {
                process.0 = 0; // Successful wait consumes the kernel process handle.
                let kind = outcome[0];
                let status = outcome[1];
                // Drain the finite remaining result pipe after child termination.
                loop {
                    match absd_runtime::read_within(result_reader.0, &mut bytes, 1) {
                        Ok(0) | Err(-110 | -11) => break,
                        Ok(n) if result.len() + n <= 4096 => result.extend_from_slice(&bytes[..n]),
                        _ => return Err("result drain".into()),
                    }
                }
                let text = String::from_utf8_lossy(&result);
                print!("{text}");
                if kind != 1
                    || status != 0
                    || !text.contains("IPV6 DNS A PASS")
                    || !text.contains("IPV6 CLIENT AUTHORITY PASS")
                    || !text.contains("IPV6 DNS AAAA PASS")
                {
                    return Err(format!("child status {status}"));
                }
                println!("IPV6 SERVICE PASS");
                return Ok(());
            }
            if !channel_live {
                return Err("delegated channel ended before child exit".into());
            }
            if waited < 0 && waited != -110 {
                return Err(format!("wait {waited}"));
            }
            if absd_runtime::boot_millis().saturating_sub(start) > 10_000 {
                return Err("child deadline".into());
            }
            stack.wait(1);
        }
    })();
    channel.revoke(stack);
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
            return Err(format!("child cleanup kill={killed} wait={waited}"));
        }
    }
    result
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("IPV6 SERVICE ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
