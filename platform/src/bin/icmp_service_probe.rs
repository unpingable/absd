#![feature(restricted_std)]
//! Bounded native service/consumer demonstration, with raw spawn_image
//! only to construct dedicated pipe grants; no new startup role or syscall.
use absd_net::datagram::{
    self as d,
    channel::{Channel, KernelPipe},
};
use absd_net::{Config, NicLink, Stack};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};

fn sys(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let out: i64;
    unsafe {
        core::arch::asm!("int 0x80",inlateout("rax") n=>out,in("rdi")a,in("rsi")b,in("rdx")c,options(nostack,preserves_flags));
    }
    out
}
fn ok(n: i64) -> Result<u64, String> {
    if n < 0 {
        Err(format!("kernel {n}"))
    } else {
        Ok(n as u64)
    }
}
fn pipe() -> Result<(u64, u64), String> {
    let both = ok(sys(16, 0, 0, 0))?;
    let reader = match absd_runtime::duplicate(both, RIGHT_READ) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = absd_runtime::close(both);
            return Err(format!("reader {error}"));
        }
    };
    let writer = match absd_runtime::duplicate(both, RIGHT_WRITE) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = absd_runtime::close(reader);
            let _ = absd_runtime::close(both);
            return Err(format!("writer {error}"));
        }
    };
    let _ = absd_runtime::close(both);
    Ok((reader, writer))
}
struct Client {
    process: u64,
    channel: Channel,
    pipe: KernelPipe,
    index: u16,
    done: bool,
    result_reader: u64,
    result: Vec<u8>,
}

fn spawn(stack: &mut Stack<NicLink>, index: u16) -> Result<Client, String> {
    let image: &[u8] = if index == 0 {
        include_bytes!(env!("ABSD_DNS_CLIENT_ELF"))
    } else {
        include_bytes!(env!("ABSD_UDP_CLIENT_ELF"))
    };
    let grant = d::Grant {
        local_port: 7200 + index,
        peer: d::Address {
            ip: [10, 0, 2, 2],
            port: 42150 + index,
        },
    };
    let mut channel = Channel::grant(stack, grant).map_err(|e| format!("grant {e:?}"))?;
    let (child_in, parent_out) = pipe()?;
    let (parent_in, child_out) = pipe()?;
    let (result_reader, result_writer) = pipe()?;
    let (startup_reader, startup_writer) = pipe()?;
    let copies = [
        [startup_reader, RIGHT_READ, 0],
        [child_in, RIGHT_READ, 0],
        [child_out, RIGHT_WRITE, 0],
        [result_writer, RIGHT_WRITE, 0],
        [child_out, RIGHT_WRITE, 1],
    ];
    let arg: &[u8] = b"--icmp";
    let mut record = [0; absd_broker::MAX_STARTUP];
    let length = absd_broker::encode_startup(
        &[
            (absd_broker::role::STDIN, 1),
            (absd_broker::role::STDOUT, 2),
            (absd_broker::role::STDERR, 3),
        ],
        [arg],
        [],
        b"/",
        b"icmp-consumer",
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
    let result = spawn_image_raw(req.as_ptr() as u64, SPAWN_NO_SPAWN, 0);
    for h in [startup_reader, child_in, child_out, result_writer] {
        let _ = absd_runtime::close(h);
    }
    if result < 0 {
        channel.revoke(stack);
        for h in [parent_in, parent_out, result_reader, startup_writer] {
            let _ = absd_runtime::close(h);
        }
        return Err(format!("spawn {result}"));
    }
    absd_runtime::write_within(startup_writer, &record[..length], 1000)
        .map_err(|e| format!("startup write {e}"))?;
    let _ = absd_runtime::close(startup_writer);
    let dns_boot = [
        0,
        10,
        0,
        2,
        2,
        (grant.peer.port >> 8) as u8,
        grant.peer.port as u8,
    ];
    let udp_boot = [3, (grant.peer.port >> 8) as u8, grant.peer.port as u8];
    let bootstrap: &[u8] = if index == 0 { &dns_boot } else { &udp_boot };
    absd_runtime::write_within(parent_out, bootstrap, 1000)
        .map_err(|e| format!("bootstrap {e}"))?;
    Ok(Client {
        process: result as u64,
        result_reader,
        result: Vec::new(),
        channel,
        pipe: KernelPipe {
            request_reader: parent_in,
            reply_writer: parent_out,
        },
        index,
        done: false,
    })
}

fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let link = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut stack = Stack::open(link, Config::qemu_user()).map_err(|e| format!("stack {e:?}"))?;
    let mut clients = vec![spawn(&mut stack, 0)?, spawn(&mut stack, 1)?];
    println!("ICMP SERVICE READY clients=2 dns=42150 udp=42151");
    let start = absd_runtime::boot_millis();
    while clients.iter().any(|c| !c.done) {
        stack.poll();
        for client in &mut clients {
            if client.done {
                continue;
            }
            client.channel.poll(&mut stack, &mut client.pipe);
            let mut text = [0; 256];
            if let Ok(n) = absd_runtime::read_within(client.result_reader, &mut text, 1) {
                if client.result.len() + n > 2048 {
                    return Err("consumer output bound".into());
                }
                client.result.extend_from_slice(&text[..n]);
            }
            let mut record = [0u64; 4];
            let result = sys(6, client.process, record.as_mut_ptr() as u64, 1);
            if result >= 0 {
                client.channel.revoke(&mut stack);
                loop {
                    match absd_runtime::read_within(client.result_reader, &mut text, 1) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if client.result.len() + n > 2048 {
                                return Err("consumer output bound".into());
                            }
                            client.result.extend_from_slice(&text[..n]);
                        }
                    }
                }
                println!(
                    "ICMP CONSUMER index={} kind={} status={} {}",
                    client.index,
                    record[0],
                    record[1],
                    String::from_utf8_lossy(&client.result)
                );
                if record[0] != 1 || record[1] != 0 {
                    return Err("native ICMP consumer failed".into());
                }
                let _ = absd_runtime::close(client.result_reader);
                let _ = absd_runtime::close(client.process);
                client.done = true;
            } else if result != -110 {
                return Err(format!("wait {result}"));
            }
        }
        if absd_runtime::boot_millis() - start > 10000 {
            return Err("consumer deadline".into());
        }
        stack.wait(1);
    }
    stack.datagram_fence();
    stack.poll();
    if stack.socket_count() != 0 {
        return Err("sockets retained".into());
    }
    println!("ICMP SERVICE DONE dns=1 udp=1 sockets=0");
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            println!("ICMP SERVICE ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
