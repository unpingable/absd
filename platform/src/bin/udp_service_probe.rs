#![feature(restricted_std)]
//! Bounded native service/consumer demonstration, with raw spawn_image
//! only to construct dedicated pipe grants; no new startup role or syscall.
use absd_net::datagram::{
    self as d,
    channel::{Channel, KernelPipe},
};
use absd_net::{Config, Connection, NicLink, Stack};
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
    mode: u8,
    start: u64,
    done: bool,
}

fn spawn(stack: &mut Stack<NicLink>, index: u16, mode: u8) -> Result<Client, String> {
    let image = include_bytes!(env!("ABSD_UDP_CLIENT_ELF"));
    let grant = d::Grant {
        local_port: 7002 + index,
        peer: d::Address {
            ip: [10, 0, 2, 2],
            port: 42000 + index,
        },
    };
    let mut channel = Channel::grant(stack, grant).map_err(|e| format!("grant {e:?}"))?;
    let (child_in, parent_out) = pipe()?;
    let (parent_in, child_out) = pipe()?;
    let copies = [[child_in, RIGHT_READ, 0], [child_out, RIGHT_WRITE, 1]];
    let req = [
        image.as_ptr() as u64,
        image.len() as u64,
        copies.as_ptr() as u64,
        2,
    ];
    let result = spawn_image_raw(req.as_ptr() as u64, SPAWN_NO_SPAWN, 0);
    for h in [child_in, child_out] {
        let _ = absd_runtime::close(h);
    }
    if result < 0 {
        channel.revoke(stack);
        for h in [parent_in, parent_out] {
            let _ = absd_runtime::close(h);
        }
        return Err(format!("spawn {result}"));
    }
    let bootstrap = [mode, (grant.peer.port >> 8) as u8, grant.peer.port as u8];
    if sys(1, parent_out, bootstrap.as_ptr() as u64, 3) != 3 {
        return Err("bootstrap write".into());
    }
    Ok(Client {
        process: result as u64,
        channel,
        pipe: KernelPipe {
            request_reader: parent_in,
            reply_writer: parent_out,
        },
        mode,
        start: absd_runtime::boot_millis(),
        done: false,
    })
}

fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let link = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut stack = Stack::open(link, Config::qemu_user()).map_err(|e| format!("stack {e:?}"))?;
    if absd_runtime::step() != 1 {
        return link_case(&mut stack);
    }
    let listener = stack.listen(7000, 2).map_err(|e| format!("TCP {e:?}"))?;
    let mut connections: Vec<Connection> = Vec::new();
    let mut clients = Vec::new();
    for (index, mode) in [0, 0, 1, 2].into_iter().enumerate() {
        clients.push(spawn(&mut stack, index as u16, mode)?);
    }
    println!("UDP SERVICE READY clients=4 tcp=7000");
    let start = absd_runtime::boot_millis();
    let mut tcp_bytes = 0;
    loop {
        stack.poll();
        while let Some(c) = stack.accept(listener) {
            connections.push(c);
        }
        let mut i = 0;
        while i < connections.len() {
            let c = connections[i];
            let mut b = [0; 128];
            if stack.send_room(c).unwrap_or(0) >= b.len() {
                match stack.recv(c, &mut b) {
                    Ok(n) if n > 0 => {
                        stack
                            .send(c, &b[..n])
                            .map_err(|e| format!("TCP send {e:?}"))?;
                        tcp_bytes += n;
                    }
                    Err(_) => {
                        let _ = stack.abort(c);
                        connections.swap_remove(i);
                        continue;
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        let now = absd_runtime::boot_millis();
        for client in &mut clients {
            if client.done {
                continue;
            }
            client.channel.poll(&mut stack, &mut client.pipe);
            if client.mode == 2 && now - client.start >= 50 {
                ok(sys(20, client.process, 0, 0))?;
                client.mode = 3;
            }
            let mut record = [0u64; 4];
            let result = sys(6, client.process, record.as_mut_ptr() as u64, 1);
            if result >= 0 {
                let was_live = client.channel.live();
                client.channel.revoke(&mut stack);
                println!(
                    "UDP CLIENT DONE mode={} kind={} status={}",
                    client.mode, record[0], record[1]
                );
                if client.mode == 0 && (record[0] != 1 || record[1] != 0) {
                    return Err("native consumer failed".into());
                }
                if client.mode == 1 && was_live {
                    return Err("partial frame survived".into());
                }
                client.done = true;
                let _ = absd_runtime::close(client.process);
            } else if result != -110 {
                return Err(format!("wait {result}"));
            }
        }
        if clients.iter().all(|c| c.done) && now - start > 1500 && tcp_bytes > 0 {
            break;
        }
        if now - start > 15000 {
            return Err(format!("deadline tcp_bytes={tcp_bytes}"));
        }
        stack.wait(1);
    }
    stack.datagram_fence();
    for c in connections {
        let _ = stack.abort(c);
    }
    stack.poll();
    stack
        .unlisten(listener)
        .map_err(|e| format!("unlisten {e:?}"))?;
    println!(
        "UDP SERVICE DONE native=2 partial=1 interrupted=1 tcp_bytes={tcp_bytes} sockets={}",
        stack.socket_count()
    );
    if stack.socket_count() != 0 {
        return Err("sockets retained".into());
    }
    Ok(())
}

fn link_case(stack: &mut Stack<NicLink>) -> Result<(), String> {
    let grant = d::Grant {
        local_port: 7002,
        peer: d::Address {
            ip: [10, 0, 2, 2],
            port: 42000,
        },
    };
    let endpoint = stack
        .datagram_bind(grant)
        .map_err(|e| format!("bind {e:?}"))?;
    if absd_runtime::step() == 2 {
        if stack.link_up() {
            return Err("expected carrier down".into());
        }
        if stack.datagram_send(endpoint, grant.peer, b"down") != Err(d::Error::LinkDown) {
            return Err("carrier refusal".into());
        }
        stack.poll();
        println!("UDP LINK DOWN FENCED");
        let end = absd_runtime::boot_millis() + 10_000;
        while !stack.link_up() && absd_runtime::boot_millis() < end {
            stack.poll();
            stack.wait(10);
        }
        if !stack.link_up() {
            return Err("carrier return deadline".into());
        }
        if stack.datagram_send(endpoint, grant.peer, b"old") != Err(d::Error::Stale) {
            return Err("old authority revived".into());
        }
        let fresh = stack
            .datagram_bind(grant)
            .map_err(|e| format!("regrant {e:?}"))?;
        stack
            .datagram_close(fresh)
            .map_err(|e| format!("close {e:?}"))?;
        println!(
            "UDP LINK UP FRESH GRANT ONLY sockets={}",
            stack.socket_count()
        );
    } else {
        stack.poll();
        if !stack.disabled() {
            return Err("device did not disable".into());
        }
        if stack.datagram_send(endpoint, grant.peer, b"old") != Err(d::Error::Stale) {
            return Err("disabled authority survived".into());
        }
        let start = absd_runtime::boot_millis();
        let mut passes = 0;
        while absd_runtime::boot_millis() - start < 1000 {
            stack.poll();
            stack.wait(10);
            passes += 1;
        }
        if !(50..=200).contains(&passes) {
            return Err(format!("device pacing {passes}"));
        }
        println!(
            "UDP DEVICE FAILED FENCED passes={passes} sockets={}",
            stack.socket_count()
        );
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            println!("UDP SERVICE FAILED {e}");
            std::process::ExitCode::from(1)
        }
    }
}
