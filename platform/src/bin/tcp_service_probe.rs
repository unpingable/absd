#![feature(restricted_std)]
//! Bounded native service/consumer demonstration, with raw spawn_image
//! only to construct dedicated pipe grants; no new startup role or syscall.
use absd_net::datagram::{self as d, channel::KernelPipe};
use absd_net::{Config, Connection, NicLink, Stack, dns, stream as s};
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
    channel: s::channel::Channel<Service>,
    pipe: KernelPipe,
    mode: u8,
    start: u64,
    done: bool,
    result_reader: u64,
    result: Vec<u8>,
}

enum Service {
    Stream(s::Session),
    Dns(dns::tcp::Session),
}
impl s::channel::Handler for Service {
    fn request<L: absd_net::Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; d::MAX_MESSAGE],
    ) -> usize {
        match self {
            Self::Stream(s) => s.request(stack, request, reply),
            Self::Dns(s) => s::channel::Handler::request(s, stack, request, reply),
        }
    }
    fn revoke<L: absd_net::Link>(&mut self, stack: &mut Stack<L>) {
        match self {
            Self::Stream(s) => s.revoke(stack),
            Self::Dns(s) => s::channel::Handler::revoke(s, stack),
        }
    }
}
fn spawn(stack: &mut Stack<NicLink>, index: u16, mode: u8) -> Result<Client, String> {
    let image = include_bytes!(env!("ABSD_TCP_CLIENT_ELF"));
    let peer = d::Address {
        ip: [10, 0, 2, 2],
        port: 42100 + mode as u16,
    };
    let grant = s::Grant {
        local_port: 7100 + index,
        peer,
        connect_timeout_ms: 2000,
        lifetime_ms: 60000,
    };
    let service = if (4..=9).contains(&mode) {
        Service::Dns(
            dns::tcp::Session::grant(
                stack,
                d::Grant {
                    local_port: grant.local_port,
                    peer,
                },
                grant,
            )
            .map_err(|e| format!("DNS grant {e:?}"))?,
        )
    } else {
        Service::Stream(s::Session::grant(stack, grant).map_err(|e| format!("TCP grant {e:?}"))?)
    };
    let mut channel = s::channel::Channel::new(service);
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
    let arg: &[u8] = b"native-consumer";
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
        b"tcp-client",
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
    let bootstrap = [
        mode,
        10,
        0,
        2,
        2,
        (grant.peer.port >> 8) as u8,
        grant.peer.port as u8,
    ];
    absd_runtime::write_within(parent_out, &bootstrap, 1000)
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
        mode,
        start: absd_runtime::boot_millis(),
        done: false,
    })
}

fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let link = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut stack = Stack::open(link, Config::qemu_user()).map_err(|e| format!("stack {e:?}"))?;
    let listener = stack.listen(7000, 2).map_err(|e| format!("TCP {e:?}"))?;
    let mut connections: Vec<Connection> = Vec::new();
    let mut clients = Vec::new();
    for mode in [0u8, 1, 10, 11] {
        clients.push(spawn(&mut stack, mode as u16, mode)?);
    }
    let mut next_batch = 0;
    println!("TCP SERVICE READY clients=4 tcp=7000");
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
            let mut text = [0; 256];
            if let Ok(n) = absd_runtime::read_within(client.result_reader, &mut text, 1) {
                if client.result.len() + n > 8192 {
                    return Err("client output bound".into());
                }
                client.result.extend_from_slice(&text[..n]);
            }
            if client.mode == 11 && now - client.start >= 100 {
                ok(sys(20, client.process, 0, 0))?;
                client.mode = 12;
            }
            let mut record = [0u64; 4];
            let result = sys(6, client.process, record.as_mut_ptr() as u64, 1);
            if result >= 0 {
                let was_live = client.channel.live();
                client.channel.revoke(&mut stack);
                println!(
                    "TCP CHILD DONE mode={} kind={} status={}",
                    client.mode, record[0], record[1]
                );
                // Drain output after exit, still bounded; all writers are gone.
                let mut text = [0; 256];
                loop {
                    match absd_runtime::read_within(client.result_reader, &mut text, 1) {
                        Ok(0) => break,
                        Ok(n) => {
                            if client.result.len() + n > 8192 {
                                return Err("client output bound".into());
                            }
                            client.result.extend_from_slice(&text[..n]);
                        }
                        Err(_) => break,
                    }
                }
                print!(
                    "TCP CONSUMER mode={} {}",
                    client.mode,
                    String::from_utf8_lossy(&client.result)
                );
                if client.mode != 12 && (record[0] != 1 || record[1] != 0) {
                    return Err("native consumer failed".into());
                }
                if client.mode == 10 && was_live {
                    return Err("partial frame survived".into());
                }
                if client.mode == 12 && record[0] != 3 {
                    return Err("interrupted child did not report killed".into());
                }
                let _ = absd_runtime::close(client.result_reader);
                client.done = true;
                let _ = absd_runtime::close(client.process);
            } else if result != -110 {
                return Err(format!("wait {result}"));
            }
        }
        if clients.iter().all(|c| c.done) && tcp_bytes > 0 {
            let modes: &[u8] = match next_batch {
                0 => &[2, 3, 4, 5],
                1 => &[6, 7, 8, 9],
                _ => &[],
            };
            if modes.is_empty() {
                break;
            }
            clients.clear();
            for &mode in modes {
                clients.push(spawn(&mut stack, mode as u16, mode)?);
            }
            next_batch += 1;
        }
        if now - start > 45000 {
            return Err(format!("deadline tcp_bytes={tcp_bytes}"));
        }
        stack.wait(1);
    }
    stack.datagram_fence();
    stack.stream_fence();
    for c in connections {
        let _ = stack.abort(c);
    }
    stack.poll();
    stack
        .unlisten(listener)
        .map_err(|e| format!("unlisten {e:?}"))?;
    println!(
        "TCP SERVICE DONE streams=4 dns=6 partial=1 interrupted=1 tcp_bytes={tcp_bytes} sockets={}",
        stack.socket_count()
    );
    if stack.socket_count() != 0 {
        return Err("sockets retained".into());
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            println!("TCP SERVICE ERROR {e}");
            std::process::ExitCode::from(1)
        }
    }
}
