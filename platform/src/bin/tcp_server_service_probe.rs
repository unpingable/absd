#![feature(restricted_std)]
//! Dedicated boot: one bounded server capability and a pipe-only echo child.
use absd_net::datagram::channel::KernelPipe;
use absd_net::{Config, NicLink, Stack};
use absd_net::{datagram as d, stream::server::Channel};
use absd_runtime::{
    RIGHT_READ, RIGHT_WRITE,
    process::{SPAWN_NO_SPAWN, spawn_image_raw},
};

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
fn run() -> Result<(), String> {
    absd_runtime::link_anchor();
    let nic = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let config = Config {
        address: [192, 0, 2, 100].into(),
        prefix_len: 24,
        gateway: None,
        rx_buffer: 1024,
        tx_buffer: 1024,
    };
    let mut stack = Stack::open(nic, config).map_err(|e| format!("stack {e:?}"))?;
    let mut channel = Channel::grant(
        &mut stack,
        absd_net::stream::server::Grant {
            local_port: 7005,
            peer: d::Address {
                ip: [192, 0, 2, 1],
                port: 42030,
            },
            accept_timeout_ms: 5000,
            lifetime_ms: 10000,
        },
    )
    .map_err(|e| format!("grant {e:?}"))?;
    let start = absd_runtime::boot_millis();
    let until = start.checked_add(10_000).ok_or("deadline overflow")?;
    let mut last = start;
    println!(
        "TCP SERVER GRANT READY local=192.0.2.100:7005 peer=192.0.2.1:42030 lifetime_ms=10000"
    );
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
        [],
        [],
        b"/",
        b"tcp-server-echo",
        copies.len(),
        &mut startup,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    let image = include_bytes!(env!("ABSD_TCP_SERVER_CHILD_ELF"));
    let request = [
        image.as_ptr() as u64,
        image.len() as u64,
        copies.as_ptr() as u64,
        copies.len() as u64,
    ];
    let mut child = Child(handle(spawn_image_raw(
        request.as_ptr() as u64,
        SPAWN_NO_SPAWN,
        0,
    ))?);
    drop((startup_in, child_in, child_out, result_out));
    absd_runtime::write_within(startup_out.0, &startup[..length], 1000)
        .map_err(|e| format!("startup write {e}"))?;
    drop(startup_out);
    absd_runtime::write_within(parent_out.0, &[3, 192, 0, 2, 1, 0xa4, 0x2e], 1000)
        .map_err(|e| format!("bootstrap {e}"))?;
    let mut pipe = KernelPipe {
        request_reader: parent_in.0,
        reply_writer: parent_out.0,
    };
    // KernelPipe takes ownership of exactly these two handles.
    core::mem::forget((parent_in, parent_out));
    let mut output = Vec::new();
    let mut listen_announced = false;
    loop {
        let now = absd_runtime::boot_millis();
        if now < last || now >= until {
            stack.stream_server_fence();
            return Err("owner clock/deadline".into());
        }
        last = now;
        let live = channel.poll(&mut stack, &mut pipe);
        // This fixture has no other sockets: LISTEN is the only constructor.
        // The peer runner also requires no eligible SYN before this marker.
        if !listen_announced && stack.socket_count() == 1 {
            println!("TCP SERVER LISTEN READY sockets=1");
            listen_announced = true;
        }
        // EOF before CLOSE cancels immediately; explicit CLOSE may drain FIN.
        stack.poll();
        let after = absd_runtime::boot_millis();
        if after < last || after >= until {
            stack.stream_server_fence();
            return Err("owner clock/deadline after I/O".into());
        }
        last = after;
        let mut bytes = [0; 256];
        match absd_runtime::read_within(result_in.0, &mut bytes, 1) {
            Ok(n) => {
                if output.len() + n > 2048 {
                    return Err("result bound".into());
                }
                output.extend_from_slice(&bytes[..n]);
            }
            Err(-110 | -11) => {}
            Err(e) => return Err(format!("result {e}")),
        }
        // EOF can precede the terminal record. An unclosed session is
        // canceled; an explicit CLOSE retains only its bounded drain.
        if let Some(result) = child.wait(if live { 1 } else { 1000 })? {
            loop {
                match absd_runtime::read_within(result_in.0, &mut bytes, 1) {
                    Ok(0) => break,
                    Ok(n) => {
                        if output.len() + n > 2048 {
                            return Err("result bound".into());
                        }
                        output.extend_from_slice(&bytes[..n]);
                    }
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&output);
            print!("{text}");
            if result[0] != 1
                || result[1] != 0
                || !text.contains("TCP SERVER ECHO PASS bytes=3072 denied=1 nic=0\n")
            {
                return Err(format!("consumer {result:?}"));
            }
            channel.revoke(&mut stack);
            let drain = absd_runtime::boot_millis()
                .checked_add(1000)
                .ok_or("drain overflow")?
                .min(until);
            while stack.socket_count() != 0 {
                let now = absd_runtime::boot_millis();
                if now < last || now >= drain {
                    break;
                }
                last = now;
                stack.poll();
                stack.wait(1);
            }
            stack.stream_server_fence();
            if stack.socket_count() != 0 {
                return Err("sockets retained".into());
            }
            println!("TCP SERVER DONE child=exited sockets=0");
            return Ok(());
        }
        if !live {
            return Err("consumer channel retired before terminal result".into());
        }
        stack.wait(1);
    }
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            println!("TCP SERVER ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
