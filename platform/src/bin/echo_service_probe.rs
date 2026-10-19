#![feature(restricted_std)]
//! Opt-in fixture owner; a private ICMP stack delegates one ping-once pipe.
use absd_net::{
    Config, NicLink,
    echo::{self, Channel, KernelPipe, Owner},
};
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
    let start = absd_runtime::boot_millis();
    let until = start
        .checked_add(echo::MAX_LIFETIME_MS)
        .ok_or("deadline overflow")?;
    let mut last = start;
    absd_runtime::link_anchor();
    let nic = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut owner = Owner::open(
        nic,
        Config {
            address: [192, 0, 2, 100].into(),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 1024,
            tx_buffer: 1024,
        },
    )
    .map_err(|e| format!("owner {e:?}"))?;
    let issued = absd_runtime::boot_millis();
    if issued < last || issued >= until {
        return Err("startup clock/deadline".into());
    }
    last = issued;
    let endpoint = owner
        .grant([192, 0, 2, 1], until, |bytes| {
            getrandom_0_2::getrandom(bytes).map_err(|_| -5)
        })
        .map_err(|e| format!("grant {e:?}"))?;
    let expires = owner
        .expires_ms(endpoint)
        .map_err(|e| format!("expiry {e:?}"))?;
    let mut channel = Channel::new(&mut owner, endpoint).map_err(|e| format!("channel {e:?}"))?;
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
        b"ping-once",
        copies.len(),
        &mut startup,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    let image = include_bytes!(env!("ABSD_PING_CLIENT_ELF"));
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
    let mut bootstrap = [1, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    bootstrap[5..].copy_from_slice(&expires.to_be_bytes());
    absd_runtime::write_within(parent_out.0, &bootstrap, 1000)
        .map_err(|e| format!("bootstrap {e}"))?;
    let mut pipe = KernelPipe {
        request_reader: parent_in.0,
        reply_writer: parent_out.0,
    };
    core::mem::forget((parent_in, parent_out));
    let mut output = Vec::new();
    loop {
        let now = absd_runtime::boot_millis();
        if now < last || now >= until {
            owner.fence();
            return Err("owner clock/deadline".into());
        }
        last = now;
        let live = channel.poll(&mut owner, &mut pipe);
        if live {
            owner.poll().map_err(|e| format!("poll {e:?}"))?;
        } else {
            owner.fence();
        }
        let after = absd_runtime::boot_millis();
        if after < last || after >= until {
            owner.fence();
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
                || text.lines().count() != 1
                || !text.starts_with("PING peer=192.0.2.1 identifier=")
                || !text.ends_with(" auth=none denied=1 nic=0 requests=1\n")
            {
                return Err(format!("consumer {result:?}"));
            }
            channel.revoke(&mut owner);
            owner.fence();
            if owner.socket_count() != 0 {
                return Err("sockets retained".into());
            }
            println!("PING DONE child=exited sockets=0 requests=1");
            return Ok(());
        }
        if !live {
            return Err("consumer channel retired before terminal result".into());
        }
        owner.wait(1).map_err(|e| format!("wait {e:?}"))?;
    }
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            println!("PING ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
