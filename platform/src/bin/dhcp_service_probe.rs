#![feature(restricted_std)]
//! Dedicated boot only. Static SSH/operator configuration does not invoke this.
use absd_net::datagram::channel::KernelPipe;
use absd_net::{
    NicLink,
    dhcp::{Owner, Policy},
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
    absd_runtime::link_anchor();
    let nic = NicLink::from_startup().map_err(|e| format!("NIC {e:?}"))?;
    let mut owner = Owner::acquire(nic, Policy::fixture()).map_err(|e| format!("acquire {e:?}"))?;
    let lease = owner.lease();
    println!(
        "DHCP ACTIVE address=192.0.2.100/24 router=192.0.2.1 resolver=192.0.2.1 xid={} request_ms={} renew_ms={} rebind_ms={} expires_ms={} stop_ms={}",
        lease.xid,
        lease.request_ms,
        lease.renew_ms,
        lease.rebind_ms,
        lease.expires_ms,
        owner.stop_ms()
    );
    let mut channel = owner.dns_channel().map_err(|e| format!("grant {e:?}"))?;
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
        b"dhcp-dns-client",
        copies.len(),
        &mut startup,
    )
    .map_err(|e| format!("startup {e:?}"))?;
    let image = include_bytes!(env!("ABSD_DHCP_DNS_CLIENT_ELF"));
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
    absd_runtime::write_within(parent_out.0, &[1, 192, 0, 2, 1, 0, 53], 1000)
        .map_err(|e| format!("bootstrap {e}"))?;
    let mut pipe = KernelPipe {
        request_reader: parent_in.0,
        reply_writer: parent_out.0,
    };
    // KernelPipe takes ownership of exactly these two handles.
    core::mem::forget((parent_in, parent_out));
    let mut output = Vec::new();
    loop {
        let live = owner
            .poll(&mut channel, &mut pipe)
            .map_err(|e| format!("lease {e:?}"))?;
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
        // EOF can precede the terminal process record. The owner has already
        // retired its entire Stack; give this exact child one bounded reap.
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
                || !text.contains("DHCP DNS ANSWER 198.51.100.9 denied=1 nic=0\n")
            {
                return Err(format!("consumer {result:?}"));
            }
            owner.retire();
            println!(
                "DHCP DONE child=exited owner=retired renew=unsupported rebind=unsupported refused={}",
                owner.refused_frames()
            );
            return Ok(());
        }
        if !live {
            return Err("consumer channel retired before terminal result".into());
        }
        owner.wait().map_err(|e| format!("wait {e:?}"))?;
    }
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            println!("DHCP ERROR {error}");
            std::process::ExitCode::from(1)
        }
    }
}
