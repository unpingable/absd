#![feature(restricted_std)]
//! The network qualification workload (`scripts/net-matrix.py`): a durable
//! worker holding the NIC runs `absd-net` (smoltcp) as 10.0.2.15/24.
//!
//! Step 1, frames: ARP and ICMP echo are answered by the stack itself; the
//! host harness talks to it over `-netdev dgram` with raw frames. Frames of
//! the local experimental EtherType 0x88b5 are diverted to this program as
//! control: `S` asks for the counters (answered with an 0x88b5 frame), `Q`
//! ends the run.
//!
//! Step 2, TCP behind QEMU's user network: port 7000 echoes every byte back
//! (reading only as much as it can queue, so a client that does not read
//! gets backpressure), closing after the peer's FIN; port 7001 takes one
//! command line: `STATS`, `SOURCE n` (n pattern bytes, then this side
//! closes first), `SPAWN` (runs `broker-echo` through init's broker and
//! reports its outcome), or `QUIT`.
//!
//! Everything it prints goes to stdout, which init frames onto the serial
//! log; the harness reads it from there.

use std::io::Write;
use std::process::ExitCode;

use absd_net::{Config, Connection, NetError, NicLink, Stack};

const CONTROL_ETHERTYPE: u16 = 0x88b5;
const ECHO_PORT: u16 = 7000;
const CONTROL_PORT: u16 = 7001;
/// Silence from the harness this long ends the run as a failure.
const IDLE_MS: u64 = 90_000;
/// How long the dead-NIC loop runs before reporting its pass count.
const DEAD_NIC_MS: u64 = 2_000;

fn mac_text(mac: [u8; 6]) -> String {
    mac.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
}

fn say(line: std::fmt::Arguments<'_>) {
    let mut stdout = std::io::stdout();
    let _ = stdout.write_fmt(line);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

fn main() -> ExitCode {
    absd_runtime::link_anchor();
    let step = absd_runtime::step();
    let link = match NicLink::from_startup() {
        Ok(link) => link,
        Err(error) => {
            say(format_args!("NETD NO NIC {error:?}"));
            return ExitCode::from(2);
        }
    };
    let result = match step {
        1 => frames(link),
        2 => tcp(link),
        3 => dead_nic(link),
        _ => Err(format!("unknown step {step}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            say(format_args!("NETD FAILED {error}"));
            ExitCode::from(1)
        }
    }
}

fn frames(link: NicLink) -> Result<(), String> {
    let config = Config {
        gateway: None,
        rx_buffer: 4096,
        tx_buffer: 4096,
        ..Config::qemu_user()
    };
    let mut stack = Stack::open(link, config).map_err(|error| format!("open {error:?}"))?;
    stack.divert(Some(CONTROL_ETHERTYPE));
    let mac = stack.mac();
    let mut link_up = stack.link_up();
    say(format_args!(
        "NETD FRAMES READY mac={} ip=10.0.2.15/24 link={}",
        mac_text(mac),
        if link_up { "up" } else { "down" }
    ));
    let mut last_heard = absd_runtime::boot_millis();
    loop {
        stack.poll();
        // Opened with the link down: report the carrier once, when it comes.
        if !link_up && stack.link_up() {
            link_up = true;
            say(format_args!("NETD LINK UP"));
        }
        while let Some(frame) = stack.raw_receive() {
            last_heard = absd_runtime::boot_millis();
            if frame.len() < 15 {
                continue;
            }
            match frame[14] {
                b'S' => {
                    let stats = stack.stats();
                    let mut reply = Vec::with_capacity(60);
                    reply.extend_from_slice(&frame[6..12]);
                    reply.extend_from_slice(&mac);
                    reply.extend_from_slice(&CONTROL_ETHERTYPE.to_be_bytes());
                    reply.push(b's');
                    for word in [stats.rx_frames, stats.tx_frames, stats.link_errors, stats.raw_frames] {
                        reply.extend_from_slice(&word.to_le_bytes());
                    }
                    reply.resize(60, 0);
                    stack.raw_send(&reply).map_err(|error| format!("stats reply {error:?}"))?;
                }
                b'Q' => {
                    let stats = stack.stats();
                    say(format_args!(
                        "NETD FRAMES DONE rx_frames={} tx_frames={} link_errors={} raw_frames={} raw_dropped={}",
                        stats.rx_frames, stats.tx_frames, stats.link_errors, stats.raw_frames, stats.raw_dropped
                    ));
                    return if stats.link_errors == 0 { Ok(()) } else { Err("link errors".into()) };
                }
                _ => {}
            }
        }
        if absd_runtime::boot_millis().saturating_sub(last_heard) > IDLE_MS {
            return Err("harness went silent".into());
        }
        stack.wait(10);
    }
}

/// Booted with the kernel's `nic-ring-fault` injection: the stack opens
/// (the fault is found at the first ring access), the first poll disables
/// the NIC, and from then on the poll/wait loop must run at the idle
/// cadence: with no sockets each `wait(10)` pauses the full 10 ms bound,
/// so two seconds make about 200 passes. A window of 5..=20 ms per pass
/// refuses both a spin and a loop that stalls, with the failure counted
/// and the device reported disabled.
fn dead_nic(link: NicLink) -> Result<(), String> {
    let config = Config {
        gateway: None,
        ..Config::qemu_user()
    };
    let mut stack = Stack::open(link, config).map_err(|error| format!("open {error:?}"))?;
    say(format_args!(
        "NETD DEAD NIC READY link={} disabled={}",
        if stack.link_up() { "up" } else { "down" },
        if stack.disabled() { "yes" } else { "no" }
    ));
    let start = absd_runtime::boot_millis();
    let mut passes = 0u64;
    loop {
        passes += 1;
        stack.poll();
        stack.wait(10);
        if absd_runtime::boot_millis().saturating_sub(start) >= DEAD_NIC_MS {
            break;
        }
    }
    let elapsed = absd_runtime::boot_millis().saturating_sub(start);
    let stats = stack.stats();
    let disabled = stack.disabled();
    say(format_args!(
        "NETD DEAD NIC DONE passes={passes} ms={elapsed} link_errors={} last_error={} disabled={}",
        stats.link_errors,
        stats.last_error,
        if disabled { "yes" } else { "no" }
    ));
    if !disabled || stats.link_errors == 0 {
        return Err("the NIC did not disable itself".into());
    }
    if passes * 5 > elapsed {
        return Err(format!("{passes} passes in {elapsed} ms: the loop spun"));
    }
    if passes * 20 < elapsed {
        return Err(format!("{passes} passes in {elapsed} ms: the loop stalled"));
    }
    Ok(())
}

fn pattern(index: u64) -> u8 {
    (index.wrapping_mul(2_654_435_761) >> 13) as u8
}

struct Echo {
    connection: Connection,
    bytes: u64,
}

enum ControlState {
    /// Reading the command line.
    Command(Vec<u8>),
    /// `SOURCE n`: bytes still to queue.
    Source { sent: u64, total: u64 },
}

struct Control {
    connection: Connection,
    state: ControlState,
}

#[derive(Default)]
struct Counters {
    echo_accepted: u64,
    echo_finished: u64,
    echo_bytes: u64,
    echo_reset: u64,
    control_accepted: u64,
    largest_echo: u64,
}

fn tcp(link: NicLink) -> Result<(), String> {
    let mut stack =
        Stack::open(link, Config::qemu_user()).map_err(|error| format!("open {error:?}"))?;
    let echo_listener = stack.listen(ECHO_PORT, 2).map_err(|error| format!("listen {error:?}"))?;
    let control_listener =
        stack.listen(CONTROL_PORT, 1).map_err(|error| format!("listen {error:?}"))?;
    let listening_sockets = stack.socket_count();
    say(format_args!(
        "NETD TCP READY mac={} ip=10.0.2.15/24 gateway=10.0.2.2 echo={ECHO_PORT} control={CONTROL_PORT} sockets={listening_sockets}",
        mac_text(stack.mac())
    ));
    let mut echoes: Vec<Echo> = Vec::new();
    let mut controls: Vec<Control> = Vec::new();
    let mut counters = Counters::default();
    let mut quitting = false;
    let mut last_heard = absd_runtime::boot_millis();
    let mut buffer = vec![0u8; 8192];
    loop {
        if stack.poll() {
            last_heard = absd_runtime::boot_millis();
        }
        while let Some(connection) = stack.accept(echo_listener) {
            counters.echo_accepted += 1;
            echoes.push(Echo { connection, bytes: 0 });
        }
        while let Some(connection) = stack.accept(control_listener) {
            counters.control_accepted += 1;
            controls.push(Control { connection, state: ControlState::Command(Vec::new()) });
        }
        echoes.retain_mut(|echo| match serve_echo(&mut stack, echo, &mut buffer) {
            Ok(true) => true,
            Ok(false) => {
                counters.echo_finished += 1;
                counters.echo_bytes += echo.bytes;
                counters.largest_echo = counters.largest_echo.max(echo.bytes);
                false
            }
            Err(_) => {
                counters.echo_reset += 1;
                let _ = stack.close(echo.connection);
                false
            }
        });
        let live_bytes: u64 = echoes.iter().map(|echo| echo.bytes).sum();
        let mut index = 0;
        while index < controls.len() {
            let keep = serve_control(
                &mut stack,
                &mut controls[index],
                &counters,
                (echoes.len(), live_bytes),
                &mut quitting,
            );
            if keep {
                index += 1;
            } else {
                controls.swap_remove(index);
            }
        }
        if quitting && controls.is_empty() && echoes.is_empty() {
            // Let the last FINs and ACKs out, then require that every
            // connection's socket was released.
            let until = absd_runtime::boot_millis() + 3_000;
            while absd_runtime::boot_millis() < until && stack.socket_count() != listening_sockets {
                stack.poll();
                stack.wait(10);
            }
            let stats = stack.stats();
            say(format_args!(
                "NETD TCP DONE echo_accepted={} echo_finished={} echo_reset={} echo_bytes={} largest_echo={} control={} released={} resets={} sockets={} listening={} heap_pages={} link_errors={}",
                counters.echo_accepted,
                counters.echo_finished,
                counters.echo_reset,
                counters.echo_bytes,
                counters.largest_echo,
                counters.control_accepted,
                stats.released,
                stats.reset,
                stack.socket_count(),
                listening_sockets,
                absd_runtime::heap_mapped_pages(),
                stats.link_errors,
            ));
            return if stack.socket_count() == listening_sockets && stats.link_errors == 0 {
                Ok(())
            } else {
                Err("sockets or link errors left at quit".into())
            };
        }
        if absd_runtime::boot_millis().saturating_sub(last_heard) > IDLE_MS {
            return Err("harness went silent".into());
        }
        stack.wait(10);
    }
}

/// Moves what arrived back out, never more than the send buffer has room
/// for. `Ok(false)` once the peer finished and the connection was closed.
fn serve_echo(stack: &mut Stack<NicLink>, echo: &mut Echo, buffer: &mut [u8]) -> Result<bool, NetError> {
    loop {
        let room = stack.send_room(echo.connection)?.min(buffer.len());
        if room == 0 {
            return Ok(true);
        }
        match stack.recv(echo.connection, &mut buffer[..room]) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                let queued = stack.send(echo.connection, &buffer[..count])?;
                if queued != count {
                    return Err(NetError::Closed);
                }
                echo.bytes += count as u64;
            }
            Err(NetError::Finished) => {
                // FIN goes out after everything queued.
                stack.close(echo.connection)?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
    }
}

fn serve_control(
    stack: &mut Stack<NicLink>,
    control: &mut Control,
    counters: &Counters,
    (active, live_bytes): (usize, u64),
    quitting: &mut bool,
) -> bool {
    let connection = control.connection;
    match &mut control.state {
        ControlState::Command(line) => {
            let mut byte = [0u8; 64];
            match stack.recv(connection, &mut byte) {
                Ok(count) => line.extend_from_slice(&byte[..count]),
                Err(_) => {
                    let _ = stack.close(connection);
                    return false;
                }
            }
            let Some(end) = line.iter().position(|&byte| byte == b'\n') else {
                if line.len() > 256 {
                    let _ = stack.abort(connection);
                    return false;
                }
                return true;
            };
            let command = String::from_utf8_lossy(&line[..end]).trim().to_string();
            let words: Vec<&str> = command.split_whitespace().collect();
            match words.as_slice() {
                ["STATS"] => {
                    let stats = stack.stats();
                    let reply = format!(
                        "STATS echo_accepted={} echo_finished={} echo_reset={} echo_bytes={} active={} live_bytes={live_bytes} sockets={} released={} resets={} heap_pages={} rx_frames={} tx_frames={} link_errors={}\n",
                        counters.echo_accepted,
                        counters.echo_finished,
                        counters.echo_reset,
                        counters.echo_bytes,
                        active,
                        stack.socket_count(),
                        stats.released,
                        stats.reset,
                        absd_runtime::heap_mapped_pages(),
                        stats.rx_frames,
                        stats.tx_frames,
                        stats.link_errors,
                    );
                    let _ = stack.send(connection, reply.as_bytes());
                    let _ = stack.close(connection);
                    false
                }
                ["SOURCE", count] => match count.parse::<u64>() {
                    Ok(total) => {
                        control.state = ControlState::Source { sent: 0, total };
                        true
                    }
                    Err(_) => {
                        let _ = stack.abort(connection);
                        false
                    }
                },
                ["SPAWN"] => {
                    // A brokered child while this process holds the NIC:
                    // the SSH server's shape. It runs to completion here.
                    let reply = match std::process::Command::new("broker-echo").args(["0", "net"]).output() {
                        Ok(output) => format!(
                            "SPAWNED status={} stderr={}\n",
                            output.status.code().unwrap_or(-1),
                            String::from_utf8_lossy(&output.stderr).trim()
                        ),
                        Err(error) => format!("SPAWN FAILED {:?}\n", error.kind()),
                    };
                    let _ = stack.send(connection, reply.as_bytes());
                    let _ = stack.close(connection);
                    false
                }
                ["QUIT"] => {
                    let _ = stack.send(connection, b"BYE\n");
                    let _ = stack.close(connection);
                    *quitting = true;
                    false
                }
                _ => {
                    let _ = stack.abort(connection);
                    false
                }
            }
        }
        ControlState::Source { sent, total } => {
            let mut chunk = [0u8; 4096];
            loop {
                let room = match stack.send_room(connection) {
                    Ok(room) => room,
                    Err(_) => return false,
                };
                let count = room.min(chunk.len()).min((*total - *sent) as usize);
                if count == 0 {
                    break;
                }
                for (offset, byte) in chunk[..count].iter_mut().enumerate() {
                    *byte = pattern(*sent + offset as u64);
                }
                match stack.send(connection, &chunk[..count]) {
                    Ok(queued) => *sent += queued as u64,
                    Err(_) => {
                        let _ = stack.close(connection);
                        return false;
                    }
                }
            }
            if *sent == *total {
                let _ = stack.close(connection);
                return false;
            }
            true
        }
    }
}
