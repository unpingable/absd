//! Private native fixture prelude. No Interface poll, new protocol or net API.
use super::*;
use absd_net::datagram::channel::Pipe;
use absd_net::stream::{self as s, server as v};

fn grant(port: u16) -> v::Grant {
    v::Grant {
        local_port: port,
        peer: d::Address {
            ip: [192, 0, 2, 1],
            port: 42030,
        },
        accept_timeout_ms: 5000,
        lifetime_ms: 10000,
    }
}

fn zero_effect(stack: &Stack<NicLink>, sockets: usize) -> Result<(), String> {
    if stack.socket_count() != sockets || stack.stats().tx_frames != 0 {
        return Err("negative socket/TX effect".into());
    }
    Ok(())
}

fn grant_cases(stack: &mut Stack<NicLink>) -> Result<(), String> {
    let mut invalid = [grant(7005); 9];
    invalid[0].local_port = 1023;
    invalid[1].peer.port = 0;
    invalid[2].peer.ip = [192, 0, 3, 1];
    invalid[3].peer.ip = [192, 0, 2, 100];
    invalid[4].peer.ip = [192, 0, 2, 255];
    invalid[5].accept_timeout_ms = 99;
    invalid[6].accept_timeout_ms = 10001;
    invalid[7].lifetime_ms = 4999;
    invalid[8].lifetime_ms = 60001;
    let ids = [
        "local-port",
        "peer-port",
        "offlink",
        "self",
        "broadcast",
        "accept-low",
        "accept-high",
        "lifetime-short",
        "lifetime-high",
    ];
    for (id, bad) in ids.into_iter().zip(invalid) {
        if stack.stream_server_grant(bad) != Err(s::Error::Invalid) {
            return Err(format!("negative grant {id}"));
        }
        zero_effect(stack, 0)?;
        println!("TCP SERVER NEG GRANT v=1 case={id} code=1 sockets=0 tx=0");
    }
    let mut old = [None; s::MAX_ENDPOINTS];
    for (slot, endpoint) in old.iter_mut().enumerate() {
        *endpoint = Some(
            stack
                .stream_server_grant(grant(7005 + slot as u16))
                .map_err(|e| format!("slot {e:?}"))?,
        );
    }
    if stack.stream_server_grant(grant(7005)) != Err(s::Error::InUse)
        || stack.stream_server_grant(grant(7013)) != Err(s::Error::Exhausted)
    {
        return Err("negative duplicate/exhausted".into());
    }
    zero_effect(stack, 0)?;
    println!("TCP SERVER NEG SLOTS v=1 reserved=8 duplicate=3 ninth=4 sockets=0 tx=0");
    for endpoint in old.into_iter().flatten() {
        stack
            .stream_abort(endpoint)
            .map_err(|e| format!("slot abort {e:?}"))?;
    }
    let mut fresh = [None; s::MAX_ENDPOINTS];
    for (slot, endpoint) in fresh.iter_mut().enumerate() {
        *endpoint = Some(
            stack
                .stream_server_grant(grant(7005 + slot as u16))
                .map_err(|e| format!("fresh slot {e:?}"))?,
        );
        if *endpoint == old[slot]
            || stack.stream_listen(old[slot].ok_or("old slot absent")?) != Err(s::Error::Stale)
        {
            return Err("old reservation revived".into());
        }
    }
    for endpoint in fresh.into_iter().flatten() {
        stack
            .stream_abort(endpoint)
            .map_err(|e| format!("fresh abort {e:?}"))?;
    }
    zero_effect(stack, 0)?;
    println!("TCP SERVER NEG SLOTS RETIRED v=1 stale=8 fresh=8 sockets=0 tx=0");
    Ok(())
}

struct ObservedPipe {
    inner: KernelPipe,
    input: Vec<u8>,
    output: Vec<u8>,
    eof_ms: Option<u64>,
}
impl Pipe for ObservedPipe {
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.input.len() + bytes.len() > 512 {
            return Err(-22);
        }
        let result = self.inner.read(bytes)?;
        if let Some(n) = result {
            if n > bytes.len() {
                return Err(-22);
            }
            if n == 0 {
                self.eof_ms = Some(absd_runtime::boot_millis());
            }
            self.input.extend_from_slice(&bytes[..n]);
        }
        Ok(result)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        if self.output.len() + bytes.len() > 512 {
            return Err(-22);
        }
        let result = self.inner.write(bytes)?;
        if let Some(n) = result {
            if n > bytes.len() {
                return Err(-22);
            }
            self.output.extend_from_slice(&bytes[..n]);
        }
        Ok(result)
    }
    fn now_ms(&self) -> u64 {
        absd_runtime::boot_millis()
    }
}

fn clock(last: &mut u64, until: u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    if now < *last || now >= until {
        return Err("negative clock/deadline".into());
    }
    *last = now;
    Ok(now)
}
fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn negative_child(stack: &mut Stack<NicLink>, whole_end: u64) -> Result<(), String> {
    let constructed = absd_runtime::boot_millis();
    let until = constructed
        .checked_add(10000)
        .ok_or("negative grant overflow")?;
    if until > whole_end {
        return Err("negative grant exceeds whole fixture".into());
    }
    let mut channel =
        Channel::grant(stack, grant(7005)).map_err(|e| format!("negative grant {e:?}"))?;
    let (mut child, pipe, result_in) = spawn_child(true)?;
    let child_handle = child.0.0;
    let mut pipe = ObservedPipe {
        inner: pipe,
        input: Vec::new(),
        output: Vec::new(),
        eof_ms: None,
    };
    let mut checked = 0;
    let mut last = constructed;
    let (partial_poll, observed) = loop {
        let before = clock(&mut last, until)?;
        let was = pipe.input.len();
        let live = channel.poll(stack, &mut pipe);
        let after = clock(&mut last, until)?;
        zero_effect(stack, if pipe.input.len() >= 112 { 1 } else { 0 })?;
        while checked < 7 && pipe.output.len() >= (checked + 1) * 14 {
            zero_effect(stack, 0)?;
            checked += 1;
        }
        if !live || pipe.eof_ms.is_some() {
            return Err("negative child retired before interruption".into());
        }
        if pipe.input.len() > 112 {
            if was != 112
                || pipe.input.len() != 113
                || pipe.input[112] != 0
                || pipe.output.len() != 113
                || checked != 7
            {
                return Err("not exactly one observed prefix byte after LISTEN reply".into());
            }
            break (before, after);
        }
        absd_runtime::sleep_ticks(1);
    };
    let frame_end = partial_poll
        .checked_add(d::channel::FRAME_TIMEOUT_MS)
        .ok_or("negative frame overflow")?
        .min(until);
    let kill_ms = clock(&mut last, frame_end)?;
    let killed = sys(20, child_handle, 0, 0);
    if killed != 0 {
        return Err(format!("negative kill {killed}"));
    }
    clock(&mut last, frame_end)?;
    let outcome = loop {
        clock(&mut last, frame_end)?;
        let result = child.wait(1)?;
        clock(&mut last, frame_end)?;
        if let Some(record) = result {
            break record;
        }
    };
    let reaped = clock(&mut last, frame_end)?;
    if outcome[0] != 3 {
        return Err(format!("negative child was not killed {outcome:?}"));
    }
    let retired = loop {
        clock(&mut last, frame_end)?;
        let live = channel.poll(stack, &mut pipe);
        let after = clock(&mut last, frame_end)?;
        if !live {
            if pipe.eof_ms.is_none() || channel.live() || stack.socket_count() != 0 {
                return Err("negative retirement not true EOF with zero sockets".into());
            }
            break after;
        }
    };
    zero_effect(stack, 0)?;
    // No explicit revoke/fence occurred: these are the real kernel pipe bytes.
    let input = &pipe.input[..112];
    let ids = [
        "version",
        "family",
        "reserved",
        "listen-length",
        "connect",
        "write-declared-without-body",
        "peer",
    ];
    for (index, id) in ids.into_iter().enumerate() {
        let request = &input[index * 14..(index + 1) * 14];
        let reply = &pipe.output[index * 14..(index + 1) * 14];
        let code = if index == 6 { 2 } else { 1 };
        if request[..2] != [0, 12] || reply[..2] != [0, 12] || reply[4] != code {
            return Err("negative actual transaction framing/status".into());
        }
        println!(
            "TCP SERVER NEG API v=1 case={id} request={} reply={} sockets=0 tx=0",
            hex(request),
            hex(reply)
        );
    }
    println!(
        "TCP SERVER NEG LISTEN v=1 request={} reply={} sockets=1 tx=0",
        hex(&input[98..112]),
        hex(&pipe.output[98..113])
    );
    println!(
        "TCP SERVER NEG INTERRUPT v=1 child_handle={child_handle} constructed_ms={constructed} grant_until_ms={until} partial_poll_ms={partial_poll} observed_ms={observed} prefix=00 prefix_bytes=1 kill_ms={kill_ms} kill_return={killed} reaped_ms={reaped} wait_kind={} wait_status={} eof_ms={} retired_ms={retired} channel_live=0 sockets=0 tx=0 fallback_fence=0",
        outcome[0],
        outcome[1],
        pipe.eof_ms.ok_or("EOF absent")?
    );
    let mut result = Vec::new();
    loop {
        clock(&mut last, until)?;
        let mut bytes = [0; 256];
        match absd_runtime::read_within(result_in.0, &mut bytes, 1) {
            Ok(0) => break,
            Ok(n) if result.len() + n <= 2048 => result.extend_from_slice(&bytes[..n]),
            _ => return Err("negative result true EOF/bound".into()),
        }
    }
    if result != b"TCP SERVER NEG CHILD v=1 cases=7 listen=1 nic=0\n" {
        return Err("negative child result".into());
    }
    print!("{}", String::from_utf8_lossy(&result));
    let reader = pipe.inner.request_reader;
    let writer = pipe.inner.reply_writer;
    absd_runtime::close(reader).map_err(|e| format!("negative reader close {e}"))?;
    absd_runtime::close(writer).map_err(|e| format!("negative writer close {e}"))?;
    core::mem::forget(pipe.inner); // Both checked closes above; no double close.
    absd_runtime::close(result_in.0).map_err(|e| format!("negative result close {e}"))?;
    core::mem::forget(result_in);
    println!(
        "TCP SERVER NEG CLOSED v=1 process_reaped=1 protocol_handles=2 result_handles=1 result_eof=1"
    );
    Ok(())
}

fn census(label: &str) -> Result<absd_runtime::ResourceCensus, String> {
    let r = absd_runtime::resource_census().map_err(|e| format!("negative census {e}"))?;
    println!(
        "TCP SERVER NEG CENSUS v=1 label={label} processes={} handles={} pipes={} cells={} frames={}",
        r.processes, r.handles, r.pipes, r.cells, r.frames
    );
    Ok(r)
}
pub(super) fn run(stack: &mut Stack<NicLink>, whole_end: u64) -> Result<(), String> {
    grant_cases(stack)?;
    let before = census("before")?;
    negative_child(stack, whole_end)?;
    let after = census("after")?;
    if (before.processes, before.handles, before.pipes, before.cells)
        != (after.processes, after.handles, after.pipes, after.cells)
    {
        return Err("negative object census not restored".into());
    }
    zero_effect(stack, 0)?;
    println!(
        "TCP SERVER NEG COMPLETE v=1 grants=9 api=7 slots=8 interrupted=1 objects_restored=1 sockets=0 tx=0"
    );
    Ok(())
}
