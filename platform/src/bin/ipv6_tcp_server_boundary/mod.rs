//! Private fixture prelude; no Interface poll or transport/library change.
use super::*;
use absd_net::ipv6::stream::{self as s, server as v};
fn grant(port: u16) -> v::Grant {
    v::Grant {
        local_port: port,
        peer: v6::Address {
            ip: ip(2),
            port: 42030,
            scope: 1,
        },
        accept_timeout_ms: 5000,
        lifetime_ms: 10000,
    }
}
fn zero_effect(stack: &Stack<NicLink>, sockets: usize) -> Result<(), String> {
    if stack.socket_count() != sockets || stack.stats().tx_frames != 0 {
        return Err("negative socket/application TX effect".into());
    }
    Ok(())
}
fn clock(last: &mut u64, until: u64) -> Result<u64, String> {
    let now = absd_runtime::boot_millis();
    completion_clock::observe(last, until, now).map_err(String::from)?;
    Ok(now)
}
fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(text, "{b:02x}");
    }
    text
}
fn grants(stack: &mut Stack<NicLink>, last: &mut u64, end: u64) -> Result<(), String> {
    let mut cases = [grant(7005); 12];
    cases[0].local_port = 1023;
    cases[1].peer.port = 0;
    cases[2].peer.ip[7] = 1;
    cases[3].peer.ip = ip(1);
    cases[4].peer.ip = [0; 16];
    cases[5].peer.ip[0] = 255;
    cases[6].peer.scope = 0;
    cases[7].peer.scope = 2;
    cases[8].accept_timeout_ms = 99;
    cases[9].accept_timeout_ms = 10001;
    cases[10].lifetime_ms = 4999;
    cases[11].lifetime_ms = 60001;
    let names = [
        "local-port",
        "peer-port",
        "offlink",
        "self",
        "unspecified",
        "multicast",
        "scope-zero",
        "scope-other",
        "accept-low",
        "accept-high",
        "lifetime-short",
        "lifetime-high",
    ];
    for (index, (name, g)) in names.into_iter().zip(cases).enumerate() {
        clock(last, end)?;
        let expected = if index < 8 {
            s::Error::Denied
        } else {
            s::Error::Invalid
        };
        let result = stack.ipv6_stream_server_grant(g);
        clock(last, end)?;
        if result != Err(expected) {
            return Err(format!("negative grant {name} {result:?}"));
        }
        zero_effect(stack, 0)?;
        println!(
            "IPV6 TCP SERVER NEG GRANT v=1 case={name} code={} sockets={} tx={}",
            expected.code(),
            stack.socket_count(),
            stack.stats().tx_frames
        );
    }
    let mut old = [None; s::MAX_ENDPOINTS];
    for (slot, e) in old.iter_mut().enumerate() {
        *e = Some(
            stack
                .ipv6_stream_server_grant(grant(7005 + slot as u16))
                .map_err(|e| format!("reserve {e:?}"))?,
        );
        clock(last, end)?;
    }
    if stack.ipv6_stream_server_grant(grant(7005)) != Err(s::Error::InUse)
        || stack.ipv6_stream_server_grant(grant(7013)) != Err(s::Error::Exhausted)
    {
        return Err("duplicate/ninth reservation".into());
    }
    clock(last, end)?;
    zero_effect(stack, 0)?;
    println!(
        "IPV6 TCP SERVER NEG SLOTS v=1 reserved=8 duplicate=3 ninth=4 sockets={} tx={}",
        stack.socket_count(),
        stack.stats().tx_frames
    );
    for e in old.into_iter().flatten() {
        stack
            .ipv6_stream_abort(e)
            .map_err(|e| format!("abort old {e:?}"))?;
        clock(last, end)?;
    }
    let mut fresh = [None; s::MAX_ENDPOINTS];
    for (slot, e) in fresh.iter_mut().enumerate() {
        *e = Some(
            stack
                .ipv6_stream_server_grant(grant(7005 + slot as u16))
                .map_err(|e| format!("fresh {e:?}"))?,
        );
        if *e == old[slot]
            || stack.ipv6_stream_listen(old[slot].ok_or("old absent")?) != Err(s::Error::Stale)
        {
            return Err("stale reservation revived".into());
        }
        clock(last, end)?;
    }
    for e in fresh.into_iter().flatten() {
        stack
            .ipv6_stream_abort(e)
            .map_err(|e| format!("abort fresh {e:?}"))?;
        clock(last, end)?;
    }
    zero_effect(stack, 0)?;
    println!(
        "IPV6 TCP SERVER NEG SLOTS RETIRED v=1 stale=8 fresh=8 sockets={} tx={}",
        stack.socket_count(),
        stack.stats().tx_frames
    );
    Ok(())
}
struct Ledger {
    inner: KernelPipe,
    input: Vec<u8>,
    output: Vec<u8>,
    eof: Option<u64>,
}
impl Pipe for Ledger {
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.input.len() + bytes.len() > 512 {
            return Err(-22);
        }
        let r = self.inner.read(bytes)?;
        if let Some(n) = r {
            if n > bytes.len() {
                return Err(-22);
            }
            if n == 0 {
                self.eof = Some(absd_runtime::boot_millis());
            }
            self.input.extend_from_slice(&bytes[..n]);
        }
        Ok(r)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        if self.output.len() + bytes.len() > 512 {
            return Err(-22);
        }
        let r = self.inner.write(bytes)?;
        if let Some(n) = r {
            if n > bytes.len() {
                return Err(-22);
            }
            self.output.extend_from_slice(&bytes[..n]);
        }
        Ok(r)
    }
}
fn child(stack: &mut Stack<NicLink>, whole_end: u64) -> Result<(), String> {
    let constructed = absd_runtime::boot_millis();
    let until = constructed
        .checked_add(10000)
        .ok_or("negative grant overflow")?;
    if until > whole_end {
        return Err("negative grant exceeds whole bound".into());
    }
    let mut channel =
        v::Channel::grant(stack, grant(7005)).map_err(|e| format!("negative grant {e:?}"))?;
    let (mut child, inner, result_in) = spawn_child(true)?;
    let child_handle = child.0.0;
    let mut pipe = Ledger {
        inner,
        input: vec![],
        output: vec![],
        eof: None,
    };
    let cases = boundary_wire::cases();
    if cases.len() != 9 {
        return Err("literal case count".into());
    }
    let mut checked = 0;
    let mut observations = Vec::new();
    let mut last = constructed;
    let (partial_poll, observed, listen_sockets, listen_tx) = loop {
        let before = clock(&mut last, until)?;
        let previous = pipe.input.len();
        let live = channel.poll(stack, &mut pipe);
        let after = clock(&mut last, until)?;
        zero_effect(stack, if pipe.input.len() >= 300 { 1 } else { 0 })?;
        while checked < cases.len() && pipe.output.len() >= (checked + 1) * 30 {
            zero_effect(stack, 0)?;
            let offset = checked * 30;
            if pipe.input.len() < offset + 30
                || pipe.input[offset..offset + 30] != cases[checked].1
                || pipe.output[offset..offset + 30] != cases[checked].2
            {
                return Err("actual typed request/reply differs".into());
            }
            observations.push((stack.socket_count(), stack.stats().tx_frames));
            checked += 1;
        }
        if !live || pipe.eof.is_some() {
            return Err("negative retired before observed interruption".into());
        }
        if pipe.input.len() > 300 {
            if previous != 300
                || pipe.input.len() != 301
                || pipe.input[300..] != [0]
                || pipe.output.len() != 301
                || checked != 9
            {
                return Err("not one actual prefix after complete LISTEN reply".into());
            }
            break (before, after, stack.socket_count(), stack.stats().tx_frames);
        }
        absd_runtime::sleep_ticks(1);
    };
    let frame_end = partial_poll
        .checked_add(v6::channel::FRAME_TIMEOUT_MS)
        .ok_or("frame bound overflow")?
        .min(until);
    let kill_ms = clock(&mut last, frame_end)?;
    let killed = sys(20, child_handle, 0, 0);
    clock(&mut last, frame_end)?;
    if killed != 0 {
        return Err(format!("exact negative kill {killed}"));
    }
    let outcome = loop {
        clock(&mut last, frame_end)?;
        let result = child.wait(1)?;
        clock(&mut last, frame_end)?;
        if let Some(r) = result {
            break r;
        }
    };
    let reaped = clock(&mut last, frame_end)?;
    if outcome[0] != 3 {
        return Err(format!("negative not killed {outcome:?}"));
    }
    let retired = loop {
        clock(&mut last, frame_end)?;
        let live = channel.poll(stack, &mut pipe);
        let after = clock(&mut last, frame_end)?;
        if !live {
            if pipe.eof.is_none() || channel.live() || stack.socket_count() != 0 {
                return Err("retirement not EOF/false/zero socket".into());
            }
            break after;
        }
    };
    zero_effect(stack, 0)?;
    for (index, (name, _, _)) in cases.iter().enumerate() {
        let at = index * 30;
        println!(
            "IPV6 TCP SERVER NEG API v=1 case={name} request={} reply={} sockets={} tx={}",
            hex(&pipe.input[at..at + 30]),
            hex(&pipe.output[at..at + 30]),
            observations[index].0,
            observations[index].1
        );
    }
    println!(
        "IPV6 TCP SERVER NEG LISTEN v=1 request={} reply={} sockets={listen_sockets} tx={listen_tx}",
        hex(&pipe.input[270..300]),
        hex(&pipe.output[270..301])
    );
    println!(
        "IPV6 TCP SERVER NEG INTERRUPT v=1 child_handle={child_handle} constructed_ms={constructed} grant_until_ms={until} partial_poll_ms={partial_poll} observed_ms={observed} prefix={} prefix_bytes={} input_bytes={} output_bytes={} kill_ms={kill_ms} kill_return={killed} reaped_ms={reaped} wait_kind={} wait_status={} eof_ms={} retired_ms={retired} channel_live=0 sockets={} tx={} fallback_fence=0",
        hex(&pipe.input[300..]),
        pipe.input.len() - 300,
        pipe.input.len(),
        pipe.output.len(),
        outcome[0],
        outcome[1],
        pipe.eof.ok_or("EOF absent")?,
        stack.socket_count(),
        stack.stats().tx_frames
    );
    let mut result = Vec::new();
    loop {
        clock(&mut last, until)?;
        let mut bytes = [0; 256];
        let read = absd_runtime::read_within(result_in.0, &mut bytes, 1);
        clock(&mut last, until)?;
        match read {
            Ok(0) => break,
            Ok(n) if result.len() + n <= 2048 => result.extend_from_slice(&bytes[..n]),
            _ => return Err("negative result EOF/bound".into()),
        }
    }
    if result != b"IPV6 TCP SERVER NEG CHILD v=1 cases=9 listen=1 nic=0\n" {
        return Err("negative child output".into());
    }
    print!("{}", String::from_utf8_lossy(&result));
    absd_runtime::close(pipe.inner.request_reader)
        .map_err(|e| format!("negative request close {e}"))?;
    absd_runtime::close(pipe.inner.reply_writer)
        .map_err(|e| format!("negative reply close {e}"))?;
    core::mem::forget(pipe.inner);
    absd_runtime::close(result_in.0).map_err(|e| format!("negative result close {e}"))?;
    core::mem::forget(result_in);
    drop(channel);
    clock(&mut last, until)?;
    println!(
        "IPV6 TCP SERVER NEG CLOSED v=1 process_reaped=1 protocol_handles=2 result_handles=1 result_eof=1"
    );
    Ok(())
}
fn census(label: &str) -> Result<absd_runtime::ResourceCensus, String> {
    let c = absd_runtime::resource_census().map_err(|e| format!("negative census {e}"))?;
    println!(
        "IPV6 TCP SERVER NEG CENSUS v=1 label={label} processes={} handles={} pipes={} cells={} frames={}",
        c.processes, c.handles, c.pipes, c.cells, c.frames
    );
    Ok(c)
}
pub(super) fn run(stack: &mut Stack<NicLink>, whole_end: u64) -> Result<(), String> {
    let mut last = absd_runtime::boot_millis();
    let before = census("before")?;
    grants(stack, &mut last, whole_end)?;
    child(stack, whole_end)?;
    clock(&mut last, whole_end)?;
    let after = census("after")?;
    clock(&mut last, whole_end)?;
    if (before.processes, before.handles, before.pipes, before.cells)
        != (after.processes, after.handles, after.pipes, after.cells)
    {
        return Err("negative owned kernel objects not restored".into());
    }
    zero_effect(stack, 0)?;
    println!(
        "IPV6 TCP SERVER NEG COMPLETE v=1 grants=12 api=9 slots=8 interrupted=1 objects_restored=1 sockets={} tx={}",
        stack.socket_count(),
        stack.stats().tx_frames
    );
    clock(&mut last, whole_end)?;
    Ok(())
}
