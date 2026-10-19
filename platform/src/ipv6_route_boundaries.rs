//! Native service/engine boundary controls. These never poll the NIC and
//! discard every temporary socket before the independent Linux DNS proof.
//! Pipe closure and partial-frame expiry use real native kernel pipes;
//! they make no claim about stopping or reaping a consumer process.
use absd_net::{
    Link, Stack,
    ipv6::{self as v6, session::*},
};

fn request(op: u8, peer: v6::Address) -> [u8; HEADER] {
    let mut bytes = [0; HEADER];
    bytes[0] = VERSION;
    bytes[1] = op;
    bytes[3] = FAMILY;
    if op == SEND {
        bytes[4..20].copy_from_slice(&peer.ip);
        bytes[20..24].copy_from_slice(&peer.scope.to_be_bytes());
        bytes[24..26].copy_from_slice(&peer.port.to_be_bytes());
    }
    bytes
}

fn response<L: Link>(
    session: &mut Session,
    stack: &mut Stack<L>,
    request: &[u8],
    expected: u8,
) -> Result<(), String> {
    let mut reply = [0; MAX_MESSAGE];
    let size = session.request(stack, request, &mut reply);
    if size != HEADER
        || reply[0] != VERSION
        || reply[1] != request.get(1).copied().unwrap_or(0)
        || reply[2] != expected
        || reply[3] != FAMILY
        || reply[4..HEADER] != [0; HEADER - 4]
    {
        return Err(format!(
            "boundary reply size={size} status={} expected={expected}",
            reply[2]
        ));
    }
    Ok(())
}

pub fn run<L: Link>(stack: &mut Stack<L>) -> Result<(), String> {
    let config = stack.ipv6_config().ok_or("boundary missing IPv6 config")?;
    if stack.socket_count() != 0 {
        return Err("boundary requires no preexisting sockets".into());
    }
    let ip = super::fixture::PEER;
    let peer = v6::Address {
        ip,
        port: 42010,
        scope: config.scope,
    };
    let grant = v6::Grant {
        local_port: 7100,
        peer,
    };
    let tx_before = stack.stats().tx_frames;
    let mut session = Session::grant(stack, grant).map_err(|e| format!("boundary grant {e:?}"))?;
    let mut owned = Vec::new();
    let result = (|| {
        let send = request(SEND, peer);
        for (at, value) in [(0, 1), (1, 255), (2, 1), (3, 4), (27, 1)] {
            let mut malformed = send;
            malformed[at] = value;
            response(&mut session, stack, &malformed, v6::Error::Invalid.code())?;
        }
        response(
            &mut session,
            stack,
            &send[..HEADER - 1],
            v6::Error::Invalid.code(),
        )?;
        let mut trailing = send.to_vec();
        trailing.push(0);
        response(&mut session, stack, &trailing, v6::Error::Invalid.code())?;
        for op in [RECEIVE, CLOSE] {
            let mut malformed = request(op, peer);
            malformed[4] = 1;
            response(&mut session, stack, &malformed, v6::Error::Invalid.code())?;
        }
        for at in [19, 23, 25] {
            let mut denied = send;
            denied[at] ^= 1;
            response(&mut session, stack, &denied, v6::Error::Denied.code())?;
        }
        let mut oversize = vec![0; HEADER + v6::MAX_DATAGRAM + 1];
        oversize[..HEADER].copy_from_slice(&send);
        oversize[26..28].copy_from_slice(&((v6::MAX_DATAGRAM + 1) as u16).to_be_bytes());
        response(&mut session, stack, &oversize, v6::Error::Oversize.code())?;
        for _ in 0..v6::QUEUE_PACKETS {
            response(&mut session, stack, &send, 0)?;
        }
        response(&mut session, stack, &send, v6::Error::Exhausted.code())?;
        for index in 1..v6::MAX_ENDPOINTS {
            owned.push(
                stack
                    .ipv6_bind(v6::Grant {
                        local_port: grant.local_port + index as u16,
                        ..grant
                    })
                    .map_err(|e| format!("boundary slot {index} {e:?}"))?,
            );
        }
        match stack.ipv6_bind(v6::Grant {
            local_port: 7108,
            ..grant
        }) {
            Err(v6::Error::Exhausted) => {}
            Ok(endpoint) => {
                owned.push(endpoint);
                return Err("ninth endpoint accepted".into());
            }
            Err(error) => return Err(format!("ninth endpoint {error:?}")),
        }
        let stale = owned[0];
        stack
            .ipv6_close(stale)
            .map_err(|e| format!("boundary close {e:?}"))?;
        let replacement = stack
            .ipv6_bind(v6::Grant {
                local_port: 7101,
                ..grant
            })
            .map_err(|e| format!("boundary rebind {e:?}"))?;
        owned.push(replacement);
        if replacement == stale || stack.ipv6_send(stale, peer, b"") != Err(v6::Error::Stale) {
            return Err("old endpoint revived after port reuse".into());
        }
        session.revoke(stack);
        let replacement = stack
            .ipv6_bind(grant)
            .map_err(|e| format!("boundary session rebind {e:?}"))?;
        owned.push(replacement);
        response(&mut session, stack, &send, v6::Error::Stale.code())?;
        Ok(())
    })();
    // Cleanup executes for both successful and failed predicates. No poll
    // or wait can emit any of the deliberately queued boundary datagrams.
    session.revoke(stack);
    let mut cleanup = None;
    for endpoint in owned {
        if let Err(error) = stack.ipv6_close(endpoint) {
            if error != v6::Error::Stale {
                cleanup = Some(format!("boundary cleanup {error:?}"));
            }
        }
    }
    if stack.socket_count() != 0 || stack.stats().tx_frames != tx_before {
        cleanup = Some("boundary socket residue or unexpected frame submission".into());
    }
    match (result, cleanup) {
        (Err(error), Some(cleanup)) => return Err(format!("{error}; {cleanup}")),
        (Err(error), None) | (Ok(()), Some(error)) => return Err(error),
        (Ok(()), None) => {}
    }
    println!(
        "ROUTE6 API BOUNDARIES PASS malformed=9 denied=3 oversize=1 queue=4 endpoints=8 stale=2 sockets=0 queued-test-wire=0"
    );
    Ok(())
}

pub fn run_pipes<L: Link>(
    stack: &mut Stack<L>,
    guard: &super::guarded::Guard,
) -> Result<(), String> {
    use super::guarded::BoundPipe;
    use v6::channel::{Channel, FRAME_TIMEOUT_MS, KernelPipe};
    let config = stack
        .ipv6_config()
        .ok_or("pipe boundary missing IPv6 config")?;
    if stack.socket_count() != 0 {
        return Err("pipe boundary requires no preexisting sockets".into());
    }
    let ip = super::fixture::PEER;
    let tx_before = stack.stats().tx_frames;
    for expiry in [false, true] {
        guard.check()?;
        let grant = v6::Grant {
            local_port: if expiry { 7121 } else { 7120 },
            peer: v6::Address {
                ip,
                port: 42010,
                scope: config.scope,
            },
        };
        let (request_reader, request_writer) = super::pipe(guard)?;
        let (reply_reader, reply_writer) = super::pipe(guard)?;
        let mut writer = Some(request_writer);
        let mut io = BoundPipe {
            inner: KernelPipe {
                request_reader: request_reader.take(),
                reply_writer: reply_writer.take(),
            },
            guard: guard.clone(),
        };
        let mut channel = Channel::grant(stack, grant).map_err(|e| format!("pipe grant {e:?}"))?;
        let mut fresh = None;
        let result = (|| {
            let n = guard
                .io(|left| {
                    absd_runtime::write_within(writer.as_ref().unwrap().0, &[0], 1000.min(left))
                })
                .map_err(|e| format!("partial prefix write {e}"))?;
            if n != 1 || !channel.poll(stack, &mut io) || !channel.live() {
                return Err("partial prefix did not leave channel live".into());
            }
            if expiry {
                // Do not attempt the frame-expiry fixture if the original
                // invocation cannot cover its deliberate wait. Two extra PIT
                // ticks cover the boot-millisecond floor conversion. No new budget.
                if guard.check()? <= FRAME_TIMEOUT_MS + 2 {
                    return Err("insufficient original budget for partial expiry".into());
                }
                let start = absd_runtime::boot_millis();
                guard
                    .io(|left| {
                        absd_runtime::sleep_ticks((FRAME_TIMEOUT_MS + 2).min(left));
                        Ok(())
                    })
                    .map_err(|e| format!("partial expiry wait {e}"))?;
                if absd_runtime::boot_millis().saturating_sub(start) <= FRAME_TIMEOUT_MS {
                    return Err("partial expiry wait did not reach its bound".into());
                }
            } else {
                guard.check()?;
                drop(writer.take());
                guard.check()?;
                if guard.io(|left| {
                    absd_runtime::read_within(io.inner.request_reader, &mut [0], 1.min(left))
                }) != Ok(0)
                {
                    return Err("closed request pipe did not report EOF".into());
                }
            }
            if channel.poll(stack, &mut io) || channel.live() {
                return Err("interrupted/expired partial channel remained live".into());
            }
            guard.check()?;
            fresh = Some(
                stack
                    .ipv6_bind(grant)
                    .map_err(|e| format!("pipe port reuse {e:?}"))?,
            );
            Ok(())
        })();
        channel.revoke(stack);
        let cleanup = fresh.map(|endpoint| stack.ipv6_close(endpoint)).transpose();
        drop((io, reply_reader, writer));
        if stack.socket_count() != 0 || stack.stats().tx_frames != tx_before {
            return Err(format!(
                "pipe boundary residue or frame submission; result={result:?}"
            ));
        }
        match (result, cleanup) {
            (Err(error), Err(cleanup)) => return Err(format!("{error}; pipe cleanup {cleanup:?}")),
            (Err(error), _) => return Err(error),
            (_, Err(cleanup)) => return Err(format!("pipe cleanup {cleanup:?}")),
            (Ok(()), Ok(_)) => {}
        }
    }
    println!("ROUTE6 PIPE BOUNDARIES PASS eof=1 partial-expiry=1 port-reuse=2 sockets=0");
    Ok(())
}
