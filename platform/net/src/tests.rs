//! Host tests: two stacks joined by an in-memory Ethernet wire, one
//! listening and one connecting, under a shared fake clock.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

use super::*;

struct Wire {
    queues: [VecDeque<Vec<u8>>; 2],
    now_ms: u64,
    /// Every Nth frame is dropped when nonzero (loss the stack must repair).
    drop_every: u64,
    sent: u64,
    /// Link-failure fallbacks: a healthy wire must never pause.
    pauses: u64,
}

struct End {
    wire: Rc<RefCell<Wire>>,
    side: usize,
    mac: [u8; 6],
}

impl Link for End {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        if !(14..=FRAME_MAX).contains(&frame.len()) {
            return Err(-22);
        }
        let mut wire = self.wire.borrow_mut();
        wire.sent += 1;
        if wire.drop_every != 0 && wire.sent % wire.drop_every == 0 {
            return Ok(());
        }
        wire.queues[1 - self.side].push_back(frame.to_vec());
        Ok(())
    }

    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        _timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        let mut wire = self.wire.borrow_mut();
        Ok(wire.queues[self.side].pop_front().map(|frame| {
            buffer[..frame.len()].copy_from_slice(&frame);
            frame.len()
        }))
    }

    fn now_ms(&self) -> u64 {
        self.wire.borrow().now_ms
    }

    fn pause(&self, ms: u64) {
        let mut wire = self.wire.borrow_mut();
        wire.pauses += 1;
        wire.now_ms += ms;
    }
}

fn pair(drop_every: u64) -> (Rc<RefCell<Wire>>, Stack<End>, Stack<End>) {
    let wire = Rc::new(RefCell::new(Wire {
        queues: [VecDeque::new(), VecDeque::new()],
        now_ms: 1,
        drop_every,
        sent: 0,
        pauses: 0,
    }));
    let config = |last| Config {
        address: Ipv4Address::new(10, 0, 2, last),
        prefix_len: 24,
        gateway: None,
        rx_buffer: 8 * 1024,
        tx_buffer: 8 * 1024,
    };
    let server = Stack::open(
        End {
            wire: wire.clone(),
            side: 0,
            mac: [2, 0, 0, 0, 0, 15],
        },
        config(15),
    )
    .unwrap();
    let client = Stack::open(
        End {
            wire: wire.clone(),
            side: 1,
            mac: [2, 0, 0, 0, 0, 2],
        },
        config(2),
    )
    .unwrap();
    (wire, server, client)
}

fn step(wire: &Rc<RefCell<Wire>>, server: &mut Stack<End>, client: &mut Stack<End>) {
    server.poll();
    client.poll();
    wire.borrow_mut().now_ms += 1;
}

fn pattern(index: usize) -> u8 {
    (index.wrapping_mul(131) ^ (index >> 7)) as u8
}

/// Client sends `total` bytes in uneven writes and reads the echo; the
/// server echoes with backpressure (it reads only what it can queue).
fn echo_session(drop_every: u64, total: usize, reconnects: usize) {
    let (wire, mut server, mut client) = pair(drop_every);
    let listener = server.listen(7000, 2).unwrap();
    let baseline = server.socket_count();
    for round in 0..reconnects {
        let connection = client
            .connect(Ipv4Address::new(10, 0, 2, 15), 7000, 40000 + round as u16)
            .unwrap();
        let mut accepted = None;
        let (mut sent, mut received) = (0usize, 0usize);
        let mut echo = [0u8; 700];
        for _ in 0..200_000 {
            step(&wire, &mut server, &mut client);
            if accepted.is_none() {
                accepted = server.accept(listener);
            }
            if client.state(connection).unwrap() == TcpState::Established && sent < total {
                // Writes of uneven sizes, unrelated to what arrives.
                let chunk: Vec<u8> = (sent..total.min(sent + 1 + (sent % 977)))
                    .map(pattern)
                    .collect();
                sent += client.send(connection, &chunk).unwrap();
            }
            loop {
                let mut buffer = [0u8; 1500];
                let count = client.recv(connection, &mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                for (offset, byte) in buffer[..count].iter().enumerate() {
                    assert_eq!(
                        *byte,
                        pattern(received + offset),
                        "byte {}",
                        received + offset
                    );
                }
                received += count;
            }
            if let Some(server_side) = accepted {
                // Backpressure: read only what can be queued back.
                let room = server.send_room(server_side).unwrap().min(echo.len());
                if room > 0 {
                    let count = server.recv(server_side, &mut echo[..room]).unwrap();
                    assert_eq!(server.send(server_side, &echo[..count]).unwrap(), count);
                }
            }
            if sent == total && received == total {
                break;
            }
        }
        assert_eq!((sent, received), (total, total), "round {round}");
        // Client closes first; the server closes on the FIN it then reads.
        client.close(connection).unwrap();
        for _ in 0..20_000 {
            step(&wire, &mut server, &mut client);
            if let Some(server_side) = accepted
                && let Ok(state) = server.state(server_side)
            {
                let mut rest = [0u8; 16];
                match server.recv(server_side, &mut rest) {
                    Err(NetError::Finished) => server.close(server_side).unwrap(),
                    Ok(0) => {}
                    other => panic!("server after client FIN: {other:?} in {state:?}"),
                }
            }
            if server.socket_count() == baseline && client.socket_count() == 0 {
                break;
            }
        }
        assert_eq!(
            server.socket_count(),
            baseline,
            "server sockets after round {round}"
        );
        assert_eq!(
            client.socket_count(),
            0,
            "client sockets after round {round}"
        );
    }
    let stats = server.stats();
    assert_eq!(stats.accepted, reconnects as u64);
    assert_eq!(stats.released, reconnects as u64);
    assert_eq!(stats.link_errors, 0);
}

#[test]
fn echo_large_transfer_uneven_writes() {
    echo_session(0, 300_000, 1);
}

#[test]
fn echo_survives_frame_loss() {
    echo_session(13, 60_000, 1);
}

#[test]
fn sequential_connections_leave_nothing_behind() {
    echo_session(0, 3_000, 40);
}

#[test]
fn accepted_socket_survives_transport_timeout_for_ssh_idle_policy() {
    let (wire, mut server, mut client) = pair(0);
    let listener = server.listen(7001, 1).unwrap();
    let connection = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7001, 40031)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(connection).unwrap() == TcpState::Established {
            break;
        }
    }
    let accepted = accepted.expect("accepted");
    assert_eq!(
        server.socket(accepted).unwrap().timeout(),
        Some(Duration::from_millis(TCP_TIMEOUT_MS))
    );
    server.disable_transport_timeout(accepted).unwrap();
    assert_eq!(server.socket(accepted).unwrap().timeout(), None);
    // This fake client has no SSH idle policy; keep its own transport timer
    // out of the server-side qualification case.
    client.socket(connection).unwrap().set_timeout(None);
    wire.borrow_mut().drop_every = 1;
    server
        .send(accepted, b"queued while peer is silent")
        .unwrap();
    step(&wire, &mut server, &mut client);
    wire.borrow_mut().now_ms += TCP_TIMEOUT_MS + 1_000;
    step(&wire, &mut server, &mut client);
    assert_eq!(server.state(accepted), Ok(TcpState::Established));
    assert_eq!(client.state(connection), Ok(TcpState::Established));
    wire.borrow_mut().drop_every = 0;
    client.send(connection, b"still active").unwrap();
    let mut received = [0u8; 12];
    let mut count = 0;
    for _ in 0..100 {
        step(&wire, &mut server, &mut client);
        count += server.recv(accepted, &mut received[count..]).unwrap();
        if count == received.len() {
            break;
        }
    }
    assert_eq!(&received, b"still active");
}

#[test]
fn accepted_socket_keeps_default_finite_transmit_timeout() {
    let (wire, mut server, mut client) = pair(0);
    let listener = server.listen(7002, 1).unwrap();
    let baseline = server.socket_count();
    let connection = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7002, 40032)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(connection).unwrap() == TcpState::Established {
            break;
        }
    }
    let accepted = accepted.expect("accepted");
    assert_eq!(
        server.socket(accepted).unwrap().timeout(),
        Some(Duration::from_millis(TCP_TIMEOUT_MS))
    );
    // Keep a transmit outstanding and drop its frames. The default timeout
    // aborts on inbound silence, whether or not anything is outstanding.
    wire.borrow_mut().drop_every = 1;
    server.send(accepted, b"unacknowledged").unwrap();
    step(&wire, &mut server, &mut client);
    wire.borrow_mut().now_ms += TCP_TIMEOUT_MS + 1_000;
    for _ in 0..10 {
        step(&wire, &mut server, &mut client);
        if server.state(accepted) == Ok(TcpState::Closed) {
            break;
        }
    }
    assert_eq!(server.state(accepted), Ok(TcpState::Closed));
    server.abort(accepted).unwrap();
    server.poll();
    assert_eq!(server.socket_count(), baseline);
}

#[test]
fn filtered_accept_refusal_releases_socket_without_application_slot() {
    for substitute_unknown in [false, true] {
        let (wire, mut server, mut client) = pair(0);
        let listener = server.listen(7003, 1).unwrap();
        let baseline = server.socket_count();
        let _connection = client
            .connect(Ipv4Address::new(10, 0, 2, 15), 7003, 40033)
            .unwrap();
        let mut classified_peers = Vec::new();
        let mut app_slots: Vec<Connection> = Vec::new();
        for _ in 0..1000 {
            step(&wire, &mut server, &mut client);
            let admitted = server.accept_filtered(listener, |peer| {
                // A missing peer is a local substitution fixture: the wire
                // supplies one, but the application classification does not.
                let classified = if substitute_unknown { None } else { peer };
                classified_peers.push(classified);
                false // source already has two unauthenticated sessions
            });
            if let Some((connection, _)) = admitted {
                app_slots.push(connection);
            }
            if !classified_peers.is_empty() {
                break;
            }
        }
        assert_eq!(classified_peers.len(), 1);
        assert_eq!(classified_peers[0].is_none(), substitute_unknown);
        assert!(app_slots.is_empty());
        server.poll();
        assert_eq!(server.socket_count(), baseline);
        assert_eq!(server.stats().released, 1);

        // A refused socket cannot occupy the listener's replacement or an
        // application slot. The next permitted connection still progresses.
        let _next = client
            .connect(Ipv4Address::new(10, 0, 2, 15), 7003, 40034)
            .unwrap();
        let mut next_accepted = None;
        for _ in 0..1000 {
            step(&wire, &mut server, &mut client);
            next_accepted =
                next_accepted.or_else(|| server.accept_filtered(listener, |peer| peer.is_some()));
            if next_accepted.is_some() {
                break;
            }
        }
        let (next_accepted, _) = next_accepted.expect("listener accepts after refusal");
        server.abort(next_accepted).unwrap();
        server.poll();
        assert_eq!(server.socket_count(), baseline);
        assert_eq!(server.stats().released, 2);
    }
}

#[test]
fn reset_releases_both_sides() {
    let (wire, mut server, mut client) = pair(0);
    let listener = server.listen(7000, 1).unwrap();
    let connection = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7000, 40001)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() {
            break;
        }
    }
    let server_side = accepted.expect("accepted");
    client.send(connection, b"partial").unwrap();
    for _ in 0..20 {
        step(&wire, &mut server, &mut client);
    }
    client.abort(connection).unwrap();
    let mut seen = None;
    for _ in 0..100 {
        step(&wire, &mut server, &mut client);
        let mut buffer = [0u8; 64];
        match server.recv(server_side, &mut buffer) {
            Ok(_) => {}
            Err(error) => {
                seen = Some(error);
                break;
            }
        }
    }
    assert_eq!(seen, Some(NetError::Closed));
    server.close(server_side).unwrap();
    for _ in 0..10 {
        step(&wire, &mut server, &mut client);
    }
    assert_eq!(server.socket_count(), 1);
    assert_eq!(client.socket_count(), 0);
    assert_eq!(server.stats().reset, 1);
    // The listener still takes a new connection afterwards.
    let again = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7000, 40002)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(again).unwrap() == TcpState::Established {
            break;
        }
    }
    assert!(accepted.is_some());
}

#[test]
fn unlisten_refuses_new_connections_and_keeps_accepted_ones() {
    let (wire, mut server, mut client) = pair(0);
    let listener = server.listen(7100, 2).unwrap();
    let first = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7100, 40011)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(first).unwrap() == TcpState::Established {
            break;
        }
    }
    let accepted = accepted.expect("accepted");
    server.unlisten(listener).unwrap();
    assert_eq!(server.unlisten(listener), Err(NetError::Unknown));
    assert_eq!(server.socket_count(), 1);
    let refused = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7100, 40012)
        .unwrap();
    for _ in 0..200 {
        step(&wire, &mut server, &mut client);
        if client.state(refused).unwrap() == TcpState::Closed {
            break;
        }
    }
    assert_eq!(client.state(refused).unwrap(), TcpState::Closed);
    assert!(server.accept(listener).is_none());
    // The accepted connection still carries data.
    client.send(first, b"still here").unwrap();
    let mut buffer = [0u8; 16];
    let mut got = 0;
    for _ in 0..200 {
        step(&wire, &mut server, &mut client);
        got += server.recv(accepted, &mut buffer[got..]).unwrap();
        if got == 10 {
            break;
        }
    }
    assert_eq!(&buffer[..got], b"still here");
    // The port can be listened on again.
    server.listen(7100, 1).unwrap();
}

#[test]
fn spent_handles_and_bad_configs_are_refused() {
    let (_wire, mut server, mut client) = pair(0);
    assert_eq!(server.listen(0, 1), Err(NetError::Config));
    assert_eq!(server.listen(22, 0), Err(NetError::Config));
    assert_eq!(server.listen(22, 9), Err(NetError::Config));
    server.listen(22, 1).unwrap();
    assert_eq!(server.listen(22, 1), Err(NetError::InUse));
    let connection = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 22, 40003)
        .unwrap();
    client.close(connection).unwrap();
    assert_eq!(client.send(connection, b"x"), Err(NetError::Unknown));
    assert_eq!(client.close(connection), Err(NetError::Unknown));
    let mut buffer = [0u8; 4];
    assert_eq!(client.recv(connection, &mut buffer), Err(NetError::Unknown));
    let mut config = Config::qemu_user();
    config.prefix_len = 0;
    let wire = Rc::new(RefCell::new(Wire {
        queues: [VecDeque::new(), VecDeque::new()],
        now_ms: 0,
        drop_every: 0,
        sent: 0,
        pauses: 0,
    }));
    assert!(
        Stack::open(
            End {
                wire,
                side: 0,
                mac: [2, 0, 0, 0, 0, 1]
            },
            config
        )
        .is_err()
    );
}

#[test]
fn diverted_frames_bypass_the_stack() {
    let (wire, mut server, _client) = pair(0);
    server.divert(Some(0x88b5));
    let mut frame = std::vec![0u8; 60];
    frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 15]);
    frame[12..14].copy_from_slice(&[0x88, 0xb5]);
    frame[14] = b'S';
    for _ in 0..20 {
        wire.borrow_mut().queues[0].push_back(frame.clone());
    }
    server.poll();
    let mut taken = 0;
    while let Some(raw) = server.raw_receive() {
        assert_eq!(raw, frame);
        taken += 1;
    }
    server.poll();
    while server.raw_receive().is_some() {
        taken += 1;
    }
    let stats = server.stats();
    assert_eq!(taken as u64 + stats.raw_dropped, 20);
    assert_eq!(stats.rx_frames, 20);
    assert_eq!(stats.tx_frames, 0);
}

/// A spent `Connection` must stay spent: `SocketSet` reuses vacated slots,
/// so a bare handle can alias a later, unrelated connection unless the
/// stack distinguishes them (`lib.rs`: "It stays valid until `close` or
/// `abort`; after that every call on it returns `NetError::Unknown`").
#[test]
fn spent_handle_cannot_alias_a_recycled_socket() {
    let (wire, mut server, mut client) = pair(0);
    let listener = server.listen(7004, 1).unwrap();
    let first = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7004, 40041)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(first).unwrap() == TcpState::Established {
            break;
        }
    }
    let server_side = accepted.expect("accepted");
    assert_eq!(client.state(first), Ok(TcpState::Established));
    client.close(first).unwrap();
    // Spent already, while the close drains.
    assert_eq!(client.send(first, b"x"), Err(NetError::Unknown));
    // Run the close to completion so the socket leaves the set.
    let mut server_closed = false;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        if !server_closed {
            let mut rest = [0u8; 16];
            if server.recv(server_side, &mut rest) == Err(NetError::Finished) {
                server.close(server_side).unwrap();
                server_closed = true;
            }
        }
        if client.socket_count() == 0 {
            break;
        }
    }
    assert_eq!(client.socket_count(), 0, "first socket released");
    // A second connection reuses the freed socket-set slot.
    let second = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7004, 40042)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(second).unwrap() == TcpState::Established {
            break;
        }
    }
    assert_eq!(client.state(second), Ok(TcpState::Established));
    assert_ne!(first, second, "socket-set slot was recycled");
    // The contract: the spent handle must not operate on the new connection.
    assert_eq!(client.state(first), Err(NetError::Unknown));
    assert_eq!(client.send(first, b"x"), Err(NetError::Unknown));
    let mut buffer = [0u8; 4];
    assert_eq!(client.recv(first, &mut buffer), Err(NetError::Unknown));
    assert_eq!(client.close(first), Err(NetError::Unknown));
    // The live connection is undisturbed by the stale handle's attempts.
    assert_eq!(client.send(second, b"live"), Ok(4));
}

/// A connection dropped by the close linger bound is aborted; an abort must
/// put a reset on the wire (smoltcp: "One reset packet will be sent"),
/// otherwise the peer hangs in CloseWait until its own policy intervenes.
#[test]
fn linger_bound_close_still_resets_the_peer() {
    let (wire, mut server, mut client) = pair(0);
    let listener = server.listen(7005, 1).unwrap();
    let connection = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 40045)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(connection).unwrap() == TcpState::Established {
            break;
        }
    }
    let server_side = accepted.expect("accepted");
    // The server closes; the client acknowledges the FIN but never closes.
    server.close(server_side).unwrap();
    for _ in 0..100 {
        step(&wire, &mut server, &mut client);
        if client.state(connection).unwrap() == TcpState::CloseWait {
            break;
        }
    }
    assert_eq!(client.state(connection), Ok(TcpState::CloseWait));
    // The linger bound drops the closing socket...
    wire.borrow_mut().now_ms += CLOSE_LINGER_MS + 1_000;
    for _ in 0..10 {
        step(&wire, &mut server, &mut client);
    }
    assert_eq!(server.closing_count(), 0, "linger dropped the socket");
    assert_eq!(server.stats().reset, 1, "the drop is accounted as a reset");
    // ...and the peer observes the reset instead of hanging in CloseWait.
    assert_eq!(client.state(connection), Ok(TcpState::Closed));
}

/// Shared state for the failed/flaky links below: `pause` advances the
/// clock so a test can tell whether `wait` actually waited.
struct DeadState {
    now_ms: u64,
    pauses: Vec<u64>,
}

/// A link whose every call fails immediately, as the kernel's NIC calls do
/// once the NIC has disabled itself (-5/ERROR_IO). It never blocks, so a
/// `wait` that does not fall back to the clock returns instantly.
struct DeadLink(Rc<RefCell<DeadState>>);

impl Link for DeadLink {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 9]
    }

    fn send(&mut self, _frame: &[u8]) -> Result<(), i64> {
        Err(-5)
    }

    fn receive(
        &mut self,
        _buffer: &mut [u8; FRAME_MAX],
        _timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        Err(-5)
    }

    fn now_ms(&self) -> u64 {
        self.0.borrow().now_ms
    }

    fn pause(&self, ms: u64) {
        let mut state = self.0.borrow_mut();
        state.pauses.push(ms);
        state.now_ms += ms;
    }
}

fn dead_config() -> Config {
    Config {
        address: Ipv4Address::new(10, 0, 2, 9),
        prefix_len: 24,
        gateway: None,
        rx_buffer: 8 * 1024,
        tx_buffer: 8 * 1024,
    }
}

/// A persistent link failure must degrade the poll loop to the ordinary
/// idle cadence (at least one tick, at most `MAX_WAIT_MS` per wait), never
/// to a spin: a service that waits on a dead NIC burns bounded time and
/// keeps every failure observable in `stats().link_errors`.
#[test]
fn persistent_link_failure_cannot_spin() {
    let state = Rc::new(RefCell::new(DeadState {
        now_ms: 1,
        pauses: Vec::new(),
    }));
    let mut stack = Stack::open(DeadLink(state.clone()), dead_config()).unwrap();
    stack.listen(7000, 1).unwrap();
    for _ in 0..100 {
        stack.poll();
        stack.wait(10);
    }
    let state = state.borrow();
    assert_eq!(
        state.pauses.len(),
        100,
        "every wait on a failed link must wait"
    );
    assert!(
        state
            .pauses
            .iter()
            .all(|&ms| (1..=MAX_WAIT_MS).contains(&ms)),
        "each pause stays inside the ordinary wait bound: {:?}",
        state.pauses
    );
    assert_eq!(state.now_ms, 1 + state.pauses.iter().sum::<u64>());
    // 100 waits cost at least 100 ticks: no rapid retry is possible.
    assert!(state.now_ms >= 101);
    assert!(stack.stats().link_errors >= 100);
    assert_eq!(stack.stats().last_error, -5);
}

/// A link that fails until `fail_until` and then works. Recovery must be
/// prompt: the first `wait` after the link answers again takes the frame
/// without pausing.
struct FlakyLink {
    state: Rc<RefCell<DeadState>>,
    queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
    fail_until: u64,
}

impl Link for FlakyLink {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 10]
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        if self.state.borrow().now_ms < self.fail_until {
            return Err(-5);
        }
        let _ = frame;
        Ok(())
    }

    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        _timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        if self.state.borrow().now_ms < self.fail_until {
            return Err(-5);
        }
        Ok(self.queue.borrow_mut().pop_front().map(|frame| {
            buffer[..frame.len()].copy_from_slice(&frame);
            frame.len()
        }))
    }

    fn now_ms(&self) -> u64 {
        self.state.borrow().now_ms
    }

    fn pause(&self, ms: u64) {
        let mut state = self.state.borrow_mut();
        state.pauses.push(ms);
        state.now_ms += ms;
    }
}

#[test]
fn link_recovery_is_prompt_after_bounded_retry() {
    let state = Rc::new(RefCell::new(DeadState {
        now_ms: 1,
        pauses: Vec::new(),
    }));
    let queue = Rc::new(RefCell::new(VecDeque::new()));
    let link = FlakyLink {
        state: state.clone(),
        queue: queue.clone(),
        fail_until: 46,
    };
    let mut stack = Stack::open(link, dead_config()).unwrap();
    stack.divert(Some(0x88b5));
    for _ in 0..100 {
        stack.poll();
        stack.wait(10);
        if state.borrow().now_ms >= 46 {
            break;
        }
    }
    assert!(
        state.borrow().now_ms >= 46,
        "waits on a failed link still consume bounded time"
    );
    let during_failure = state.borrow().pauses.len();
    assert!(during_failure >= 4, "bounded retry while the link is down");
    // The link answers again: the next wait takes a waiting frame without
    // pausing, so recovery latency is one wait bound, not a backoff tail.
    let mut frame = std::vec![0u8; 60];
    frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 10]);
    frame[12..14].copy_from_slice(&[0x88, 0xb5]);
    frame[14] = b'R';
    queue.borrow_mut().push_back(frame.clone());
    stack.wait(10);
    assert_eq!(state.borrow().pauses.len(), during_failure);
    assert_eq!(stack.raw_receive(), Some(frame));
}

/// Negative control for the link-failure fallback: on a healthy wire every
/// wait blocks in `receive`, so the clock-fallback pause must never run.
#[test]
fn healthy_wire_never_pauses() {
    let (wire, mut server, mut client) = pair(0);
    let listener = server.listen(7006, 1).unwrap();
    let connection = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7006, 40046)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        server.wait(1);
        client.wait(1);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(connection).unwrap() == TcpState::Established {
            break;
        }
    }
    assert_eq!(client.state(connection), Ok(TcpState::Established));
    client.send(connection, b"data").unwrap();
    for _ in 0..50 {
        step(&wire, &mut server, &mut client);
        server.wait(1);
        client.wait(1);
    }
    assert_eq!(wire.borrow().pauses, 0, "healthy wire never pauses");
}

/// A SYN that is answered but never completed must not hold its backlog
/// socket forever: the transport timeout reaps the half-open socket and
/// the stack re-listens it, so the listener recovers on its own.
#[test]
fn unfinished_handshake_recovers_backlog_socket() {
    let (wire, mut server, mut client) = pair(0);
    let listener = server.listen(7010, 1).unwrap();
    let baseline = server.socket_count();
    let abandoned = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7010, 40040)
        .unwrap();
    // The case is the server's backlog socket; keep the client fixture's
    // own timer out of it (a service fixture opts out, as sshd does).
    client.socket(abandoned).unwrap().set_timeout(None);
    // Deliver the SYN only: once it is on its way (ARP request, ARP reply,
    // SYN), cut the wire so the SYN|ACK never reaches the peer.
    for _ in 0..100 {
        if wire.borrow().sent >= 3 {
            break;
        }
        step(&wire, &mut server, &mut client);
    }
    assert!(wire.borrow().sent >= 3, "SYN sent");
    wire.borrow_mut().drop_every = 1;
    for _ in 0..3 {
        step(&wire, &mut server, &mut client);
    }
    // The backlog socket sits half-open: held, but not yet acceptable.
    assert_eq!(server.socket_count(), baseline);
    assert!(server.accept(listener).is_none());
    assert_eq!(client.state(abandoned), Ok(TcpState::SynSent));
    // Past the transport timeout the half-open socket is reaped and
    // re-listened, not leaked: the backlog keeps its size. The 61-second
    // jump also expires the ARP entries (60-second lifetime), so the fresh
    // handshake below has to wait out the one-second solicitation silence
    // before the wire answers again; the drive bound covers that.
    wire.borrow_mut().now_ms += TCP_TIMEOUT_MS + 1_000;
    for _ in 0..10 {
        step(&wire, &mut server, &mut client);
    }
    assert_eq!(server.socket_count(), baseline);
    client.abort(abandoned).unwrap();
    for _ in 0..3 {
        step(&wire, &mut server, &mut client);
    }
    // The recovered backlog takes a fresh handshake.
    wire.borrow_mut().drop_every = 0;
    let recovered = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7010, 40041)
        .unwrap();
    let mut accepted = None;
    for _ in 0..20_000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(recovered).unwrap() == TcpState::Established {
            break;
        }
    }
    assert!(
        accepted.is_some(),
        "listener accepts after half-open recovery"
    );
    assert_eq!(server.socket_count(), baseline + 1);
    assert_eq!(server.stats().accepted, 1);
    assert_eq!(server.stats().link_errors, 0);
}

/// The default transport timeout is an inbound-silence bound, not only a
/// stalled-transmit one: a healthy established connection that simply
/// hears nothing for `TCP_TIMEOUT_MS` is aborted. A service with its own
/// idle policy (sshd) opts out instead; see
/// `accepted_socket_survives_transport_timeout_for_ssh_idle_policy`.
#[test]
fn default_transport_timeout_reaps_passive_idle_connection() {
    let (wire, mut server, mut client) = pair(0);
    let listener = server.listen(7011, 1).unwrap();
    let baseline = server.socket_count();
    let connection = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7011, 40042)
        .unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut client);
        accepted = accepted.or_else(|| server.accept(listener));
        if accepted.is_some() && client.state(connection).unwrap() == TcpState::Established {
            break;
        }
    }
    let accepted = accepted.expect("accepted");
    // Negative control: nothing was ever queued, no frame is lost, and the
    // connection is healthy before the clock moves.
    assert_eq!(server.state(accepted), Ok(TcpState::Established));
    assert_eq!(server.send_queue(accepted), Ok(0));
    // The client fixture opts out (as sshd does) so only the server side
    // can reap: the server's socket must time out on inbound silence alone.
    client.socket(connection).unwrap().set_timeout(None);
    wire.borrow_mut().now_ms += TCP_TIMEOUT_MS + 1_000;
    for _ in 0..10 {
        step(&wire, &mut server, &mut client);
    }
    assert_eq!(server.state(accepted), Ok(TcpState::Closed));
    // The abort is observable at the peer: the server's reset closes it.
    assert_eq!(client.state(connection), Ok(TcpState::Closed));
    // Reaped sockets are still releasable; nothing is left behind.
    server.abort(accepted).unwrap();
    client.abort(connection).unwrap();
    for _ in 0..10 {
        step(&wire, &mut server, &mut client);
    }
    assert_eq!(server.socket_count(), baseline);
    assert_eq!(client.socket_count(), 0);
}

/// A service that re-binds its port (a configuration reload) must not grow
/// the listener table without bound: `listen` fills a vacated slot, and a
/// spent handle never names a live listener again, even with its slot back
/// in use.
#[test]
fn listener_rebind_keeps_table_bounded_and_handles_spent() {
    let (wire, mut server, mut client) = pair(0);
    let spent = server.listen(7020, 1).unwrap();
    server.unlisten(spent).unwrap();
    let slots = server.listener_count();
    for round in 0..20u16 {
        let listener = server.listen(7020, 1).unwrap();
        // The spent handle stays spent while its slot lives again.
        assert_eq!(server.accept(spent), None, "round {round}");
        assert_eq!(
            server.unlisten(spent),
            Err(NetError::Unknown),
            "round {round}"
        );
        // The live listener accepts a fresh handshake.
        let connection = client
            .connect(Ipv4Address::new(10, 0, 2, 15), 7020, 40060 + round)
            .unwrap();
        let mut accepted = None;
        for _ in 0..1000 {
            step(&wire, &mut server, &mut client);
            accepted = accepted.or_else(|| server.accept(listener));
            if accepted.is_some() && client.state(connection).unwrap() == TcpState::Established {
                break;
            }
        }
        assert!(accepted.is_some(), "round {round}");
        server.abort(accepted.unwrap()).unwrap();
        client.abort(connection).unwrap();
        for _ in 0..10 {
            step(&wire, &mut server, &mut client);
        }
        server.unlisten(listener).unwrap();
        assert_eq!(server.listener_count(), slots, "round {round}");
    }
}

struct SwitchState {
    now_ms: u64,
    reading: Option<LinkReading>,
    reads: u64,
}

/// A link whose `nic_info` reading the test sets; `None` is a refused read.
struct SwitchLink(Rc<RefCell<SwitchState>>);

impl Link for SwitchLink {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 10]
    }

    fn send(&mut self, _frame: &[u8]) -> Result<(), i64> {
        Ok(())
    }

    fn receive(
        &mut self,
        _buffer: &mut [u8; FRAME_MAX],
        _timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        Ok(None)
    }

    fn now_ms(&self) -> u64 {
        self.0.borrow().now_ms
    }

    fn pause(&self, ms: u64) {
        self.0.borrow_mut().now_ms += ms;
    }

    fn read(&self) -> Option<LinkReading> {
        let mut state = self.0.borrow_mut();
        state.reads += 1;
        state.reading
    }
}

fn reading(link_up: bool, disabled: bool, rx_missed: u64) -> Option<LinkReading> {
    Some(LinkReading {
        link_up,
        disabled,
        rx_missed,
    })
}

fn switch(first: Option<LinkReading>) -> (Rc<RefCell<SwitchState>>, Stack<SwitchLink>, NetWatch) {
    let state = Rc::new(RefCell::new(SwitchState {
        now_ms: 1,
        reading: first,
        reads: 0,
    }));
    (
        state.clone(),
        Stack::open(SwitchLink(state), dead_config()).unwrap(),
        NetWatch::new(),
    )
}

#[test]
fn first_reading_reports_and_transitions_report_once() {
    let (state, stack, mut watch) = switch(reading(false, false, 0));
    assert!(watch.observe(&stack));
    assert_eq!(
        watch.fields(&stack),
        "link=down disabled=0 rx_missed=0 link_errors=0"
    );
    assert!(!watch.observe(&stack));
    state.borrow_mut().reading = reading(true, false, 0);
    assert!(watch.observe(&stack));
    assert_eq!(
        (watch.carrier(), watch.fields(&stack).as_str()),
        (Carrier::Up, "link=up disabled=0 rx_missed=0 link_errors=0")
    );
}

#[test]
fn counter_change_alone_is_silent() {
    let (state, stack, mut watch) = switch(reading(true, false, 0));
    watch.observe(&stack);
    state.borrow_mut().reading = reading(true, false, 7);
    assert!(!watch.observe(&stack));
    assert_eq!(
        watch.fields(&stack),
        "link=up disabled=0 rx_missed=7 link_errors=0"
    );
}

#[test]
fn failed_read_is_unknown_not_disabled() {
    let (state, stack, mut watch) = switch(reading(true, false, 3));
    watch.observe(&stack);
    state.borrow_mut().reading = None;
    assert!(watch.observe(&stack));
    assert_eq!(watch.carrier(), Carrier::Unknown);
    assert!(
        !watch.disabled(),
        "a refused read is never the disabled latch"
    );
    assert_eq!(
        watch.fields(&stack),
        "link=unknown disabled=unknown rx_missed=3 link_errors=0"
    );
    assert!(
        !watch.observe(&stack),
        "unknown is printed once, not per sample"
    );
    state.borrow_mut().reading = reading(true, false, 3);
    assert!(watch.observe(&stack));
}

#[test]
fn disabled_reading_is_reported_and_latched() {
    let (state, stack, mut watch) = switch(reading(true, false, 0));
    watch.observe(&stack);
    state.borrow_mut().reading = reading(false, true, 0);
    assert!(watch.observe(&stack) && watch.disabled());
    assert_eq!(
        watch.fields(&stack),
        "link=down disabled=1 rx_missed=0 link_errors=0"
    );
}

#[test]
fn sample_is_time_gated() {
    let (state, stack, mut watch) = switch(reading(true, false, 0));
    assert!(watch.sample(&stack));
    state.borrow_mut().now_ms += NET_SAMPLE_MS - 1;
    assert!(!watch.sample(&stack));
    assert_eq!(
        state.borrow().reads,
        1,
        "no read before the sample period ends"
    );
    state.borrow_mut().now_ms += 1;
    watch.sample(&stack);
    assert_eq!(state.borrow().reads, 2);
}

#[test]
fn flap_inside_one_sample_prints_nothing() {
    let (state, stack, mut watch) = switch(reading(true, false, 0));
    watch.sample(&stack);
    state.borrow_mut().reading = reading(false, false, 0);
    state.borrow_mut().now_ms += 50;
    assert!(!watch.sample(&stack));
    assert_eq!(
        state.borrow().reads,
        1,
        "+50 ms is inside the sample period: the down reading is never read"
    );
    state.borrow_mut().reading = reading(true, false, 0);
    state.borrow_mut().now_ms += NET_SAMPLE_MS;
    assert!(
        !watch.sample(&stack),
        "carrier is up again at the next sample: no transition"
    );
}

#[test]
fn fresh_marker_distinguishes_unchanged_read_from_cached_flags() {
    let (state, stack, mut watch) = switch(reading(true, false, 0));
    assert_eq!(watch.sample_fresh(&stack), Some(true));
    assert_eq!(watch.sample_fresh(&stack), None);
    state.borrow_mut().now_ms += NET_SAMPLE_MS;
    assert_eq!(watch.sample_fresh(&stack), Some(false));
    assert_eq!(state.borrow().reads, 2);
    assert_eq!(watch.disabled_reading(), Some(false));
    state.borrow_mut().reading = None;
    state.borrow_mut().now_ms += NET_SAMPLE_MS;
    assert_eq!(watch.sample_fresh(&stack), Some(true));
    assert_eq!(watch.carrier(), Carrier::Unknown);
    assert_eq!(watch.disabled_reading(), None);
    assert_eq!(watch.sample_fresh(&stack), None);
}

#[test]
fn info_record_parses_flags_and_rx_missed() {
    let mut info = [0u8; INFO_BYTES];
    info[6..8].copy_from_slice(&3u16.to_le_bytes());
    info[24..32].copy_from_slice(&41u64.to_le_bytes());
    assert_eq!(
        reading_from_info(&info),
        LinkReading {
            link_up: true,
            disabled: true,
            rx_missed: 41
        }
    );
    info[6..8].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        reading_from_info(&info),
        LinkReading {
            link_up: false,
            disabled: false,
            rx_missed: 41
        }
    );
}

struct CarrierState {
    now_ms: u64,
    /// Sends still to refuse with `NIC_NO_CARRIER`; then sends succeed.
    refuse: u64,
    sends: u64,
}

/// A link whose sends the kernel refuses for lack of carrier `refuse`
/// times (the NIC stays enabled), then accepts.
struct CarrierLink(Rc<RefCell<CarrierState>>);

impl Link for CarrierLink {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 11]
    }

    fn send(&mut self, _frame: &[u8]) -> Result<(), i64> {
        let mut state = self.0.borrow_mut();
        state.sends += 1;
        if state.refuse > 0 {
            state.refuse -= 1;
            Err(NIC_NO_CARRIER)
        } else {
            Ok(())
        }
    }

    fn receive(
        &mut self,
        _buffer: &mut [u8; FRAME_MAX],
        _timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        Ok(None)
    }

    fn now_ms(&self) -> u64 {
        self.0.borrow().now_ms
    }

    fn pause(&self, ms: u64) {
        self.0.borrow_mut().now_ms += ms;
    }
}

fn carrier(refuse: u64) -> (Rc<RefCell<CarrierState>>, Stack<CarrierLink>, NetWatch) {
    let state = Rc::new(RefCell::new(CarrierState {
        now_ms: 1,
        refuse,
        sends: 0,
    }));
    (
        state.clone(),
        Stack::open(CarrierLink(state), dead_config()).unwrap(),
        NetWatch::new(),
    )
}

fn raw_frame() -> [u8; 60] {
    let mut frame = [0u8; 60];
    frame[..6].fill(0xff);
    frame[12..14].copy_from_slice(&[0x88, 0xb5]);
    frame
}

#[test]
fn no_carrier_refusals_are_counted_and_the_hold_clears_on_the_next_send() {
    let (_state, mut stack, mut watch) = carrier(3);
    assert!(!watch.tx_changed(&stack), "no line before any send: the hold starts clear");
    for _ in 0..3 {
        assert_eq!(stack.raw_send(&raw_frame()), Err(NetError::Nic(NIC_NO_CARRIER)));
    }
    let stats = stack.stats();
    assert_eq!(
        (stats.no_carrier, stats.link_errors, stats.last_error, stats.tx_held),
        (3, 3, -100, true)
    );
    assert!(watch.tx_changed(&stack));
    assert_eq!(watch.tx_fields(&stack), "held=1 no_carrier=3");
    assert!(!watch.tx_changed(&stack), "one line per transition");
    stack.raw_send(&raw_frame()).unwrap();
    assert!(!stack.stats().tx_held);
    assert!(watch.tx_changed(&stack));
    assert_eq!(watch.tx_fields(&stack), "held=0 no_carrier=3");
    assert!(!watch.tx_changed(&stack));
}

#[test]
fn a_device_refusal_is_not_a_carrier_hold() {
    let state = Rc::new(RefCell::new(DeadState {
        now_ms: 1,
        pauses: Vec::new(),
    }));
    let mut stack = Stack::open(DeadLink(state), dead_config()).unwrap();
    let mut watch = NetWatch::new();
    assert_eq!(stack.raw_send(&raw_frame()), Err(NetError::Nic(-5)));
    let stats = stack.stats();
    assert_eq!((stats.no_carrier, stats.tx_held, stats.last_error), (0, false, -5));
    assert!(!watch.tx_changed(&stack), "-5 is the disabled latch's business, not a hold");
}

#[test]
fn smoltcp_sends_refused_for_carrier_set_the_hold() {
    let (state, mut stack, mut watch) = carrier(1_000);
    let _connection = stack
        .connect(Ipv4Address::new(10, 0, 2, 15), 7000, 40040)
        .unwrap();
    stack.poll();
    let stats = stack.stats();
    assert!(stats.no_carrier >= 1 && stats.tx_held, "{stats:?}");
    assert_eq!(stats.no_carrier, stats.link_errors);
    assert!(state.borrow().sends <= 2, "a refused send is a dropped frame, never a retry loop");
    assert!(watch.tx_changed(&stack));
}

/// A link whose sends return the scripted results in order, then succeed.
struct ScriptLink(Rc<RefCell<(u64, VecDeque<Result<(), i64>>)>>);

impl Link for ScriptLink {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 12]
    }

    fn send(&mut self, _frame: &[u8]) -> Result<(), i64> {
        self.0.borrow_mut().1.pop_front().unwrap_or(Ok(()))
    }

    fn receive(
        &mut self,
        _buffer: &mut [u8; FRAME_MAX],
        _timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        Ok(None)
    }

    fn now_ms(&self) -> u64 {
        self.0.borrow().0
    }

    fn pause(&self, ms: u64) {
        self.0.borrow_mut().0 += ms;
    }
}

#[test]
fn a_refusal_other_than_no_carrier_clears_the_hold_so_a_later_hold_prints_again() {
    let script = VecDeque::from([
        Err(NIC_NO_CARRIER),
        Err(-5),
        Err(NIC_NO_CARRIER),
        Ok(()),
    ]);
    let mut stack = Stack::open(ScriptLink(Rc::new(RefCell::new((1, script)))), dead_config())
        .unwrap();
    let mut watch = NetWatch::new();
    assert_eq!(stack.raw_send(&raw_frame()), Err(NetError::Nic(NIC_NO_CARRIER)));
    assert!(watch.tx_changed(&stack));
    assert_eq!(watch.tx_fields(&stack), "held=1 no_carrier=1");
    // The NIC disabled itself: the kernel holds no descriptor for it now.
    assert_eq!(stack.raw_send(&raw_frame()), Err(NetError::Nic(-5)));
    assert!(!stack.stats().tx_held);
    assert!(watch.tx_changed(&stack));
    assert_eq!(watch.tx_fields(&stack), "held=0 no_carrier=1");
    // Re-enabled, and the carrier is still absent: the hold prints again.
    assert_eq!(stack.raw_send(&raw_frame()), Err(NetError::Nic(NIC_NO_CARRIER)));
    assert!(watch.tx_changed(&stack));
    assert_eq!(watch.tx_fields(&stack), "held=1 no_carrier=2");
    // The held descriptor completed; the next send is accepted.
    stack.raw_send(&raw_frame()).unwrap();
    assert!(watch.tx_changed(&stack));
    assert_eq!(watch.tx_fields(&stack), "held=0 no_carrier=2");
    assert!(!watch.tx_changed(&stack));
}

fn udp_grant(port: u16, last: u8, peer_port: u16) -> datagram::Grant {
    datagram::Grant {
        local_port: port,
        peer: datagram::Address {
            ip: [10, 0, 2, last],
            port: peer_port,
        },
    }
}

#[test]
fn udp_empty_maximum_oversize_and_short_receive_preserve_boundaries() {
    use datagram::*;
    let (wire, mut a, mut b) = pair(0);
    let ga = udp_grant(7002, 2, 40000);
    let gb = udp_grant(40000, 15, 7002);
    let ea = a.datagram_bind(ga).unwrap();
    let eb = b.datagram_bind(gb).unwrap();
    let mut out = [0; MAX_DATAGRAM];
    for size in [0, 1, MAX_DATAGRAM] {
        let data: Vec<u8> = (0..size).map(pattern).collect();
        b.datagram_send(eb, gb.peer, &data).unwrap();
        for _ in 0..20 {
            step(&wire, &mut a, &mut b);
        }
        if size > 0 {
            assert_eq!(
                a.datagram_receive(ea, &mut []),
                Err(Error::TooSmall { needed: size })
            );
        }
        assert_eq!(a.datagram_receive(ea, &mut out), Ok((size, ga.peer)));
        assert_eq!(&out[..size], data);
        assert_eq!(a.datagram_receive(ea, &mut out), Err(Error::Again));
    }
    assert_eq!(
        a.datagram_send(ea, ga.peer, &[0; MAX_DATAGRAM + 1]),
        Err(Error::Oversize)
    );
    let other = Address {
        port: 40001,
        ..ga.peer
    };
    assert_eq!(a.datagram_send(ea, other, b"denied"), Err(Error::Denied));
}

#[test]
fn udp_grants_capacity_collision_rebind_and_service_instances() {
    use datagram::*;
    let (_, mut a, mut b) = pair(0);
    let grant = udp_grant(7002, 2, 40000);
    let old = a.datagram_bind(grant).unwrap();
    assert_eq!(a.datagram_bind(grant), Err(Error::InUse));
    assert_eq!(b.datagram_close(old), Err(Error::Stale));
    for port in 7003..7003 + MAX_ENDPOINTS as u16 - 1 {
        a.datagram_bind(udp_grant(port, 2, 40000)).unwrap();
    }
    assert_eq!(
        a.datagram_bind(udp_grant(8000, 2, 40000)),
        Err(Error::Exhausted)
    );
    a.datagram_close(old).unwrap();
    let new = a.datagram_bind(grant).unwrap();
    assert_eq!(a.datagram_close(old), Err(Error::Stale));
    assert_eq!(a.datagram_send(old, grant.peer, b"old"), Err(Error::Stale));
    a.datagram_fence();
    assert_eq!(a.socket_count(), 0);
    assert_eq!(a.datagram_receive(new, &mut [0; 10]), Err(Error::Stale));
    for _ in 0..40 {
        let fresh = a.datagram_bind(grant).unwrap();
        a.datagram_close(fresh).unwrap();
    }
    for grant in [
        udp_grant(53, 2, 53),
        udp_grant(7002, 2, 0),
        udp_grant(7002, 255, 53),
        udp_grant(7002, 0, 53),
        udp_grant(7002, 15, 53),
        Grant {
            peer: Address {
                ip: [224, 0, 0, 1],
                port: 53,
            },
            ..grant
        },
    ] {
        assert_eq!(a.datagram_bind(grant), Err(Error::Denied));
    }
}

#[test]
fn udp_tx_and_rx_exhaustion_are_bounded_and_close_discards_queued_tx() {
    use datagram::*;
    let (wire, mut a, mut b) = pair(0);
    let ga = udp_grant(7002, 2, 40000);
    let gb = udp_grant(40000, 15, 7002);
    let ea = a.datagram_bind(ga).unwrap();
    let eb = b.datagram_bind(gb).unwrap();
    for n in 0..QUEUE_PACKETS {
        b.datagram_send(eb, gb.peer, &[n as u8]).unwrap();
    }
    assert_eq!(
        b.datagram_send(eb, gb.peer, b"extra"),
        Err(Error::Exhausted)
    );
    for _ in 0..20 {
        step(&wire, &mut a, &mut b);
    }
    // More data reaches a full receive queue; it is dropped whole.
    b.datagram_send(eb, gb.peer, b"drop").unwrap();
    for _ in 0..20 {
        step(&wire, &mut a, &mut b);
    }
    for n in 0..QUEUE_PACKETS {
        let mut data = [0; 10];
        assert_eq!(a.datagram_receive(ea, &mut data), Ok((1, ga.peer)));
        assert_eq!(data[0], n as u8);
    }
    assert_eq!(a.datagram_receive(ea, &mut [0; 10]), Err(Error::Again));
    b.datagram_send(eb, gb.peer, b"discard").unwrap();
    b.datagram_close(eb).unwrap();
    for _ in 0..20 {
        step(&wire, &mut a, &mut b);
    }
    assert_eq!(a.datagram_receive(ea, &mut [0; 10]), Err(Error::Again));
}

fn independent_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += ((pair[0] as u32) << 8) | pair.get(1).copied().unwrap_or(0) as u32;
    }
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

// Independent RFC 791/768 fixture; no smoltcp packet encoder/parser.
fn udp_frame(source_port: u16, body: &[u8]) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend_from_slice(&source_port.to_be_bytes());
    udp.extend_from_slice(&7002u16.to_be_bytes());
    udp.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // IPv4 permits an absent UDP checksum.
    udp.extend_from_slice(body);
    let mut frame = vec![2, 0, 0, 0, 0, 15, 2, 0, 0, 0, 0, 2, 8, 0];
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 17, 0, 0, 10, 0, 2, 2, 10, 0, 2, 15]);
    let checksum = independent_checksum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame
}

#[test]
fn udp_independent_malformed_lengths_checksums_fragment_and_unauthorized_source() {
    use datagram::*;
    let (wire, mut a, _) = pair(0);
    let grant = udp_grant(7002, 2, 40000);
    let endpoint = a.datagram_bind(grant).unwrap();
    let good = udp_frame(40000, b"reference");
    let mut fixtures = Vec::new();
    fixtures.push(good[..24].to_vec());
    let mut f = good.clone();
    f[14] = 0x44;
    fixtures.push(f);
    let mut f = good.clone();
    f[24] ^= 1;
    fixtures.push(f);
    let mut f = good.clone();
    f[38..40].copy_from_slice(&7u16.to_be_bytes());
    fixtures.push(f);
    let mut f = good.clone();
    f[38..40].copy_from_slice(&200u16.to_be_bytes());
    fixtures.push(f);
    let mut f = good.clone();
    f[40..42].copy_from_slice(&1u16.to_be_bytes());
    fixtures.push(f);
    let mut f = good.clone();
    f[20] = 0x20;
    f[24..26].fill(0);
    let c = independent_checksum(&f[14..34]);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    fixtures.push(f);
    fixtures.push(udp_frame(40001, b"wrong peer port"));
    let mut f = good.clone();
    f[29] = 3;
    f[24..26].fill(0);
    let c = independent_checksum(&f[14..34]);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    fixtures.push(f);
    for f in fixtures {
        wire.borrow_mut().queues[0].push_back(f);
        a.poll();
        assert_eq!(
            a.datagram_receive(endpoint, &mut [0; MAX_DATAGRAM]),
            Err(Error::Again)
        );
    }
    wire.borrow_mut().queues[0].push_back(good);
    a.poll();
    let mut out = [0; MAX_DATAGRAM];
    assert_eq!(a.datagram_receive(endpoint, &mut out), Ok((9, grant.peer)));
    assert_eq!(&out[..9], b"reference");
}

fn udp_request(op: u8, peer: datagram::Address, bytes: &[u8], capacity: usize) -> Vec<u8> {
    let mut r = vec![1, op, 0, 0];
    r.extend_from_slice(&peer.ip);
    r.extend_from_slice(&peer.port.to_be_bytes());
    r.extend_from_slice(
        &(if op == datagram::SEND {
            bytes.len()
        } else {
            capacity
        } as u16)
            .to_be_bytes(),
    );
    r.extend_from_slice(bytes);
    r
}

#[test]
fn udp_channel_request_cannot_select_or_expand_another_clients_grant() {
    use datagram::*;
    let (_, mut a, _) = pair(0);
    let mut one = Session::grant(&mut a, udp_grant(7002, 2, 40000)).unwrap();
    let mut two = Session::grant(&mut a, udp_grant(7003, 2, 40001)).unwrap();
    let mut reply = [0; MAX_MESSAGE];
    let foreign = udp_request(SEND, udp_grant(7003, 2, 40001).peer, b"foreign", 0);
    assert_eq!(one.request(&mut a, &foreign, &mut reply), 12);
    assert_eq!(reply[2], Error::Denied.code());
    assert_eq!(two.request(&mut a, &foreign, &mut reply), 12);
    assert_eq!(reply[2], 0);
    for n in 0..12 {
        one.request(&mut a, &foreign[..n], &mut reply);
        assert_eq!(reply[2], Error::Invalid.code());
    }
    let mut invalid = foreign.clone();
    invalid[2] = 1;
    two.request(&mut a, &invalid, &mut reply);
    assert_eq!(reply[2], Error::Invalid.code());
    one.revoke(&mut a);
    one.request(
        &mut a,
        &udp_request(SEND, udp_grant(7002, 2, 40000).peer, b"old", 0),
        &mut reply,
    );
    assert_eq!(reply[2], Error::Stale.code());
    two.request(&mut a, &foreign, &mut reply);
    assert_eq!(reply[2], 0);
}

struct TestPipe {
    input: VecDeque<u8>,
    output: Vec<u8>,
    now: u64,
    eof: bool,
    block: bool,
}
impl datagram::channel::Pipe for TestPipe {
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.input.is_empty() {
            return if self.eof { Ok(Some(0)) } else { Ok(None) };
        }
        b[0] = self.input.pop_front().unwrap();
        Ok(Some(1))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        if self.block {
            return Ok(None);
        }
        self.output.push(b[0]);
        Ok(Some(1))
    }
    fn now_ms(&self) -> u64 {
        self.now
    }
}

#[test]
fn udp_channel_partial_messages_eof_slow_reader_and_revocation() {
    use datagram::*;
    let (_, mut a, _) = pair(0);
    let grant = udp_grant(7002, 2, 40000);
    for mode in 0..4 {
        let mut channel = channel::Channel::grant(&mut a, grant).unwrap();
        let request = udp_request(SEND, grant.peer, b"one", 0);
        let mut input = VecDeque::from((request.len() as u16).to_be_bytes().to_vec());
        input.extend(request);
        let mut pipe = TestPipe {
            input,
            output: Vec::new(),
            now: 0,
            eof: false,
            block: false,
        };
        if mode == 0 {
            for _ in 0..40 {
                channel.poll(&mut a, &mut pipe);
            }
            assert_eq!(
                &pipe.output[..],
                &[0, 12, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            );
            pipe.eof = true;
            assert!(!channel.poll(&mut a, &mut pipe));
        } else if mode == 1 {
            channel.poll(&mut a, &mut pipe); // partial prefix
            pipe.now = 250;
            assert!(!channel.poll(&mut a, &mut pipe));
        } else if mode == 2 {
            pipe.input = VecDeque::from(vec![0xff, 0xff]);
            channel.poll(&mut a, &mut pipe);
            assert!(!channel.poll(&mut a, &mut pipe));
        } else {
            pipe.block = true;
            for _ in 0..30 {
                channel.poll(&mut a, &mut pipe);
            }
            pipe.now = 250;
            assert!(!channel.poll(&mut a, &mut pipe));
        }
        assert_eq!(a.socket_count(), 0);
    }
}

#[test]
fn udp_carrier_unknown_device_failure_fence_and_tcp_without_udp_does_not_sample() {
    use datagram::*;
    let state = Rc::new(RefCell::new(SwitchState {
        now_ms: 0,
        reading: reading(true, false, 0),
        reads: 0,
    }));
    let mut stack = Stack::open(SwitchLink(state.clone()), dead_config()).unwrap();
    stack.poll();
    assert_eq!(
        state.borrow().reads,
        0,
        "TCP-only poll gained NIC observation calls"
    );
    let grant = udp_grant(7002, 2, 40000);
    for (reading, error) in [
        (reading(false, false, 0), Error::LinkDown),
        (None, Error::LinkUnknown),
        (reading(true, true, 0), Error::DeviceFailed),
    ] {
        state.borrow_mut().reading = super::tests::reading(true, false, 0);
        let endpoint = stack.datagram_bind(grant).unwrap();
        state.borrow_mut().reading = reading;
        assert_eq!(stack.datagram_send(endpoint, grant.peer, b"x"), Err(error));
        stack.poll();
        state.borrow_mut().reading = super::tests::reading(true, false, 0);
        assert_eq!(
            stack.datagram_send(endpoint, grant.peer, b"old"),
            Err(Error::Stale)
        );
        assert_eq!(stack.socket_count(), 0);
    }
}

#[test]
fn udp_emitted_ipv4_udp_checksums_ports_lengths_and_bytes_match_independent_control() {
    use datagram::*;
    let (wire,mut a,mut b)=pair(0);
    let ga=udp_grant(7002,2,40000);let gb=udp_grant(40000,15,7002);
    let ea=a.datagram_bind(ga).unwrap();let eb=b.datagram_bind(gb).unwrap();
    b.datagram_send(eb,gb.peer,b"learn").unwrap();
    for _ in 0..20 {step(&wire,&mut a,&mut b);}
    a.datagram_receive(ea,&mut [0;10]).unwrap();
    for length in [0,1,MAX_DATAGRAM] {
        let data:Vec<u8>=(0..length).map(pattern).collect();
        b.datagram_send(eb,gb.peer,&data).unwrap();b.poll();
        let frame=wire.borrow_mut().queues[0].pop_front().unwrap();
        assert_eq!(&frame[12..14],&[8,0]);assert_eq!(frame[14],0x45);
        assert_eq!(independent_checksum(&frame[14..34]),0);
        assert_eq!(&frame[26..34],&[10,0,2,2,10,0,2,15]);
        assert_eq!(&frame[34..38],&[0x9c,0x40,0x1b,0x5a]);
        assert_eq!(u16::from_be_bytes([frame[16],frame[17]]) as usize,28+length);
        assert_eq!(u16::from_be_bytes([frame[38],frame[39]]) as usize,8+length);
        let mut pseudo=frame[26..34].to_vec();pseudo.extend_from_slice(&[0,17]);
        pseudo.extend_from_slice(&frame[38..40]);pseudo.extend_from_slice(&frame[34..42+length]);
        assert_eq!(independent_checksum(&pseudo),0);
        assert_eq!(&frame[42..42+length],&data);
    }
}

mod stream_cases { include!("stream/tests.rs"); }

mod icmp_cases { include!("icmp/tests.rs"); }

mod server_cases {
    include!("stream/server_tests.rs");
}

#[test]
fn reused_tx_buffer_cannot_supply_icmpv4_unused_fields_after_udp_retirement() {
    for fence in [false, true] {
        let (wire, mut local, mut peer) = pair(0);
        let local_grant = udp_grant(7002, 2, 40000);
        let peer_grant = udp_grant(40000, 15, 7002);
        let local_endpoint = local.datagram_bind(local_grant).unwrap();
        let peer_endpoint = peer.datagram_bind(peer_grant).unwrap();
        peer.datagram_send(peer_endpoint, peer_grant.peer, b"learn")
            .unwrap();
        for _ in 0..20 {
            step(&wire, &mut local, &mut peer);
        }
        local
            .datagram_receive(local_endpoint, &mut [0; 16])
            .unwrap();

        // Exercise the real engine and actual reusable owner TX buffer. The
        // first packet puts a nonzero UDP length/checksum at the later ICMP
        // unused-word offset; no test writes into the private TX buffer.
        local
            .datagram_send(local_endpoint, local_grant.peer, &[0x5a; 129])
            .unwrap();
        local.poll();
        let previous = wire.borrow_mut().queues[1].pop_front().unwrap();
        assert_eq!(previous[23], 17);
        assert_eq!(u16::from_be_bytes([previous[38], previous[39]]), 137);
        assert_ne!(&previous[38..42], &[0; 4]);

        peer.datagram_send(peer_endpoint, peer_grant.peer, b"queued-before-retire")
            .unwrap();
        peer.poll();
        let submitted = wire.borrow().queues[0].front().unwrap().clone();
        if fence {
            local.datagram_fence();
        } else {
            local.datagram_close(local_endpoint).unwrap();
        }
        local.poll();
        let error = wire.borrow_mut().queues[1].pop_front().unwrap();
        assert_eq!(error[23], 1);
        assert_eq!(&error[34..36], &[3, 3]);
        assert_eq!(&error[38..42], &[0; 4], "fence={fence}");
        let total = usize::from(u16::from_be_bytes([error[16], error[17]]));
        assert_eq!(error.len(), 14 + total);
        assert_eq!(independent_checksum(&error[14..34]), 0);
        assert_eq!(independent_checksum(&error[34..14 + total]), 0);
        assert_eq!(independent_checksum(&error[42..62]), 0);
        assert_eq!(&error[54..62], &submitted[26..34]);
        assert_eq!(&error[62..], &submitted[34..]);
        // The engine reconstructs the quoted IP header; only its source,
        // destination and original UDP bytes are asserted above. This test
        // does not claim byte-identical IP ID/checksum preservation.
        assert_eq!(local.socket_count(), 0);
        assert!(wire.borrow().queues[1].is_empty());
        peer.datagram_close(peer_endpoint).unwrap();
    }
}
