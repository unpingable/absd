//! Retired datagram generations retain one observed link reason, not authority.
//! These controls exercise the real Stack/Session/Channel paths. They establish
//! neither QMP propagation nor physical NIC quiescence.

use super::*;
use crate::datagram::{self, Error};

fn faults() -> [(Option<LinkReading>, Error); 4] {
    [
        (reading(false, false, 0), Error::LinkDown),
        (None, Error::LinkUnknown),
        (reading(true, true, 0), Error::DeviceFailed),
        (reading(false, true, 0), Error::DeviceFailed),
    ]
}

fn setup() -> (Rc<RefCell<SwitchState>>, Stack<SwitchLink>) {
    let (state, stack, _) = switch(reading(true, false, 0));
    (state, stack)
}

fn ip6(last: u8) -> [u8; 16] {
    let mut address = [0; 16];
    address[0] = 0xfd;
    address[15] = last;
    address
}

fn configure6<L: Link>(stack: &mut Stack<L>) {
    stack
        .configure_ipv6(ipv6::Config {
            address: ip6(9),
            prefix_len: 64,
            scope: 7,
        })
        .unwrap();
}

fn grant6() -> ipv6::Grant {
    ipv6::Grant {
        local_port: 7200,
        peer: ipv6::Address {
            ip: ip6(2),
            port: 40000,
            scope: 7,
        },
    }
}

#[test]
fn poll_first_reason_survives_recovery_and_is_consumed_once_by_send_or_receive() {
    for (fault, error) in faults() {
        for receive_first in [false, true] {
            let (state, mut stack) = setup();
            let grant = udp_grant(7002, 2, 40000);
            let endpoint = stack.datagram_bind(grant).unwrap();
            state.borrow_mut().reading = fault;
            stack.poll();
            assert_eq!(stack.socket_count(), 0);
            state.borrow_mut().reading = reading(true, false, 0);
            stack.poll();
            if receive_first {
                assert_eq!(stack.datagram_receive(endpoint, &mut [0; 1]), Err(error));
                assert_eq!(
                    stack.datagram_send(endpoint, grant.peer, b"x"),
                    Err(Error::Stale)
                );
            } else {
                assert_eq!(stack.datagram_send(endpoint, grant.peer, b"x"), Err(error));
                assert_eq!(
                    stack.datagram_receive(endpoint, &mut [0; 1]),
                    Err(Error::Stale)
                );
            }
            assert_eq!(stack.socket_count(), 0);
        }
    }
}

#[test]
fn request_first_reason_is_not_reported_again_after_poll_or_carrier_recovery() {
    for (fault, error) in faults() {
        for receive_first in [false, true] {
            let (state, mut stack) = setup();
            let grant = udp_grant(7002, 2, 40000);
            let endpoint = stack.datagram_bind(grant).unwrap();
            state.borrow_mut().reading = fault;
            if receive_first {
                assert_eq!(stack.datagram_receive(endpoint, &mut [0; 1]), Err(error));
            } else {
                assert_eq!(stack.datagram_send(endpoint, grant.peer, b"x"), Err(error));
            }
            stack.poll();
            state.borrow_mut().reading = reading(true, false, 0);
            assert_eq!(
                stack.datagram_send(endpoint, grant.peer, b"x"),
                Err(Error::Stale)
            );
            assert_eq!(
                stack.datagram_receive(endpoint, &mut [0; 1]),
                Err(Error::Stale)
            );
            assert_eq!(stack.socket_count(), 0);
        }
    }
}

#[test]
fn first_cause_survives_later_fault_in_a_new_other_family_generation() {
    for (first_fault, first_error) in faults() {
        let (state, mut stack) = setup();
        let grant = udp_grant(7002, 2, 40000);
        let endpoint = stack.datagram_bind(grant).unwrap();
        state.borrow_mut().reading = first_fault;
        stack.poll();
        state.borrow_mut().reading = reading(true, false, 0);
        configure6(&mut stack);
        let other = stack.ipv6_bind(grant6()).unwrap();
        state.borrow_mut().reading = if first_error == Error::LinkUnknown {
            reading(false, false, 0)
        } else {
            None
        };
        stack.poll();
        assert_eq!(stack.ipv6_receive(other, &mut [0; 1]), Err(Error::Stale));
        assert_eq!(
            stack.datagram_send(endpoint, grant.peer, b"x"),
            Err(first_error)
        );
        assert_eq!(
            stack.datagram_send(endpoint, grant.peer, b"x"),
            Err(Error::Stale)
        );
        assert_eq!(stack.socket_count(), 0);
    }
}

#[test]
fn administrative_fence_and_explicit_close_cancel_unread_diagnostic() {
    for explicit_close in [false, true] {
        let (state, mut stack) = setup();
        let grant = udp_grant(7002, 2, 40000);
        let endpoint = stack.datagram_bind(grant).unwrap();
        state.borrow_mut().reading = None;
        stack.poll();
        if explicit_close {
            assert_eq!(stack.datagram_close(endpoint), Err(Error::Stale));
        } else {
            stack.datagram_fence();
        }
        assert_eq!(
            stack.datagram_send(endpoint, grant.peer, b"x"),
            Err(Error::Stale)
        );
        assert_eq!(
            stack.datagram_receive(endpoint, &mut [0; 1]),
            Err(Error::Stale)
        );
        assert_eq!(stack.socket_count(), 0);
    }
}

#[test]
fn foreign_instance_cannot_consume_or_close_another_stacks_pending_reason() {
    let (state, mut stack) = setup();
    let (_, mut other) = setup();
    let grant = udp_grant(7002, 2, 40000);
    let endpoint = stack.datagram_bind(grant).unwrap();
    let foreign = other.datagram_bind(grant).unwrap();
    state.borrow_mut().reading = None;
    stack.poll();
    assert_eq!(
        stack.datagram_send(foreign, grant.peer, b"x"),
        Err(Error::Stale)
    );
    assert_eq!(stack.datagram_close(foreign), Err(Error::Stale));
    assert_eq!(
        stack.datagram_receive(endpoint, &mut [0; 1]),
        Err(Error::LinkUnknown)
    );
    assert_eq!(
        other.datagram_send(foreign, grant.peer, b"still-live"),
        Ok(())
    );
    assert_eq!(other.socket_count(), 1);
}

#[test]
fn slot_reuse_spends_old_epoch_and_does_not_reserve_the_port_for_diagnostics() {
    let (state, mut stack) = setup();
    let grant = udp_grant(7002, 2, 40000);
    let old = stack.datagram_bind(grant).unwrap();
    state.borrow_mut().reading = None;
    stack.poll();
    // Binding the same local port succeeds while its retired diagnostic is unread.
    state.borrow_mut().reading = reading(true, false, 0);
    let new = stack.datagram_bind(grant).unwrap();
    assert_ne!(new, old);
    assert_eq!(
        stack.datagram_send(old, grant.peer, b"x"),
        Err(Error::Stale)
    );
    assert_eq!(stack.datagram_close(old), Err(Error::Stale));
    assert_eq!(stack.datagram_send(new, grant.peer, b"new"), Ok(()));
    state.borrow_mut().reading = reading(false, false, 0);
    stack.poll();
    assert_eq!(stack.datagram_close(old), Err(Error::Stale));
    assert_eq!(stack.datagram_receive(old, &mut [0; 1]), Err(Error::Stale));
    assert_eq!(
        stack.datagram_send(new, grant.peer, b"x"),
        Err(Error::LinkDown)
    );
    assert_eq!(
        stack.datagram_send(new, grant.peer, b"x"),
        Err(Error::Stale)
    );
}

#[test]
fn each_retired_endpoint_receives_its_own_reason_without_restoring_any_socket() {
    let (state, mut stack) = setup();
    let first_grant = udp_grant(7002, 2, 40000);
    let second_grant = udp_grant(7003, 2, 40001);
    let first = stack.datagram_bind(first_grant).unwrap();
    let second = stack.datagram_bind(second_grant).unwrap();
    state.borrow_mut().reading = None;
    assert_eq!(
        stack.datagram_send(first, first_grant.peer, b"x"),
        Err(Error::LinkUnknown)
    );
    assert_eq!(stack.socket_count(), 0);
    assert_eq!(
        stack.datagram_send(first, first_grant.peer, b"x"),
        Err(Error::Stale)
    );
    assert_eq!(
        stack.datagram_receive(second, &mut [0; 1]),
        Err(Error::LinkUnknown)
    );
    assert_eq!(
        stack.datagram_receive(second, &mut [0; 1]),
        Err(Error::Stale)
    );
    assert_eq!(stack.socket_count(), 0);
}

#[test]
fn malformed_session_request_does_not_consume_reason_and_revoke_cancels_it() {
    for revoke in [false, true] {
        let (state, mut stack) = setup();
        let grant = udp_grant(7002, 2, 40000);
        let mut session = datagram::Session::grant(&mut stack, grant).unwrap();
        state.borrow_mut().reading = None;
        stack.poll();
        let mut reply = [0; datagram::MAX_MESSAGE];
        let mut request = udp_request(datagram::SEND, grant.peer, b"x", 0);
        request[2] = 1;
        assert_eq!(session.request(&mut stack, &request, &mut reply), 12);
        assert_eq!(reply[2], Error::Invalid.code());
        if revoke {
            session.revoke(&mut stack);
        }
        request[2] = 0;
        session.request(&mut stack, &request, &mut reply);
        assert_eq!(
            reply[2],
            if revoke {
                Error::Stale
            } else {
                Error::LinkUnknown
            }
            .code()
        );
        session.request(&mut stack, &request, &mut reply);
        assert_eq!(reply[2], Error::Stale.code());
    }
}

#[test]
fn parent_poll_then_partial_channel_reply_serializes_link_code_once() {
    for (fault, error) in faults() {
        let (state, mut stack) = setup();
        let grant = udp_grant(7002, 2, 40000);
        let mut channel = datagram::channel::Channel::grant(&mut stack, grant).unwrap();
        let request = udp_request(datagram::SEND, grant.peer, b"x", 0);
        let mut framed = (request.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&request);
        let mut pipe = TestPipe {
            input: VecDeque::new(),
            output: Vec::new(),
            now: 0,
            eof: false,
            block: false,
        };
        state.borrow_mut().reading = fault;
        for expected in [error.code(), Error::Stale.code()] {
            pipe.input.extend(framed.iter().copied());
            let offset = pipe.output.len();
            for _ in 0..64 {
                stack.poll();
                assert!(channel.poll(&mut stack, &mut pipe));
            }
            assert!(pipe.input.is_empty());
            assert_eq!(
                &pipe.output[offset..offset + 4],
                &[0, 12, 1, datagram::SEND]
            );
            assert_eq!(pipe.output[offset + 4], expected);
            assert_eq!(pipe.output.len(), offset + 14);
            assert_eq!(stack.socket_count(), 0);
        }
        channel.revoke(&mut stack);
        assert!(!channel.live());
    }
}

#[test]
fn ipv6_maintain_before_native_poll_preserves_link_cause_without_ipv6_semantic_change() {
    for (fault, error) in faults() {
        let (state, mut stack) = setup();
        configure6(&mut stack);
        let other = stack.ipv6_bind(grant6()).unwrap();
        let grant = udp_grant(7002, 2, 40000);
        let endpoint = stack.datagram_bind(grant).unwrap();
        state.borrow_mut().reading = fault;
        stack.poll();
        assert_eq!(stack.ipv6_receive(other, &mut [0; 1]), Err(Error::Stale));
        assert_eq!(stack.datagram_receive(endpoint, &mut [0; 1]), Err(error));
        assert_eq!(
            stack.datagram_receive(endpoint, &mut [0; 1]),
            Err(Error::Stale)
        );
        assert_eq!(stack.socket_count(), 0);
    }
}

#[test]
fn direct_stream_link_fault_cross_fences_native_with_native_codes_only() {
    for (fault, native_error) in faults() {
        for family6 in [false, true] {
            let (state, mut stack) = setup();
            configure6(&mut stack);
            let grant = udp_grant(7002, 2, 40000);
            let endpoint = stack.datagram_bind(grant).unwrap();
            let stream_error = match native_error {
                Error::LinkDown => stream::Error::LinkDown,
                Error::DeviceFailed => stream::Error::DeviceFailed,
                _ => stream::Error::LinkUnknown,
            };
            if family6 {
                let other = stack
                    .ipv6_stream_grant(ipv6::stream::Grant {
                        local_port: 7300,
                        peer: grant6().peer,
                        connect_timeout_ms: 1000,
                        lifetime_ms: 5000,
                    })
                    .unwrap();
                state.borrow_mut().reading = fault;
                assert_eq!(stack.ipv6_stream_status(other), Err(stream_error));
                assert_eq!(stack.ipv6_stream_status(other), Err(stream::Error::Stale));
            } else {
                let other = stack
                    .stream_grant(stream::Grant {
                        local_port: 7300,
                        peer: grant.peer,
                        connect_timeout_ms: 1000,
                        lifetime_ms: 5000,
                    })
                    .unwrap();
                state.borrow_mut().reading = fault;
                assert_eq!(stack.stream_status(other), Err(stream_error));
                assert_eq!(stack.stream_status(other), Err(stream::Error::Stale));
            }
            assert_eq!(
                stack.datagram_send(endpoint, grant.peer, b"x"),
                Err(native_error)
            );
            assert_eq!(
                stack.datagram_send(endpoint, grant.peer, b"x"),
                Err(Error::Stale)
            );
            assert_eq!(stack.socket_count(), 0);
        }
    }
}

#[test]
fn ipv6_clock_rewind_is_administrative_fence_not_a_retained_link_reason() {
    let (state, mut stack) = setup();
    configure6(&mut stack);
    stack.ipv6_bind(grant6()).unwrap();
    let grant = udp_grant(7002, 2, 40000);
    let endpoint = stack.datagram_bind(grant).unwrap();
    state.borrow_mut().now_ms = 0;
    state.borrow_mut().reading = None;
    stack.poll();
    assert_eq!(
        stack.datagram_send(endpoint, grant.peer, b"x"),
        Err(Error::Stale)
    );
    assert_eq!(stack.socket_count(), 0);
}

struct DuringPoll {
    reading: Option<LinkReading>,
    on_send: Option<Option<LinkReading>>,
    sent: Vec<Vec<u8>>,
    now: u64,
}
struct DuringPollLink(Rc<RefCell<DuringPoll>>);
impl Link for DuringPollLink {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 10]
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        let mut state = self.0.borrow_mut();
        state.sent.push(frame.to_vec());
        if let Some(reading) = state.on_send.take() {
            state.reading = reading;
        }
        Ok(())
    }
    fn receive(&mut self, _: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(None)
    }
    fn now_ms(&self) -> u64 {
        self.0.borrow().now
    }
    fn pause(&self, ms: u64) {
        self.0.borrow_mut().now += ms;
    }
    fn read(&self) -> Option<LinkReading> {
        self.0.borrow().reading
    }
}

#[test]
fn fault_during_actual_arp_emission_is_observed_by_post_poll_check_and_discards_queue() {
    for (fault, error) in faults() {
        let state = Rc::new(RefCell::new(DuringPoll {
            reading: reading(true, false, 0),
            on_send: Some(fault),
            sent: Vec::new(),
            now: 1,
        }));
        let mut stack = Stack::open(DuringPollLink(state.clone()), dead_config()).unwrap();
        let grant = udp_grant(7002, 2, 40000);
        let endpoint = stack.datagram_bind(grant).unwrap();
        stack
            .datagram_send(endpoint, grant.peer, b"queued-before-fault")
            .unwrap();
        stack.poll();
        assert_eq!(state.borrow().sent.len(), 1);
        assert_eq!(&state.borrow().sent[0][12..14], &[0x08, 0x06]);
        assert_eq!(stack.socket_count(), 0);
        state.borrow_mut().reading = reading(true, false, 0);
        for _ in 0..4 {
            state.borrow_mut().now += 1000;
            stack.poll();
        }
        assert_eq!(
            state.borrow().sent.len(),
            1,
            "retired queued UDP must not resume"
        );
        assert_eq!(stack.datagram_send(endpoint, grant.peer, b"x"), Err(error));
        assert_eq!(
            stack.datagram_send(endpoint, grant.peer, b"x"),
            Err(Error::Stale)
        );
    }
}
