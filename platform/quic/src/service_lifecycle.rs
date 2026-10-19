//! Polling policy for the private, single-grant fixture parent.
//! This observes existing authority; it never constructs or renews a grant.

use absd_net::{Link, Stack, datagram::channel::Channel};

pub trait LiveGrant {
    fn live(&self) -> bool;
}
impl LiveGrant for Channel {
    fn live(&self) -> bool {
        Channel::live(self)
    }
}
impl LiveGrant for absd_net::ipv6::channel::Channel {
    fn live(&self) -> bool {
        absd_net::ipv6::channel::Channel::live(self)
    }
}

fn usable<L: Link, C: LiveGrant>(stack: &Stack<L>, channel: &C, queue_held: bool) -> bool {
    !queue_held && channel.live() && stack.socket_count() != 0
}

/// Enter network processing only while this parent still owns a live socket.
pub fn poll_if_granted<L: Link, C: LiveGrant>(
    stack: &mut Stack<L>,
    channel: &C,
    queue_held: bool,
) -> bool {
    if !usable(stack, channel, queue_held) {
        return false;
    }
    stack.poll();
    true
}

/// A parent reaping its consumer must sleep locally once authority is gone.
pub fn wait_if_granted<L: Link, C: LiveGrant>(
    stack: &mut Stack<L>,
    channel: &C,
    queue_held: bool,
    max_ms: u64,
) -> bool {
    if !usable(stack, channel, queue_held) {
        return false;
    }
    stack.wait(max_ms);
    true
}

/// Local retirement discards socket queues without another network turn.
pub fn fence<L: Link>(stack: &mut Stack<L>) {
    stack.datagram_fence();
    stack.stream_fence();
    stack.ipv6_fence();
}

#[cfg(test)]
mod tests {
    use super::*;
    use absd_net::{Config, FRAME_MAX, datagram as d};
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    #[derive(Default)]
    struct Wire {
        incoming: VecDeque<Vec<u8>>,
        receives: usize,
        sends: usize,
        now: u64,
    }
    struct End(Rc<RefCell<Wire>>);
    impl Link for End {
        fn mac(&self) -> [u8; 6] {
            [0x52, 0x54, 0, 0x12, 0x34, 0x56]
        }
        fn send(&mut self, _: &[u8]) -> Result<(), i64> {
            self.0.borrow_mut().sends += 1;
            Ok(())
        }
        fn receive(&mut self, out: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
            let mut wire = self.0.borrow_mut();
            wire.receives += 1;
            Ok(wire.incoming.pop_front().map(|frame| {
                out[..frame.len()].copy_from_slice(&frame);
                frame.len()
            }))
        }
        fn now_ms(&self) -> u64 {
            self.0.borrow().now
        }
        fn pause(&self, ms: u64) {
            self.0.borrow_mut().now += ms;
        }
    }

    // A checksum-valid literal Linux UDP4443 -> native7807 frame, also used
    // by the independent Python classifier controls. No packet builder is used.
    fn pending_datagram(wire: &Rc<RefCell<Wire>>) {
        let hex = "52540012345602710000000208004500002500014000401122b70a0002020a00020f115b1e7f0011e11e717569632d77697265000000000000000000";
        let frame = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        wire.borrow_mut().incoming.push_back(frame);
    }
    fn granted() -> (Rc<RefCell<Wire>>, Stack<End>, Channel) {
        let wire = Rc::new(RefCell::new(Wire {
            now: 1,
            ..Wire::default()
        }));
        let mut stack = Stack::open(End(wire.clone()), Config::qemu_user()).unwrap();
        let channel = Channel::grant(
            &mut stack,
            d::Grant {
                local_port: 7807,
                peer: crate::PEER,
            },
        )
        .unwrap();
        (wire, stack, channel)
    }
    fn assert_quiet(
        wire: &Rc<RefCell<Wire>>,
        stack: &mut Stack<End>,
        channel: &Channel,
        held: bool,
    ) {
        pending_datagram(wire);
        let before = (wire.borrow().receives, wire.borrow().sends);
        assert!(!poll_if_granted(stack, channel, held));
        assert!(!wait_if_granted(stack, channel, held, 1));
        assert_eq!((wire.borrow().receives, wire.borrow().sends), before);
        assert_eq!(wire.borrow().incoming.len(), 1);
    }

    struct LocalPipe {
        input: VecDeque<u8>,
        output: Vec<u8>,
        eof: bool,
    }
    impl d::channel::Pipe for LocalPipe {
        fn now_ms(&self) -> u64 {
            1
        }
        fn read(&mut self, out: &mut [u8]) -> Result<Option<usize>, i64> {
            if self.input.is_empty() {
                return Ok(if self.eof { Some(0) } else { None });
            }
            let count = out.len().min(self.input.len());
            for byte in &mut out[..count] {
                *byte = self.input.pop_front().unwrap();
            }
            Ok(Some(count))
        }
        fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
            self.output.extend_from_slice(bytes);
            Ok(Some(bytes.len()))
        }
    }

    #[test]
    fn active_grant_poll_and_wait_reach_actual_link() {
        let (wire, mut stack, channel) = granted();
        pending_datagram(&wire);
        assert!(poll_if_granted(&mut stack, &channel, false));
        assert!(wire.borrow().incoming.is_empty());
        let received = wire.borrow().receives;
        assert!(received > 0);
        assert!(wait_if_granted(&mut stack, &channel, false, 1));
        assert!(wire.borrow().receives > received);
    }
    #[test]
    fn close_request_leaves_live_channel_but_no_network_socket() {
        let (wire, mut stack, mut channel) = granted();
        let mut request = vec![0, 12, d::VERSION, d::CLOSE];
        request.resize(14, 0);
        let mut pipe = LocalPipe {
            input: request.into(),
            output: Vec::new(),
            eof: false,
        };
        for _ in 0..4 {
            assert!(channel.poll(&mut stack, &mut pipe));
        }
        assert_eq!(pipe.output.len(), 14);
        assert_eq!(pipe.output[4], 0); // Complete successful CLOSE reply.
        assert!(channel.live());
        assert_eq!(stack.socket_count(), 0);
        assert_quiet(&wire, &mut stack, &channel, false);
    }
    #[test]
    fn observed_pipe_eof_prevents_further_network_turns() {
        let (wire, mut stack, mut channel) = granted();
        let mut pipe = LocalPipe {
            input: VecDeque::new(),
            output: Vec::new(),
            eof: true,
        };
        assert!(!channel.poll(&mut stack, &mut pipe));
        assert!(!channel.live());
        assert_quiet(&wire, &mut stack, &channel, false);
    }
    #[test]
    fn owner_revocation_prevents_further_network_turns() {
        let (wire, mut stack, mut channel) = granted();
        channel.revoke(&mut stack);
        assert_quiet(&wire, &mut stack, &channel, false);
    }
    #[test]
    fn held_queue_keeps_actual_pending_frame_untouched() {
        let (wire, mut stack, channel) = granted();
        assert_eq!(stack.socket_count(), 1);
        assert_quiet(&wire, &mut stack, &channel, true);
    }
    #[test]
    fn final_fence_removes_socket_without_consuming_pending_frame() {
        let (wire, mut stack, channel) = granted();
        pending_datagram(&wire);
        let before = (wire.borrow().receives, wire.borrow().sends);
        fence(&mut stack);
        assert_eq!(stack.socket_count(), 0);
        assert_eq!((wire.borrow().receives, wire.borrow().sends), before);
        assert_eq!(wire.borrow().incoming.len(), 1);
        assert!(!poll_if_granted(&mut stack, &channel, false));
        assert!(!wait_if_granted(&mut stack, &channel, false, 1));
        assert_eq!((wire.borrow().receives, wire.borrow().sends), before);
    }
    #[test]
    fn final_fence_also_retires_ipv6_without_a_network_turn() {
        use absd_net::ipv6 as v6;
        let (wire, mut stack, _) = granted();
        let mut local = [0; 16];
        local[0] = 0xfd;
        local[15] = 1;
        let mut remote = local;
        remote[15] = 2;
        stack
            .configure_ipv6(v6::Config {
                address: local,
                prefix_len: 64,
                scope: 7,
            })
            .unwrap();
        let endpoint = stack
            .ipv6_bind(v6::Grant {
                local_port: 7002,
                peer: v6::Address {
                    ip: remote,
                    port: 42010,
                    scope: 7,
                },
            })
            .unwrap();
        assert_eq!(stack.socket_count(), 2);
        pending_datagram(&wire);
        let before = (wire.borrow().receives, wire.borrow().sends);
        fence(&mut stack);
        assert_eq!(stack.socket_count(), 0);
        assert_eq!(stack.ipv6_close(endpoint), Err(v6::Error::Stale));
        assert_eq!((wire.borrow().receives, wire.borrow().sends), before);
        assert_eq!(wire.borrow().incoming.len(), 1);
    }
    #[test]
    fn unconditional_poll_after_revoke_consumes_pending_frame_calibration() {
        let (wire, mut stack, mut channel) = granted();
        channel.revoke(&mut stack);
        pending_datagram(&wire);
        stack.poll();
        assert!(wire.borrow().receives > 0);
        assert!(wire.borrow().incoming.is_empty());
    }

    #[test]
    fn ipv6_actual_close_reply_prevents_later_network_turns() {
        use absd_net::ipv6 as v6;
        let (wire, mut stack, mut old) = granted();
        old.revoke(&mut stack);
        stack
            .configure_ipv6(v6::Config {
                address: crate::fixture_family::IPV6_LOCAL,
                prefix_len: 64,
                scope: 1,
            })
            .unwrap();
        let mut channel = v6::channel::Channel::grant(
            &mut stack,
            v6::Grant {
                local_port: 7800,
                peer: crate::fixture_family::IPV6_PEER,
            },
        )
        .unwrap();
        assert!(poll_if_granted(&mut stack, &channel, false));
        let mut request = vec![0, 28, 2, d::CLOSE, 0, 6];
        request.resize(30, 0);
        let mut pipe = LocalPipe {
            input: request.into(),
            output: Vec::new(),
            eof: false,
        };
        for _ in 0..4 {
            assert!(channel.poll(&mut stack, &mut pipe));
        }
        assert_eq!(pipe.output, {
            let mut reply = vec![0, 28, 2, d::CLOSE, 0, 6];
            reply.resize(30, 0);
            reply
        });
        assert!(channel.live());
        assert_eq!(stack.socket_count(), 0);
        pending_datagram(&wire);
        let before = (wire.borrow().receives, wire.borrow().sends);
        assert!(!poll_if_granted(&mut stack, &channel, false));
        assert!(!wait_if_granted(&mut stack, &channel, false, 1));
        assert_eq!((wire.borrow().receives, wire.borrow().sends), before);
        assert_eq!(wire.borrow().incoming.len(), 1);
    }
}
