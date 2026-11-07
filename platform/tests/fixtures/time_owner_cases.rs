#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GRANT, NOW, REQUESTS, SAMPLE};
    use std::sync::atomic::Ordering::Relaxed;
    #[test]
    fn paired_rtc_floor_matches_actual_sntp_window() {
        assert_eq!(
            absd_net::sntp::MIN_UNIX,
            absd_runtime::civil_clock::MIN_RTC_UNIX_SECONDS
        );
    }
    struct Link;
    impl absd_net::Link for Link {
        fn mac(&self) -> [u8; 6] {
            [2, 0, 0, 0, 0, 15]
        }
        fn send(&mut self, _: &[u8]) -> Result<(), i64> {
            Ok(())
        }
        fn receive(
            &mut self,
            _: &mut [u8; absd_net::FRAME_MAX],
            _: u64,
        ) -> Result<Option<usize>, i64> {
            Ok(None)
        }
        fn now_ms(&self) -> u64 {
            crate::boot_millis()
        }
        fn pause(&self, _: u64) {}
    }
    #[test]
    fn real_service_rearms_on_carrier_rise_and_preserves_manual_cancellation() {
        NOW.store(0, Relaxed);
        GRANT.store(1, Relaxed);
        REQUESTS.lock().unwrap().clear();
        *SAMPLE.lock().unwrap() = None;
        let config = crate::etc::Time {
            enabled: true,
            server: Some([10, 0, 2, 2]),
            ..crate::etc::Time::DEFAULT
        };
        let mut stack = Stack::open(Link, absd_net::Config::qemu_user()).unwrap();
        let mut service = Service::new(config);
        service.poll(&mut stack, false);
        assert!(!service.poller.active());
        assert_eq!(REQUESTS.lock().unwrap().len(), 1);
        NOW.store(1200, Relaxed);
        service.poll(&mut stack, true);
        assert!(
            service.poller.active(),
            "carrier recovered, but actual Service delayed bootstrap for a full interval"
        );
        assert!(service.endpoint.is_some());
        // Manual assertion cancels the live poll and does not immediately
        // restart automatic work at a simultaneously observed carrier rise.
        operator("set 1700000000").unwrap();
        service.poll(&mut stack, true);
        assert!(!service.poller.active());
        assert!(service.endpoint.is_none());
        assert!(service.pending.is_none());
        let manual_next = service.next;
        NOW.store(1300, Relaxed);
        service.poll(&mut stack, true);
        assert_eq!(service.next, manual_next);
        assert!(!service.poller.active());
        // A later explicit request starts one bounded poll. Carrier loss
        // retires its endpoint, then a new rise re-arms immediately.
        operator("sync").unwrap();
        service.poll(&mut stack, true);
        assert!(service.poller.active());
        service.poll(&mut stack, false);
        assert!(!service.poller.active());
        assert!(service.endpoint.is_none());
        NOW.store(1500, Relaxed);
        service.poll(&mut stack, true);
        assert!(service.poller.active());
        service.poll(&mut stack, false);
        operator("set 1700000100").unwrap();
        service.poll(&mut stack, true);
        assert!(
            !service.poller.active(),
            "carrier rise overrode the fresh manual assertion"
        );
        assert!(service.endpoint.is_none());
        // A manual assertion while carrier remains down must also keep
        // the next rise from immediately restarting automatic work.
        operator("sync").unwrap();
        service.poll(&mut stack, true);
        service.poll(&mut stack, false);
        operator("set 1700000200").unwrap();
        service.poll(&mut stack, false);
        service.poll(&mut stack, true);
        assert!(
            !service.poller.active(),
            "later carrier rise undid manual cancellation"
        );
        // Missing authority cannot admit any provider or sync request.
        GRANT.store(0, Relaxed);
        let mut unavailable = Service::new(config);
        unavailable.poll(&mut stack, true);
        assert!(!unavailable.poller.active());
        assert!(operator("sync").is_err());
        GRANT.store(1, Relaxed);
    }

    struct Wire {
        queues: [std::collections::VecDeque<Vec<u8>>; 2],
    }
    struct Node {
        wire: std::rc::Rc<std::cell::RefCell<Wire>>,
        side: usize,
    }
    impl absd_net::Link for Node {
        fn mac(&self) -> [u8; 6] {
            [2, 0, 0, 0, 0, 15 + self.side as u8]
        }
        fn send(&mut self, bytes: &[u8]) -> Result<(), i64> {
            self.wire.borrow_mut().queues[1 - self.side].push_back(bytes.to_vec());
            Ok(())
        }
        fn receive(
            &mut self,
            out: &mut [u8; absd_net::FRAME_MAX],
            _: u64,
        ) -> Result<Option<usize>, i64> {
            Ok(self.wire.borrow_mut().queues[self.side]
                .pop_front()
                .map(|bytes| {
                    out[..bytes.len()].copy_from_slice(&bytes);
                    bytes.len()
                }))
        }
        fn now_ms(&self) -> u64 {
            crate::boot_millis()
        }
        fn pause(&self, _: u64) {}
    }
    fn exercise(
        initial: Option<(u64, u32)>,
        rise: u64,
        ready: u64,
        duration: u64,
        refusal: Option<u8>,
    ) -> (Option<u64>, usize) {
        NOW.store(0, Relaxed);
        GRANT.store(1, Relaxed);
        *SAMPLE.lock().unwrap() = initial;
        crate::GENERATION.store(u64::from(initial.is_some()), Relaxed);
        REQUESTS.lock().unwrap().clear();
        let wire = std::rc::Rc::new(std::cell::RefCell::new(Wire {
            queues: Default::default(),
        }));
        let mut peer_config = absd_net::Config::qemu_user();
        peer_config.address = [10, 0, 2, 2].into();
        peer_config.gateway = None;
        let mut peer = Stack::open(
            Node {
                wire: wire.clone(),
                side: 1,
            },
            peer_config,
        )
        .unwrap();
        let mut client =
            Stack::open(Node { wire, side: 0 }, absd_net::Config::qemu_user()).unwrap();
        let endpoint = peer
            .datagram_bind(Grant {
                local_port: 12300,
                peer: Address {
                    ip: [10, 0, 2, 15],
                    port: 49123,
                },
            })
            .unwrap();
        let config = crate::etc::Time {
            enabled: true,
            server: Some([10, 0, 2, 2]),
            server_port: 12300,
            ..crate::etc::Time::DEFAULT
        };
        let mut service = Service::new(config);

        let mut accepted = None;
        let mut snapshots = 0;
        let mut queries = 0;
        for elapsed in (0..duration).step_by(10) {
            NOW.store(elapsed, Relaxed);
            client.poll();
            peer.poll();
            service.poll(&mut client, elapsed >= rise);
            let mut request = [0u8; 48];
            match peer.datagram_receive(endpoint, &mut request) {
                Ok((48, _)) => {
                    queries += 1;
                    if elapsed < ready {
                        continue;
                    }
                    let mut reply = [0u8; 48];
                    reply[0] = 0x24;
                    reply[1] = refusal.unwrap_or(10);
                    let ntp = |seconds: u64, fraction: u32| {
                        (((seconds + 2_208_988_800) << 32) | u64::from(fraction)).to_be_bytes()
                    };
                    reply[16..24].copy_from_slice(&ntp(1_799_999_999, 0));
                    reply[24..32].copy_from_slice(&request[40..48]);
                    reply[32..40].copy_from_slice(&ntp(1_800_000_000, 1));
                    reply[40..48].copy_from_slice(&ntp(1_800_000_000, 2));
                    peer.datagram_send(
                        endpoint,
                        Address {
                            ip: [10, 0, 2, 15],
                            port: 49123,
                        },
                        &reply,
                    )
                    .unwrap();
                }
                Err(datagram::Error::Again) => {}
                other => panic!("unexpected fixture receive {other:?}"),
            }
            let info = crate::civil_clock::info().unwrap();
            let status = info.status(Err(-5)).to_string();
            snapshots += 1;
            assert!(status.contains("source="));
            if info.source == crate::civil_clock::SNTP_UNAUTHENTICATED {
                let ns = info.unix_ns.unwrap();
                assert_eq!(ns / 1_000_000_000, 1_800_000_000);
                accepted = Some(elapsed);
                break;
            }
        }
        if let Some(elapsed) = accepted {
            assert_eq!(
                service.next,
                elapsed + config.interval_seconds * 1000,
                "successful sample must restore configured interval"
            );
            assert!(snapshots > 0);
            println!(
                "ACTUAL SERVICE RECOVERY elapsed_ms={elapsed} ready_ms={ready} queries={queries} status_snapshots={snapshots}"
            );
        }
        (accepted, queries)
    }
    fn acquire(initial: Option<(u64, u32)>, rise: u64, ready: u64) -> u64 {
        let (accepted, _) = exercise(initial, rise, ready, ready + 10_000, None);
        accepted.expect("actual Service failed declared controlled recovery case")
    }
    #[test]
    fn actual_service_waits_for_carrier_without_repeated_failure_records() {
        NOW.store(0, Relaxed);
        GRANT.store(1, Relaxed);
        REQUESTS.lock().unwrap().clear();
        crate::NOTES.lock().unwrap().clear();
        *SAMPLE.lock().unwrap() = None;
        let config = crate::etc::Time {
            enabled: true,
            server: Some([10, 0, 2, 2]),
            ..crate::etc::Time::DEFAULT
        };
        let mut stack = Stack::open(Link, absd_net::Config::qemu_user()).unwrap();
        let mut service = Service::new(config);
        for now in (0..3_600_000).step_by(100) {
            NOW.store(now, Relaxed);
            service.poll(&mut stack, false);
            assert!(!service.poller.active());
            assert!(service.endpoint.is_none());
        }
        assert!(
            REQUESTS.lock().unwrap().len() <= 1,
            "carrier wait flooded Clock failure records"
        );
        assert!(
            crate::NOTES.lock().unwrap().len() <= 3,
            "carrier wait flooded operator history"
        );
        NOW.store(3_600_000, Relaxed);
        service.poll(&mut stack, true);
        assert!(
            service.poller.active(),
            "carrier recovery did not rearm immediately"
        );
    }
    #[test]
    fn actual_service_honours_real_peer_kod_and_stratum_refusals() {
        for stratum in [0, 16] {
            crate::NOTES.lock().unwrap().clear();
            let (accepted, queries) = exercise(None, 0, 0, 3_600_000, Some(stratum));
            assert!(accepted.is_none());
            assert!(
                queries <= 1,
                "peer refusal was queried {queries} times instead of the normal interval"
            );
            assert!(
                crate::NOTES.lock().unwrap().len() <= 3,
                "peer refusal flooded operator history"
            );
        }
    }
    #[test]
    fn actual_service_timeout_retries_are_capped_and_summarized() {
        crate::NOTES.lock().unwrap().clear();
        let (accepted, queries) = exercise(None, 0, u64::MAX, 3_600_000, None);
        assert!(accepted.is_none());
        assert!(
            queries <= 60,
            "silent peer received {queries} requests in one hour"
        );
        assert!(REQUESTS.lock().unwrap().len() <= 20);
        assert!(crate::NOTES.lock().unwrap().len() <= 20);
        let config = crate::etc::Time {
            enabled: true,
            interval_seconds: 60,
            server: Some([10, 0, 2, 2]),
            ..crate::etc::Time::DEFAULT
        };
        let mut stack = Stack::open(Link, absd_net::Config::qemu_user()).unwrap();
        let mut service = Service::new(config);
        let mut now = 0;
        for pause in [1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000] {
            NOW.store(now, Relaxed);
            service.fail(&mut stack, now, -110, "fixture timeout", Retry::Timeout);
            assert_eq!(service.next - now, pause);
            now = service.next;
        }
        service.reset_retry();
        service.fail(&mut stack, now, -110, "fixture timeout", Retry::Timeout);
        assert_eq!(service.next - now, 1000);
    }
    #[test]
    fn actual_service_acquires_unknown_time_through_real_stacks_after_carrier_returns() {
        assert!(acquire(None, 1200, 1200) <= 11_200);
    }
    #[test]
    fn actual_service_retries_unknown_clock_after_initial_peer_silence() {
        acquire(None, 0, 10_000);
        acquire(None, 5000, 17_000);
    }
    #[test]
    fn actual_service_replaces_valid_rtc_anchor_before_applying_step_bound() {
        acquire(
            Some((1_767_225_600_000_000_000, crate::civil_clock::RTC)),
            0,
            0,
        );
    }
}
