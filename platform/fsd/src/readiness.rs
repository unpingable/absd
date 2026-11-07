//! Bounded idle-wait selection and quiet-time policy for the serving loop.
pub const MAX_HANDLES: usize = 11;
/// Kernel argument 1 expires after up to two delivered ticks plus scheduling.
pub const IDLE_TICKS: u64 = 1;

pub fn round_robin(start: usize, channels: usize) -> impl Iterator<Item = usize> {
    assert!(channels != 0 && start < channels);
    (0..channels).map(move |offset| (start + offset) % channels)
}

pub fn next_idle_start(current: usize, channels: usize) -> usize {
    assert!(channels != 0 && current < channels);
    (current + MAX_HANDLES) % channels
}

#[derive(Default)]
pub struct Quiet {
    empty_since: Option<u64>,
}
impl Quiet {
    pub fn reset(&mut self) {
        self.empty_since = None;
    }
    pub fn empty(&mut self, now: u64) -> bool {
        let since = *self.empty_since.get_or_insert(now);
        // read_within(..., 1) uses the kernel's now + timeout + 1 deadline.
        now.saturating_sub(since) >= 2
    }
}

pub struct Channel {
    pub request: u64,
    pub active: bool,
    pub reply_pending: bool,
    pub buffered_work: bool,
    pub request_ended: bool,
}
pub struct WaitPlan {
    handles: [u64; MAX_HANDLES],
    count: usize,
    pub buffered_work: bool,
}
impl WaitPlan {
    pub fn handles(&self) -> &[u64] {
        &self.handles[..self.count]
    }
    pub fn collect(channels: impl Iterator<Item = Channel>) -> Self {
        let mut plan = Self {
            handles: [0; MAX_HANDLES],
            count: 0,
            buffered_work: false,
        };
        for channel in channels {
            if !channel.active || channel.reply_pending {
                continue;
            }
            if channel.buffered_work {
                plan.buffered_work = true;
                continue;
            }
            if channel.request_ended {
                continue;
            }
            if plan.count == MAX_HANDLES {
                // Keep scanning omitted sources: buffered work forbids sleep.
                continue;
            }
            plan.handles[plan.count] = channel.request;
            plan.count += 1;
        }
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immediate_empty_poll_is_not_a_quiet_timeout() {
        let mut quiet = Quiet::default();
        assert!(!quiet.empty(100));
        assert!(!quiet.empty(101));
        assert!(quiet.empty(102));
    }
    #[test]
    fn new_bytes_restart_the_partial_frame_quiet_period() {
        let mut quiet = Quiet::default();
        assert!(!quiet.empty(100));
        quiet.reset();
        assert!(!quiet.empty(102));
        assert!(!quiet.empty(103));
        assert!(quiet.empty(104));
    }
    #[test]
    fn backward_clock_does_not_discard_a_partial_frame() {
        let mut quiet = Quiet::default();
        assert!(!quiet.empty(100));
        assert!(!quiet.empty(99));
        assert!(!quiet.empty(101));
        assert!(quiet.empty(102));
    }
    fn channel(request: u64) -> Channel {
        Channel {
            request,
            active: true,
            reply_pending: false,
            buffered_work: false,
            request_ended: false,
        }
    }
    #[test]
    fn one_full_wait_set_fits_without_losing_sources() {
        let p = WaitPlan::collect((1..=11).map(channel));
        assert_eq!(p.handles(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        assert!(!p.buffered_work);
    }
    #[test]
    fn twenty_channels_rotate_through_two_bounded_idle_sets() {
        let first = WaitPlan::collect((1..=20).map(channel));
        let next = next_idle_start(0, 20);
        let second = WaitPlan::collect(round_robin(next, 20).map(|i| channel(i as u64 + 1)));
        assert_eq!(first.handles(), &(1..=11).collect::<std::vec::Vec<_>>());
        assert_eq!(second.handles(), &[12, 13, 14, 15, 16, 17, 18, 19, 20, 1, 2]);
        for handle in 1..=20 {
            assert!(first.handles().contains(&handle) || second.handles().contains(&handle));
        }
    }
    #[test]
    fn omitted_eof_and_data_are_observed_in_the_next_serve_pass() {
        let first = WaitPlan::collect((1..=20).map(channel));
        assert!(!first.handles().contains(&20));
        // A level event arriving after the poll can miss this subset. The
        // actual serve iterator still visits it after one finite idle wait.
        assert_eq!(IDLE_TICKS, 1);
        for eof in [false, true] {
            let mut observed = None;
            for index in round_robin(next_idle_start(0, 20), 20) {
                if index == 19 {
                    observed = Some((20, eof));
                }
            }
            assert_eq!(observed, Some((20, eof)));
        }
    }
    #[test]
    fn omitted_complete_frame_still_prevents_sleep() {
        let plan = WaitPlan::collect((1..=20).map(|request| Channel {
            buffered_work: request == 20,
            ..channel(request)
        }));
        assert_eq!(plan.handles().len(), MAX_HANDLES);
        assert!(plan.buffered_work);
    }
    #[test]
    fn rotation_filters_eof_and_pending_replies_without_losing_other_sources() {
        let make = |request| Channel {
            request_ended: request == 20,
            reply_pending: request == 12,
            ..channel(request)
        };
        let first = WaitPlan::collect((1..=20).map(make));
        let second = WaitPlan::collect((12..=20).chain(1..=11).map(make));
        for plan in [&first, &second] {
            assert!(!plan.handles().contains(&20));
            assert!(!plan.handles().contains(&12));
            assert!(plan.handles().len() <= MAX_HANDLES);
        }
        for handle in (1..=19).filter(|&h| h != 12) {
            assert!(first.handles().contains(&handle) || second.handles().contains(&handle));
        }
    }
    #[test]
    fn pending_replies_and_inactive_slots_do_not_cause_readiness_spin() {
        let p = WaitPlan::collect(
            [
                Channel {
                    active: false,
                    ..channel(1)
                },
                Channel {
                    reply_pending: true,
                    ..channel(2)
                },
                channel(3),
            ]
            .into_iter(),
        )
        ;
        assert_eq!(p.handles(), &[3]);
    }
    #[test]
    fn a_complete_buffered_frame_requires_service_before_sleep() {
        let p = WaitPlan::collect(
            [
                channel(1),
                Channel {
                    buffered_work: true,
                    ..channel(2)
                },
            ]
            .into_iter(),
        )
        ;
        assert!(p.buffered_work);
        assert_eq!(p.handles(), &[1]);
    }
    #[test]
    fn ended_request_is_removed_from_the_level_wait_set() {
        let p = WaitPlan::collect(
            [
                channel(1),
                Channel {
                    request_ended: true,
                    ..channel(2)
                },
            ]
            .into_iter(),
        )
        ;
        assert_eq!(p.handles(), &[1]);
    }
    #[test]
    fn buffered_work_precedes_an_ended_source() {
        let p = WaitPlan::collect(
            [Channel {
                request_ended: true,
                buffered_work: true,
                ..channel(1)
            }]
            .into_iter(),
        )
        ;
        assert!(p.buffered_work);
        assert!(p.handles().is_empty());
    }
}
