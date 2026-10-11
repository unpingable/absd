#![allow(unused_variables, unused_imports)]
//! Research instrumentation is disabled on ARM UP. These hooks grant no SMP capability.
use absd_kernel::memory::FrameAllocator;
use absd_kernel::process::{CpuClaim, Process};
pub mod ap {
    use super::*;
    #[derive(Clone, Copy)]
    pub struct StopToken {
        pub slot: usize,
        pub pid: u64,
        pub claim: CpuClaim,
    }
    pub fn complete_drain(token: StopToken) {}
    pub fn poll_departed() -> Option<StopToken> {
        Default::default()
    }
}
pub mod modern_smp {
    use super::*;
    pub fn before_stop(p: &Process) {}
    pub fn claimed(slot: usize, claim: CpuClaim, process: &Process) {}
    pub fn departed(slot: usize, claim: CpuClaim) {}
    pub fn enabled() -> bool {
        Default::default()
    }
    pub fn mutate_publication(process: &Process) {}
    pub fn publish(process: &Process) {}
    pub fn register(slot: usize, process: &Process, cpu: u8) {}
    pub fn remove(slot: usize) {}
    pub fn select(current: usize, cpu: u8, allow_steal: bool) -> Option<usize> {
        Default::default()
    }
}
pub mod smp_app_pressure {
    use super::*;
    pub fn bsp_after_release(slot: usize, p: &Process) {}
    pub fn bsp_before_remove(slot: usize, p: &Process) {}
    pub fn bsp_mode() -> bool {
        Default::default()
    }
    pub fn bsp_occupied(occupied: usize) {}
    pub fn check_terminal_frames(p: &Process, frames: &absd_kernel::memory::FrameAllocator) {}
    pub fn omit_refusal(site: u64) -> bool {
        Default::default()
    }
    pub fn refusal(site: u64) {}
    pub fn refusal_entry(pid: u64, program: usize, number: u64) {}
    pub fn role(role: u64) -> bool {
        Default::default()
    }
    pub fn saved(slot: usize, p: &Process, preempted: bool) {}
    pub fn startup_mode() -> bool {
        Default::default()
    }
}
pub mod smp_app_scale {
    use super::*;
    pub fn activated(slot: usize, p: &Process) {}
    pub fn before_remove(slot: usize, p: &Process) {}
    pub fn reclaimed(p: &Process) {}
    pub fn saved(slot: usize, p: &Process, preempted: bool) {}
}
pub mod smp_bench {
    use super::*;
    pub fn dispatch() {}
    pub fn preempt() {}
}
pub mod smp_fixture {
    use super::*;
    pub fn after_publication(current: usize, child: u64) {}
    pub fn on_bsp_spawner_departed(token: ap::StopToken) {}
    pub fn on_drain(token: ap::StopToken) {}
    pub fn prepublication_gap(current: usize, child: u64, handle: u64) {}
    pub fn record_remote_request(token: ap::StopToken) {}
}
pub mod smp_fpu {
    use super::*;
    pub fn restore_negative(p: &Process) {}
    pub fn saved(slot: usize, p: &Process, preempted: bool) {}
    pub fn skip_restore(p: &Process) -> bool {
        Default::default()
    }
}
pub mod smp_leaf_measure {
    use super::*;
    pub const FROM_USER: u64 = 0;
    pub const READ: u64 = 0;
    pub const STATUS: u64 = 0;
    pub const TO_USER: u64 = 0;
    pub const WAKE: u64 = 0;
    pub const WRITE: u64 = 0;
    pub struct Scope;
    impl Scope {
        pub fn begin(_: u64) -> Self {
            Self
        }
        pub fn end(self) {}
        pub fn finish(self, _: usize) {}
    }
}
pub mod smp_measure {
    use super::*;
    pub const FAULT: usize = 0;
    pub const TIMER: usize = 1;
    pub fn syscall(number: u64) {}
    pub fn tag(path: usize) {}
}

pub mod smp_startup {
    use super::*;
    pub fn active() -> bool {
        Default::default()
    }
}
pub mod smp_timer {
    use super::*;
    pub fn enabled() -> bool {
        Default::default()
    }
    pub fn reset_quantum() {}
    pub fn restore_negative() {}
    pub fn switched(from: u64, to: u64) {}
}

// Shared semantic hooks delegate to explicit qualification mechanisms.
pub mod smp_nway {
    use super::*;
    pub fn requires_running_stop(caller: usize, slot: usize) -> bool {
        crate::smp::requires_running_stop(caller, slot)
    }
    pub fn restore_negative(_: usize, _: &Process) {}
    pub fn saved(_: usize, _: &Process, _: bool) {}
}
pub mod smp_user {
    use super::*;
    pub fn enabled() -> bool {
        crate::smp::enabled()
    }
    pub fn next_runnable(current: usize, cpu: u8) -> Option<usize> {
        crate::smp::next_runnable(current, cpu)
    }
    pub fn assert_selection(slot: usize) {
        crate::smp::assert_selection(slot);
    }
    pub fn prepare_process(slot: usize, p: &mut Process) {
        crate::smp::prepare_process(slot, p);
    }
    pub fn initial_placement(_: usize, _: &Process) -> u8 {
        0
    }
    pub fn notify_runnable() {
        crate::smp::notify_runnable();
    }
    pub fn notify_process(p: &Process) {
        crate::smp::notify_process(p);
    }
    pub fn idle_wait() {
        crate::smp::idle_wait();
    }
    pub fn departure(slot: usize, claim: CpuClaim) {
        crate::smp::departure(slot, claim);
    }
    pub fn reclaimed(slot: usize, pid: u64, claim: CpuClaim) {
        crate::smp::reclaimed(slot, pid, claim);
    }
    pub fn calls_on(_: usize) -> u64 {
        0
    }
    pub fn block_gap() {}
    pub fn blocked_frame(_: &Process) {}
    pub fn commit_gap(_: u64) {}
    pub fn created_gap() {}
    pub fn restore_fixture_page(_: &Process) {}
    pub fn rt_fixture_first(_: u64, value: u64) -> u64 {
        value
    }
    pub fn syscall_entry(_: *mut u64, _: u64) {}
    pub fn test_call(_: u64, _: u64, _: u64) -> i64 {
        absd_kernel::syscall::ERROR_NOT_IMPLEMENTED
    }
}
