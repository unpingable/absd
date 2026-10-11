//! Process records, lifecycle states, and the fixed-capacity process table.
//!
//! Lifecycle: `Created` -> `Runnable` -> `Running` -> (`Waiting` ->
//! `Runnable`)* -> `Exited` | `Faulted` -> `Empty`. A `Created` entry is being
//! loaded in place and is never scheduled. A terminal entry has already
//! returned its frames; only PID, parent, and outcome remain until the parent
//! reaps it or, for kernel-owned processes, until the kernel releases it.

use crate::handle::HandleTable;
use crate::layout::{USER_STACK_BASE, USER_STACK_TOP};
use crate::memory::PAGE_SIZE;
use crate::object::{CellId, PipeId};
use crate::syscall::Outcome;

pub const MAX_PROCESSES: usize = 16;
pub const SAVED_FRAME_WORDS: usize = 20;
/// Page tables per user address space (2 MiB of address space each). This
/// bounds what a process can touch at once, not its windows (the image, the
/// stack reservation, and the 32 MiB heap could need 30 + 2 + 16): 32
/// covers a 6 MiB image, its stack, and a heap holding a multi-megabyte
/// file, which AG's pinned-file check reads whole. A page fault or `map`
/// that needs one more table fails as it did at the old bound of 8.
pub const MAX_USER_PAGE_TABLES: usize = 32;
/// Parent identifier for processes started directly by the kernel.
pub const KERNEL_PARENT: u64 = 0;
/// SysV permits leaf functions to use 128 bytes below RSP without moving it.
pub const USER_STACK_RED_ZONE: u64 = crate::arch::USER_RED_ZONE;

/// Exclusive execution ownership. A PID identifies a process for the boot;
/// the epoch distinguishes successive CPU claims of its same table slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuClaim {
    pub cpu: u8,
    pub epoch: u64,
}

/// A stop request is not permission to reclaim. Only `Departed` means that
/// the owning CPU has abandoned the task stack, CR3, TSS.RSP0 and handler
/// references. A terminal outcome is published after the single drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopState {
    Active,
    Requested,
    Observed,
    Departed,
}

/// Classifies the only fault eligible for stack growth and returns the page
/// to map. Growth is one page, directly below the mapped range, and
/// RSP must already be in that page or within one red zone above the fault.
pub fn stack_growth_page(
    error: u64,
    address: u64,
    user_rsp: u64,
    mapped_bottom: u64,
) -> Option<u64> {
    // Normalized translation, write, user fault. Refuse every other
    // class rather than turning protection, execute, or reserved-bit faults
    // into allocations.
    let fault = crate::arch::memory_fault(error);
    if fault.class != crate::arch::FaultClass::Translation
        || fault.access != crate::arch::Access::Write
        || !fault.from_user
        || mapped_bottom <= USER_STACK_BASE
        || mapped_bottom > USER_STACK_TOP
        || !mapped_bottom.is_multiple_of(PAGE_SIZE)
    {
        return None;
    }
    let page = mapped_bottom.checked_sub(PAGE_SIZE)?;
    let fault_page = address & !(PAGE_SIZE - 1);
    if page < USER_STACK_BASE
        || fault_page != page
        || user_rsp < page
        || user_rsp > address.saturating_add(USER_STACK_RED_ZONE)
    {
        return None;
    }
    Some(page)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Empty,
    /// Claimed a slot and PID; the loader is still building it in place.
    Created,
    Runnable,
    Running,
    /// Blocked on `wait_kind`; RT Waiting/Blocked/Exhausted is explicit in class.
    Waiting,
    Exited,
    Faulted,
    /// Ended by its parent's `kill` while runnable or blocked.
    Killed,
}

pub use crate::arch::{AddressSpace, FpuState, PageTableSlot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Task {
    pub tid: u64,
    pub fpu: FpuState,
    /// Lowest address of the contiguous kernel stack; zero once released.
    pub kernel_stack_base: u64,
    pub kernel_stack_top: u64,
    pub user_stack_top: u64,
    /// Lowest currently mapped page of the reserved grow-down user stack.
    pub user_stack_bottom: u64,
    pub context: crate::arch::ExecutionContext,
    pub context_valid: bool,
}

impl Task {
    pub const EMPTY: Self = Self {
        tid: 0,
        fpu: FpuState::INITIAL,
        kernel_stack_base: 0,
        kernel_stack_top: 0,
        user_stack_top: 0,
        user_stack_bottom: 0,
        context: crate::arch::EMPTY_CONTEXT,
        context_valid: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Process {
    pub pid: u64,
    pub parent: u64,
    pub program: usize,
    pub handles: HandleTable,
    pub address_space: AddressSpace,
    pub task: Task,
    pub state: ProcessState,
    pub exit_status: i32,
    pub fault_vector: u64,
    pub fault_address: u64,
    pub fault_error: u64,
    /// While `Waiting` for a child: the child PID awaited, or zero for any.
    pub wait_target: u64,
    /// While `Waiting` for a child: user address receiving the outcome.
    pub wait_record: u64,
    /// While `Waiting` for a cell: the cell and the version already seen.
    pub wait_cell: Option<(CellId, u64)>,
    /// While `Waiting` on a pipe: which pipe.
    pub wait_pipe: Option<PipeId>,
    /// While `Waiting` on a pipe or the console: the transfer the kernel
    /// completes, against this process's memory, when it can proceed.
    pub wait_transfer: Option<TransferWait>,
    /// What a `Waiting` process is blocked on.
    pub wait_kind: WaitKind,
    /// While `Waiting`: tick at which the wait is cut short (timeout) or, for
    /// a sleep, ends.
    pub wake_at: Option<u64>,
    pub class: crate::rt::SchedulingClass,
    /// `None` is the only state eligible for a new CPU claim.
    pub cpu_owner: Option<CpuClaim>,
    pub claim_epoch: u64,
    pub stop: StopState,
    /// Whether `spawn` and `spawn_many_copy` are permitted. The kernel grants
    /// it to init; a child keeps it only if spawned without `SPAWN_NO_SPAWN`.
    pub may_spawn: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitKind {
    None,
    Child,
    Cell,
    Pipe,
    Console,
    Sleep,
    /// Kernel-owned periodic release / budget suspension, preserves registers.
    RtRelease,
    /// `nic_receive`: woken by a received frame, a disabled NIC, or its
    /// deadline (a NIC receive always has one).
    Nic,
    /// A remote stop is pending; wait for departed-then-drained completion.
    StopFence,
}

/// A read or write that could not proceed and is retried by the kernel,
/// against the waiter's own memory, when the object changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferWait {
    pub address: u64,
    pub length: usize,
    pub write: bool,
}

impl Process {
    pub const EMPTY: Self = Self {
        pid: 0,
        parent: KERNEL_PARENT,
        program: 0,
        handles: HandleTable::new(0),
        address_space: AddressSpace::EMPTY,
        task: Task::EMPTY,
        state: ProcessState::Empty,
        exit_status: 0,
        fault_vector: 0,
        fault_address: 0,
        fault_error: 0,
        wait_target: 0,
        wait_record: 0,
        wait_cell: None,
        wait_pipe: None,
        wait_transfer: None,
        wait_kind: WaitKind::None,
        wake_at: None,
        class: crate::rt::SchedulingClass::Normal,
        cpu_owner: None,
        claim_epoch: 0,
        stop: StopState::Active,
        may_spawn: false,
    };
    pub fn is_runnable(&self) -> bool {
        self.state == ProcessState::Runnable
            && self.cpu_owner.is_none()
            && self.stop == StopState::Active
            && self.class.eligible()
    }
    /// No waker may copy into user memory or commit a wait result after a
    /// stop request. Check this before side effects, under serialization.
    pub fn can_wake(&self) -> bool {
        self.state == ProcessState::Waiting
            && self.cpu_owner.is_none()
            && self.stop == StopState::Active
    }
    /// Claim this process once, while the process table is serialized.
    pub fn claim_cpu(&mut self, cpu: u8) -> CpuClaim {
        assert_eq!(self.state, ProcessState::Runnable);
        assert!(self.cpu_owner.is_none());
        assert_eq!(self.stop, StopState::Active);
        self.claim_epoch = self
            .claim_epoch
            .checked_add(1)
            .expect("CPU claim epoch exhausted");
        let claim = CpuClaim {
            cpu,
            epoch: self.claim_epoch,
        };
        self.cpu_owner = Some(claim);
        self.state = ProcessState::Running;
        claim
    }
    /// Clear ownership only after the hardware departure predicate succeeds.
    pub fn depart_cpu(&mut self, claim: CpuClaim) {
        assert_eq!(self.cpu_owner, Some(claim));
        self.cpu_owner = None;
        if self.stop == StopState::Requested || self.stop == StopState::Observed {
            self.stop = StopState::Departed;
        }
    }
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ProcessState::Exited | ProcessState::Faulted | ProcessState::Killed
        )
    }
    pub const fn is_live(&self) -> bool {
        matches!(
            self.state,
            ProcessState::Created
                | ProcessState::Runnable
                | ProcessState::Running
                | ProcessState::Waiting
        )
    }
    pub fn outcome(&self) -> Option<Outcome> {
        match self.state {
            ProcessState::Exited => Some(Outcome::Exited(self.exit_status)),
            ProcessState::Faulted => Some(Outcome::Faulted {
                vector: self.fault_vector,
                address: self.fault_address,
                error: self.fault_error,
            }),
            ProcessState::Killed => Some(Outcome::Killed),
            _ => None,
        }
    }
    /// Whether this entry is blocked in `wait` for a child.
    pub const fn is_waiting_for_child(&self) -> bool {
        matches!(self.state, ProcessState::Waiting)
            && matches!(self.stop, StopState::Active)
            && matches!(self.wait_kind, WaitKind::Child)
    }
    /// Forgets whatever this entry was blocked on.
    pub const fn clear_wait(&mut self) {
        self.wait_target = 0;
        self.wait_record = 0;
        self.wait_cell = None;
        self.wait_pipe = None;
        self.wait_transfer = None;
        self.wait_kind = WaitKind::None;
        self.wake_at = None;
    }
    /// Whether a `wait` from `parent` for `target` (zero = any) covers this entry.
    pub fn is_child_of(&self, parent: u64, target: u64) -> bool {
        self.state != ProcessState::Empty
            && self.parent == parent
            && (target == 0 || self.pid == target)
    }
}

pub struct ProcessTable {
    pub entries: [Process; MAX_PROCESSES],
    next_pid: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimError {
    Full,
    PidExhausted,
}

impl ProcessTable {
    pub const fn new() -> Self {
        Self {
            entries: [Process::EMPTY; MAX_PROCESSES],
            next_pid: 1,
        }
    }
    /// Reserves the next PID; PIDs are never reused within one boot.
    pub fn allocate_pid(&mut self) -> u64 {
        let pid = self.next_pid;
        self.next_pid += 1;
        pid
    }
    pub fn has_free_slot(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.state == ProcessState::Empty)
    }
    /// Claims the first empty slot for a new `Created` process with a fresh
    /// PID and returns its index; the caller fills the entry in place.
    pub fn claim(&mut self, parent: u64, program: usize) -> Option<usize> {
        self.claim_with_max_pid(parent, program, u64::MAX - 1).ok()
    }
    /// Claims a slot only when the next PID is representable by its consumer.
    /// A full table is reported before PID exhaustion because no PID would be
    /// consumed in that case. Either refusal leaves both table and PID state
    /// unchanged.
    pub fn claim_with_max_pid(
        &mut self,
        parent: u64,
        program: usize,
        max_pid: u64,
    ) -> Result<usize, ClaimError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.state == ProcessState::Empty)
            .ok_or(ClaimError::Full)?;
        if self.next_pid > max_pid {
            return Err(ClaimError::PidExhausted);
        }
        let pid = self.allocate_pid();
        let entry = &mut self.entries[index];
        *entry = Process::EMPTY;
        entry.pid = pid;
        entry.parent = parent;
        entry.program = program;
        entry.handles = HandleTable::new(pid);
        entry.state = ProcessState::Created;
        Ok(index)
    }
    /// Releases a slot, discarding retained terminal metadata.
    pub fn release(&mut self, index: usize) {
        assert!(
            self.entries[index].cpu_owner.is_none(),
            "release of CPU-owned process"
        );
        assert!(
            !matches!(
                self.entries[index].stop,
                StopState::Requested | StopState::Observed
            ),
            "release before remote departure"
        );
        self.entries[index] = Process::EMPTY;
    }
    /// Undoes a `claim` whose load failed before the process ever ran. The
    /// PID is given back when it is still the newest, so a refused spawn
    /// leaves no trace in the numbering either.
    pub fn unclaim(&mut self, index: usize) {
        let pid = self.entries[index].pid;
        if self.entries[index].state == ProcessState::Created {
            self.release(index);
            self.rewind_newest_pid(pid);
        } else {
            self.release(index);
        }
    }
    /// Gives back `pid` if it is the newest and no longer in the table, so
    /// a process that left no trace does not consume a number either.
    pub fn rewind_newest_pid(&mut self, pid: u64) -> bool {
        if pid + 1 == self.next_pid && self.slot_of(pid).is_none() {
            self.next_pid -= 1;
            true
        } else {
            false
        }
    }
    pub fn slot_of(&self, pid: u64) -> Option<usize> {
        if pid == 0 {
            return None;
        }
        self.entries
            .iter()
            .position(|entry| entry.state != ProcessState::Empty && entry.pid == pid)
    }
    pub fn first_runnable(&self) -> Option<usize> {
        self.next_runnable_after(MAX_PROCESSES - 1)
    }
    pub fn next_runnable_after(&self, current: usize) -> Option<usize> {
        self.next_runnable_after_if(current, |_, _| true)
    }
    /// Preserve priority/round-robin policy while applying an execution
    /// eligibility constraint (e.g. a qualification CPU placement).
    pub fn next_runnable_after_if(
        &self,
        current: usize,
        eligible: impl Fn(usize, &Process) -> bool,
    ) -> Option<usize> {
        let priority = self
            .entries
            .iter()
            .enumerate()
            .filter(|(i, entry)| entry.is_runnable() && eligible(*i, entry))
            .map(|(_, entry)| entry.class.priority())
            .max()?;
        (1..=MAX_PROCESSES)
            .map(|offset| (current + offset) % MAX_PROCESSES)
            .find(|&index| {
                self.entries[index].is_runnable()
                    && eligible(index, &self.entries[index])
                    && self.entries[index].class.priority() == priority
            })
    }
    pub fn live_count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_live()).count()
    }
    pub fn occupied_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.state != ProcessState::Empty)
            .count()
    }
    /// First terminal, unreaped child matching a `wait` from `parent`.
    pub fn terminal_child(&self, parent: u64, target: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.is_child_of(parent, target) && entry.is_terminal())
    }
    pub fn has_child(&self, parent: u64, target: u64) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.is_child_of(parent, target))
    }

    /// Adopts every child of `exiting_pid` into a live userspace init. `None`
    /// selects the kernel fallback because PID 1 is the exiting process,
    /// absent, or already terminal; `Some` reports the number adopted.
    pub fn reparent_children_to_live_init(&mut self, exiting_pid: u64) -> Option<usize> {
        if exiting_pid == 1 {
            return None;
        }
        let init = self.slot_of(1)?;
        if !self.entries[init].is_live() {
            return None;
        }
        let mut adopted = 0;
        for child in &mut self.entries {
            if child.state != ProcessState::Empty && child.parent == exiting_pid {
                child.parent = 1;
                adopted += 1;
            }
        }
        Some(adopted)
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stopped_waiter_never_enters_any_wake_path() {
        // The shared predicate gates every waker before user copy, wait
        // clearing, context mutation, or Runnable publication. Exercise each
        // supported continuation, including both pipe directions (whose
        // direction lives in TransferWait rather than WaitKind).
        let kinds = [
            WaitKind::Child,
            WaitKind::Cell,
            WaitKind::Pipe,
            WaitKind::Console,
            WaitKind::Sleep,
            WaitKind::RtRelease,
            WaitKind::Nic,
            WaitKind::StopFence,
        ];
        for kind in kinds {
            for direction in [false, true] {
                let mut entry = Process {
                    state: ProcessState::Waiting,
                    wait_kind: kind,
                    wait_transfer: (kind == WaitKind::Pipe).then_some(TransferWait {
                        address: 0x1000,
                        length: 1,
                        write: direction,
                    }),
                    ..Process::EMPTY
                };
                assert!(entry.can_wake(), "active {kind:?} must be serviceable");
                for stop in [
                    StopState::Requested,
                    StopState::Observed,
                    StopState::Departed,
                ] {
                    entry.stop = stop;
                    assert!(!entry.can_wake(), "{kind:?} woke after {stop:?}");
                }
            }
        }
    }
    fn process(pid: u64, parent: u64, state: ProcessState) -> Process {
        Process {
            pid,
            parent,
            state,
            ..Process::EMPTY
        }
    }
    fn insert(table: &mut ProcessTable, process: Process) -> Option<usize> {
        let index = table.claim(process.parent, process.program)?;
        let pid = table.entries[index].pid;
        table.entries[index] = Process { pid, ..process };
        Some(index)
    }
    #[test]
    fn slots_are_reused_but_pids_are_not() {
        let mut table = ProcessTable::new();
        let a = table.claim(0, 3).unwrap();
        assert_eq!(a, 0);
        assert_eq!(table.entries[a].pid, 1);
        assert_eq!(table.entries[a].program, 3);
        assert_eq!(table.entries[a].state, ProcessState::Created);
        assert_eq!(table.first_runnable(), None);
        assert!(table.entries[a].is_live());
        table.entries[a].state = ProcessState::Exited;
        table.release(a);
        let b = table.claim(0, 0).unwrap();
        assert_eq!((table.entries[b].pid, b), (2, 0));
        assert_eq!(table.slot_of(1), None);
        assert_eq!(table.slot_of(2), Some(0));
        assert_eq!(table.slot_of(0), None);
    }
    #[test]
    fn unclaim_gives_back_the_newest_pid_only() {
        let mut table = ProcessTable::new();
        let a = table.claim(0, 0).unwrap();
        table.unclaim(a);
        let b = table.claim(0, 0).unwrap();
        assert_eq!(table.entries[b].pid, 1);
        table.entries[b].state = ProcessState::Runnable;
        let c = table.claim(0, 0).unwrap();
        assert_eq!(table.entries[c].pid, 2);
        table.unclaim(b);
        assert_eq!(table.entries[b].state, ProcessState::Empty);
        let d = table.claim(0, 0).unwrap();
        assert_eq!(table.entries[d].pid, 3);
    }

    #[test]
    fn table_is_bounded_and_reports_occupancy() {
        let mut table = ProcessTable::new();
        for _ in 0..MAX_PROCESSES {
            assert!(table.claim(1, 0).is_some());
        }
        assert!(!table.has_free_slot());
        assert!(table.claim(1, 0).is_none());
        table.entries[3].state = ProcessState::Faulted;
        assert_eq!(table.live_count(), MAX_PROCESSES - 1);
        assert_eq!(table.occupied_count(), MAX_PROCESSES);
        table.release(3);
        assert!(table.has_free_slot());
        assert_eq!(table.occupied_count(), MAX_PROCESSES - 1);
    }
    #[test]
    fn full_table_and_pid_exhaustion_are_distinct_and_nonmutating() {
        let mut table = ProcessTable::new();
        for _ in 0..MAX_PROCESSES {
            table.claim(1, 0).unwrap();
        }

        let next_pid = table.next_pid;
        assert_eq!(table.claim_with_max_pid(1, 0, 0), Err(ClaimError::Full));
        assert_eq!(table.next_pid, next_pid);
        assert_eq!(table.occupied_count(), MAX_PROCESSES);

        table.release(3);
        let occupancy = table.occupied_count();
        assert_eq!(
            table.claim_with_max_pid(1, 0, next_pid - 1),
            Err(ClaimError::PidExhausted)
        );
        assert_eq!(table.next_pid, next_pid);
        assert_eq!(table.occupied_count(), occupancy);
        assert_eq!(table.entries[3], Process::EMPTY);

        let index = table.claim_with_max_pid(1, 0, next_pid).unwrap();
        assert_eq!(index, 3);
        assert_eq!(table.entries[index].pid, next_pid);
    }
    #[test]
    fn round_robin_skips_terminal_waiting_and_empty_slots() {
        let mut table = ProcessTable::new();
        insert(&mut table, process(1, 0, ProcessState::Waiting));
        insert(&mut table, process(2, 1, ProcessState::Runnable));
        insert(&mut table, process(3, 1, ProcessState::Runnable));
        insert(&mut table, process(4, 1, ProcessState::Runnable));
        table.entries[1].state = ProcessState::Exited;
        assert_eq!(table.first_runnable(), Some(2));
        assert_eq!(table.next_runnable_after(2), Some(3));
        assert_eq!(table.next_runnable_after(3), Some(2));
        table.entries[3].state = ProcessState::Faulted;
        assert_eq!(table.next_runnable_after(2), Some(2));
        table.entries[2].state = ProcessState::Running;
        assert_eq!(table.next_runnable_after(2), None);
    }

    #[test]
    fn stack_growth_requires_the_adjacent_page_and_rsp_proximity() {
        let bottom = USER_STACK_TOP - 2 * PAGE_SIZE;
        let page = bottom - PAGE_SIZE;
        assert_eq!(
            stack_growth_page(0x6, page + 32, page + 32, bottom),
            Some(page)
        );
        // A leaf may touch the red zone just below an RSP still in the
        // mapped page.
        assert_eq!(
            stack_growth_page(0x6, bottom - 8, bottom + 64, bottom),
            Some(page)
        );
        assert_eq!(stack_growth_page(0x7, page, page, bottom), None);
        assert_eq!(stack_growth_page(0x4, page, page, bottom), None);
        assert_eq!(stack_growth_page(0x6, page - PAGE_SIZE, page, bottom), None);
        assert_eq!(stack_growth_page(0x6, page, bottom + 129, bottom), None);
        assert_eq!(stack_growth_page(0x6, page, page - 1, bottom), None);
        assert_eq!(
            stack_growth_page(0x6, USER_STACK_BASE - 1, USER_STACK_BASE, USER_STACK_BASE),
            None
        );
    }
    #[test]
    fn wait_matching_respects_parentage_and_terminal_state() {
        let mut table = ProcessTable::new();
        insert(&mut table, process(1, 0, ProcessState::Running));
        insert(&mut table, process(2, 1, ProcessState::Runnable));
        insert(&mut table, process(3, 1, ProcessState::Runnable));
        insert(&mut table, process(4, 2, ProcessState::Runnable));
        table.entries[2].state = ProcessState::Exited;
        table.entries[3].state = ProcessState::Faulted;
        assert!(table.has_child(1, 2));
        assert!(!table.has_child(1, 4));
        assert!(!table.has_child(2, 1));
        assert_eq!(table.terminal_child(1, 0), Some(2));
        assert_eq!(table.terminal_child(1, 2), None);
        assert_eq!(table.terminal_child(2, 0), Some(3));
        assert_eq!(
            table.entries[3].outcome(),
            Some(Outcome::Faulted {
                vector: 0,
                address: 0,
                error: 0
            })
        );
        assert_eq!(table.entries[1].outcome(), None);
    }

    #[test]
    fn live_init_adopts_both_live_and_terminal_orphans() {
        let mut table = ProcessTable::new();
        let init = insert(&mut table, process(1, 0, ProcessState::Running)).unwrap();
        let parent = insert(&mut table, process(2, 1, ProcessState::Exited)).unwrap();
        let live = insert(&mut table, process(3, 2, ProcessState::Runnable)).unwrap();
        let terminal = insert(&mut table, process(4, 2, ProcessState::Exited)).unwrap();
        let exiting_pid = table.entries[parent].pid;
        assert_eq!(table.reparent_children_to_live_init(exiting_pid), Some(2));
        assert_eq!(table.entries[live].parent, 1);
        assert_eq!(table.entries[terminal].parent, 1);
        assert_eq!(table.reparent_children_to_live_init(1), None);
        table.entries[init].state = ProcessState::Exited;
        table.entries[live].parent = exiting_pid;
        assert_eq!(table.reparent_children_to_live_init(exiting_pid), None);
        assert_eq!(table.entries[live].parent, exiting_pid);
    }
    #[test]
    fn initial_fpu_image_masks_exceptions() {
        let image = FpuState::INITIAL.0;
        assert_eq!(u16::from_le_bytes([image[0], image[1]]), 0x37f);
        assert_eq!(
            u32::from_le_bytes([image[24], image[25], image[26], image[27]]),
            0x1f80
        );
        assert_eq!(core::mem::align_of::<FpuState>(), 16);
    }
}

#[cfg(test)]
mod priority_tests {
    use super::*;
    use crate::rt::{BoundedRt, Priority, SchedulingClass, State};
    fn rt(priority: Priority) -> SchedulingClass {
        let mut rt = BoundedRt::new(priority, 10, 20, 5);
        rt.release_at(10);
        SchedulingClass::BoundedRt(rt)
    }
    #[test]
    fn execution_eligibility_preserves_priority_and_round_robin() {
        let mut table = ProcessTable::new();
        for i in 0..3 {
            table.entries[i].state = ProcessState::Runnable;
        }
        table.entries[1].class = rt(Priority::RtHigh);
        assert_eq!(table.next_runnable_after_if(0, |i, _| i != 1), Some(2));
        assert_eq!(table.next_runnable_after_if(2, |i, _| i != 1), Some(0));
        assert_eq!(table.next_runnable_after_if(0, |_, _| true), Some(1));
        assert_eq!(table.next_runnable_after_if(0, |_, _| false), None);
    }
    #[test]
    fn priority_fairness_and_exhaustion_gate() {
        let mut table = ProcessTable::new();
        for index in [0, 1, 2] {
            table.entries[index].state = ProcessState::Runnable;
        }
        table.entries[0].class = rt(Priority::RtLow);
        assert_eq!(table.first_runnable(), Some(0));
        assert_eq!(table.next_runnable_after(0), Some(0));
        table.entries[2].class = rt(Priority::RtLow);
        assert_eq!(table.next_runnable_after(0), Some(2));
        assert_eq!(table.next_runnable_after(2), Some(0));
        table.entries[2].class = rt(Priority::RtHigh);
        assert_eq!(table.next_runnable_after(0), Some(2));
        let rt = table.entries[2].class.rt_mut().unwrap();
        rt.state = State::Exhausted;
        rt.consumed = 5;
        // Even a generic Runnable state cannot bypass RT exhaustion.
        assert_eq!(table.next_runnable_after(0), Some(0));
        table.entries[0].state = ProcessState::Waiting;
        assert_eq!(table.next_runnable_after(0), Some(1));
        table.release(2);
        assert_eq!(table.entries[2].class, SchedulingClass::Normal);
    }
    #[test]
    fn fresh_child_does_not_inherit_class_and_waiting_has_no_runnable_path() {
        let mut table = ProcessTable::new();
        let parent = table.claim(0, 0).unwrap();
        table.entries[parent].class = rt(Priority::RtHigh);
        let child = table.claim(table.entries[parent].pid, 0).unwrap();
        assert_eq!(table.entries[child].class, SchedulingClass::Normal);
        table.entries[parent].state = ProcessState::Waiting;
        table.entries[parent].class =
            SchedulingClass::BoundedRt(BoundedRt::new(Priority::RtHigh, 10, 20, 5));
        assert_eq!(table.first_runnable(), None);
        table.entries[parent].class.rt_mut().unwrap().release_at(10);
        table.entries[parent].state = ProcessState::Runnable;
        assert_eq!(table.first_runnable(), Some(parent));
        table.release(parent);
        assert_eq!(table.entries[parent].class, SchedulingClass::Normal);
    }
}

/// A userspace exception reaches shared isolation policy only after decoding.
pub fn user_fault_disposition(fault: crate::arch::UserFault) -> Option<ProcessState> {
    fault.from_user.then_some(ProcessState::Faulted)
}
#[cfg(test)]
mod fault_policy_tests {
    use super::*;
    #[test]
    fn terminal_fault_policy_refuses_non_user_metadata() {
        for class in [
            crate::arch::FaultClass::Translation,
            crate::arch::FaultClass::Permission,
            crate::arch::FaultClass::Alignment,
            crate::arch::FaultClass::Undefined,
            crate::arch::FaultClass::FloatingPoint,
            crate::arch::FaultClass::Other,
        ] {
            let mut fault = crate::arch::UserFault {
                class,
                access: None,
                from_user: true,
                address: 1,
            };
            assert_eq!(user_fault_disposition(fault), Some(ProcessState::Faulted));
            fault.from_user = false;
            assert_eq!(user_fault_disposition(fault), None);
        }
    }
}
