//! Fixed, transient readiness wait for the supported wait_readable call.
use crate::handle::{HandleError, HandleTable, Object, RIGHT_READ};
use crate::object::PipeTable;
use crate::process::{Process, ProcessState, WaitKind};
use crate::syscall::{ERROR_BAD_HANDLE, ERROR_INVALID, ERROR_RIGHTS};

pub use absd_abi::syscall::{WAIT_READABLE_MAX as MAX_HANDLES, WAIT_READABLE_POLL as POLL};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadWait {
    handles: [u64; MAX_HANDLES],
    count: usize,
    pub deadline: Option<u64>,
    poll_only: bool,
}

impl ReadWait {
    /// Whether this indefinite wait can receive external Console input.
    pub fn has_readable_console(&self, handles: &HandleTable) -> bool {
        self.handles[..self.count].iter().any(|&value| {
            handles.lookup(value).is_ok_and(|handle| {
                handle.object == Object::Console && handle.require(RIGHT_READ).is_ok()
            })
        })
    }

    /// Caller holds kernel serialization from readiness check through this
    /// registration; no pipe/table mutation or wake scan can interleave here.
    /// Console IRQ level publication may occur on the BSP, but its wake scan
    /// must acquire that same lock after this registration.
    pub fn register(
        self,
        process: &mut Process,
        pipes: &PipeTable,
        console_ready: bool,
    ) -> Result<Option<u64>, i64> {
        assert_eq!(process.state, ProcessState::Running);
        let result = if cfg!(absd_mutant_wait_skip_recheck) {
            None
        } else {
            self.poll(&process.handles, pipes, console_ready)?
        };
        if result.is_none() {
            process.clear_wait();
            process.wait_readable = Some(self);
            process.wait_kind = WaitKind::Readable;
            process.wake_at = self.deadline;
            process.state = ProcessState::Waiting;
        }
        Ok(result)
    }

    pub fn capture(values: &[u64], timeout: u64, now: u64) -> Result<Self, i64> {
        if values.is_empty() || values.len() > MAX_HANDLES {
            return Err(ERROR_INVALID);
        }
        let mut handles = [0; MAX_HANDLES];
        handles[..values.len()].copy_from_slice(values);
        let deadline = if timeout == 0 || timeout == POLL {
            None
        } else {
            Some(
                now.checked_add(timeout)
                    .and_then(|t| t.checked_add(1))
                    .ok_or(ERROR_INVALID)?,
            )
        };
        Ok(Self {
            handles,
            count: values.len(),
            deadline,
            poll_only: timeout == POLL,
        })
    }

    pub fn poll(
        &self,
        handles: &HandleTable,
        pipes: &PipeTable,
        console_ready: bool,
    ) -> Result<Option<u64>, i64> {
        let mut mask = 0;
        for (index, &value) in self.handles[..self.count].iter().enumerate() {
            let handle = handles.lookup(value).map_err(|_| ERROR_BAD_HANDLE)?;
            handle.require(RIGHT_READ).map_err(|error| match error {
                HandleError::Rights => ERROR_RIGHTS,
                _ => ERROR_BAD_HANDLE,
            })?;
            let ready = match handle.object {
                Object::Pipe(id) => {
                    let status = pipes.status(id).map_err(|_| ERROR_BAD_HANDLE)?;
                    status.available > 0 || (!cfg!(absd_mutant_wait_no_eof) && status.writers == 0)
                }
                Object::Console => console_ready,
                _ => return Err(ERROR_BAD_HANDLE),
            };
            if ready {
                mask |= 1 << index;
            }
        }
        // Validate every member even when an earlier member is ready.
        Ok((mask != 0 || self.poll_only).then_some(mask))
    }
}

/// Check a registered process without publishing it. The native caller stores
/// the returned result, clears the wait and uses its normal runnable gate.
pub fn completion(process: &Process, pipes: &PipeTable, console_ready: bool) -> Option<i64> {
    if !process.can_wake() || process.wait_kind != WaitKind::Readable {
        return None;
    }
    let wait = process.wait_readable?;
    match wait.poll(&process.handles, pipes, console_ready) {
        Ok(mask) => mask.map(|value| value as i64),
        Err(error) => (!cfg!(absd_mutant_wait_ignore_revocation)).then_some(error),
    }
}

/// The native timer scan uses this result for a registered readable wait.
pub fn timeout_completion(process: &Process, tick: u64) -> Option<i64> {
    if !process.can_wake() || process.wait_kind != WaitKind::Readable {
        return None;
    }
    let deadline = process.wait_readable?.deadline?;
    assert_eq!(process.wake_at, Some(deadline));
    (tick >= deadline && !cfg!(absd_mutant_wait_ignore_timeout))
        .then_some(crate::syscall::ERROR_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::{Object, RIGHT_READ, RIGHT_WRITE};
    use crate::object::PipeId;
    use crate::syscall::{ERROR_BAD_HANDLE, ERROR_INVALID, ERROR_RIGHTS};

    struct Fixture {
        handles: HandleTable,
        pipes: PipeTable,
        id: PipeId,
        read: u64,
    }
    impl Fixture {
        fn new() -> Self {
            let mut handles = HandleTable::new(73);
            let mut pipes = PipeTable::new();
            let id = pipes.create(RIGHT_WRITE).unwrap();
            pipes.retain(id, true, false).unwrap();
            let read = handles.insert(Object::Pipe(id), RIGHT_READ).unwrap();
            Self {
                handles,
                pipes,
                id,
                read,
            }
        }
        fn wait(&self, timeout: u64) -> ReadWait {
            ReadWait::capture(&[self.read], timeout, 100).unwrap()
        }
        fn poll(&self, wait: &ReadWait) -> Result<Option<u64>, i64> {
            wait.poll(&self.handles, &self.pipes, false)
        }
    }

    #[test]
    fn boot_alive_pipe_only_is_false() {
        let f = Fixture::new();
        assert!(!f.wait(0).has_readable_console(&f.handles));
    }

    #[test]
    fn boot_alive_readable_console_is_true() {
        let mut f = Fixture::new();
        let console = f.handles.insert(Object::Console, RIGHT_READ).unwrap();
        let wait = ReadWait::capture(&[console], 0, 0).unwrap();
        assert!(wait.has_readable_console(&f.handles));
    }

    #[test]
    fn boot_alive_mixed_pipe_console_is_true() {
        let mut f = Fixture::new();
        let console = f.handles.insert(Object::Console, RIGHT_READ).unwrap();
        let wait = ReadWait::capture(&[f.read, console], 0, 0).unwrap();
        assert!(wait.has_readable_console(&f.handles));
    }

    #[test]
    fn boot_alive_closed_or_replaced_console_is_false() {
        let mut f = Fixture::new();
        let console = f.handles.insert(Object::Console, RIGHT_READ).unwrap();
        let wait = ReadWait::capture(&[console], 0, 0).unwrap();
        f.handles.close(console).unwrap();
        assert!(!wait.has_readable_console(&f.handles));
        let replacement = f.handles.insert(Object::Console, RIGHT_READ).unwrap();
        assert_ne!(replacement, console);
        assert!(!wait.has_readable_console(&f.handles));
    }

    #[test]
    fn boot_alive_console_without_read_is_false() {
        let mut f = Fixture::new();
        let console = f.handles.insert(Object::Console, RIGHT_WRITE).unwrap();
        let wait = ReadWait::capture(&[console], 0, 0).unwrap();
        assert!(!wait.has_readable_console(&f.handles));
    }

    #[test]
    fn event_between_capture_and_registration_is_not_lost() {
        let mut f = Fixture::new();
        let wait = f.wait(0);
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(f.poll(&wait), Ok(Some(1)));
    }
    #[test]
    fn event_after_registration_completes_without_consuming() {
        let mut f = Fixture::new();
        let wait = f.wait(0);
        assert_eq!(f.poll(&wait), Ok(None));
        f.pipes.write(f.id, b"xy").unwrap();
        assert_eq!(f.poll(&wait), Ok(Some(1)));
        assert_eq!(f.pipes.status(f.id).unwrap().available, 2);
        f.pipes.read(f.id, &mut [0; 2]).unwrap();
        assert_eq!(f.poll(&wait), Ok(None));
    }
    #[test]
    fn last_writer_close_and_buffered_eof_are_level_ready() {
        let mut f = Fixture::new();
        let wait = f.wait(0);
        f.pipes.write(f.id, b"x").unwrap();
        f.pipes.release(f.id, false, true).unwrap();
        assert_eq!(f.poll(&wait), Ok(Some(1)));
        f.pipes.read(f.id, &mut [0]).unwrap();
        assert_eq!(f.poll(&wait), Ok(Some(1)));
        assert_eq!(f.poll(&wait), Ok(Some(1)));
    }
    #[test]
    fn close_and_replaced_handle_do_not_inherit_readiness() {
        let mut f = Fixture::new();
        let wait = f.wait(0);
        f.handles.close(f.read).unwrap();
        let replacement = f.handles.insert(Object::Pipe(f.id), RIGHT_READ).unwrap();
        assert_ne!(replacement, f.read);
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(f.poll(&wait), Err(ERROR_BAD_HANDLE));
    }
    #[test]
    fn revoked_member_is_not_hidden_by_a_ready_member() {
        let mut f = Fixture::new();
        let console = f.handles.insert(Object::Console, RIGHT_READ).unwrap();
        let wait = ReadWait::capture(&[f.read, console], 0, 0).unwrap();
        f.pipes.write(f.id, b"x").unwrap();
        f.handles.close(console).unwrap();
        assert_eq!(f.poll(&wait), Err(ERROR_BAD_HANDLE));
    }
    #[test]
    fn retired_pipe_generation_cannot_alias_new_pipe() {
        let mut f = Fixture::new();
        let wait = f.wait(0);
        f.pipes.release(f.id, true, false).unwrap();
        f.pipes.release(f.id, false, true).unwrap();
        let replacement = f.pipes.create(RIGHT_READ | RIGHT_WRITE).unwrap();
        assert_ne!(replacement, f.id);
        f.pipes.write(replacement, b"x").unwrap();
        assert_eq!(f.poll(&wait), Err(ERROR_BAD_HANDLE));
    }
    #[test]
    fn pipe_console_and_duplicate_positions_form_one_mask() {
        let mut f = Fixture::new();
        let console = f.handles.insert(Object::Console, RIGHT_READ).unwrap();
        let wait = ReadWait::capture(&[f.read, console, f.read], 0, 0).unwrap();
        assert_eq!(wait.poll(&f.handles, &f.pipes, true), Ok(Some(2)));
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(wait.poll(&f.handles, &f.pipes, true), Ok(Some(7)));
        assert_eq!(wait.poll(&f.handles, &f.pipes, false), Ok(Some(5)));
    }
    #[test]
    fn rights_types_and_all_positions_are_validated() {
        let mut f = Fixture::new();
        let write = f.handles.insert(Object::Pipe(f.id), RIGHT_WRITE).unwrap();
        let wrong = f.handles.insert(Object::Block, RIGHT_READ).unwrap();
        f.pipes.write(f.id, b"x").unwrap();
        for (bad, error) in [
            (write, ERROR_RIGHTS),
            (wrong, ERROR_BAD_HANDLE),
            (0, ERROR_BAD_HANDLE),
        ] {
            let wait = ReadWait::capture(&[f.read, bad], 0, 0).unwrap();
            assert_eq!(f.poll(&wait), Err(error));
        }
    }
    #[test]
    fn poll_and_indefinite_wait_are_distinct() {
        let f = Fixture::new();
        assert_eq!(f.poll(&f.wait(POLL)), Ok(Some(0)));
        assert_eq!(f.poll(&f.wait(0)), Ok(None));
        assert_eq!(f.wait(0).deadline, None);
        assert_eq!(f.wait(POLL).deadline, None);
    }
    #[test]
    fn finite_deadline_uses_existing_tick_convention_and_rejects_overflow() {
        let f = Fixture::new();
        assert_eq!(f.wait(1).deadline, Some(102));
        assert_eq!(f.wait(7).deadline, Some(108));
        assert_eq!(
            ReadWait::capture(&[f.read], 1, u64::MAX - 1),
            Err(ERROR_INVALID)
        );
        assert_eq!(
            ReadWait::capture(&[f.read], u64::MAX - 1, 1),
            Err(ERROR_INVALID)
        );
    }
    #[test]
    fn bounded_snapshot_copies_inputs_and_covers_eleven_channels() {
        let mut f = Fixture::new();
        let mut values = [f.read; MAX_HANDLES];
        let wait = ReadWait::capture(&values, 0, 0).unwrap();
        values.fill(0);
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(f.poll(&wait), Ok(Some((1 << MAX_HANDLES) - 1)));
        assert_eq!(ReadWait::capture(&[], 0, 0), Err(ERROR_INVALID));
        assert_eq!(
            ReadWait::capture(&[f.read; MAX_HANDLES + 1], 0, 0),
            Err(ERROR_INVALID)
        );
    }

    fn process(f: &Fixture) -> Process {
        Process {
            state: ProcessState::Running,
            handles: f.handles,
            ..Process::EMPTY
        }
    }
    #[test]
    fn register_rechecks_arrival_before_arming() {
        let mut f = Fixture::new();
        let wait = f.wait(0);
        let mut p = process(&f);
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(wait.register(&mut p, &f.pipes, false), Ok(Some(1)));
        assert_eq!(p.state, ProcessState::Running);
        assert_eq!(p.wait_readable, None);
    }
    #[test]
    fn registered_wait_wakes_after_arrival_and_clear_retires_all_state() {
        let mut f = Fixture::new();
        let wait = f.wait(1);
        let mut p = process(&f);
        assert_eq!(wait.register(&mut p, &f.pipes, false), Ok(None));
        assert_eq!(p.state, ProcessState::Waiting);
        assert_eq!(p.wait_kind, WaitKind::Readable);
        assert_eq!(p.wake_at, Some(102));
        assert_eq!(completion(&p, &f.pipes, false), None);
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(completion(&p, &f.pipes, false), Some(1));
        p.clear_wait();
        assert_eq!(p.wait_readable, None);
        assert_eq!(p.wake_at, None);
        assert_eq!(completion(&p, &f.pipes, false), None);
    }
    #[test]
    fn stopped_waiter_cannot_complete_or_retain_state_after_retirement() {
        use crate::process::StopState;
        let mut f = Fixture::new();
        let mut p = process(&f);
        f.wait(0).register(&mut p, &f.pipes, false).unwrap();
        assert_eq!(p.wait_kind, WaitKind::Readable);
        p.stop = StopState::Departed;
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(completion(&p, &f.pipes, false), None);
        p.clear_wait();
        assert_eq!(p.wait_readable, None);
    }
    #[test]
    fn registered_revocation_is_terminal_even_without_a_deadline() {
        let f = Fixture::new();
        let mut p = process(&f);
        f.wait(0).register(&mut p, &f.pipes, false).unwrap();
        p.handles.close(f.read).unwrap();
        assert_eq!(completion(&p, &f.pipes, false), Some(ERROR_BAD_HANDLE));
    }
    #[test]
    fn writer_close_after_registration_completes_eof() {
        let mut f = Fixture::new();
        let mut p = process(&f);
        f.wait(0).register(&mut p, &f.pipes, false).unwrap();
        f.pipes.release(f.id, false, true).unwrap();
        assert_eq!(completion(&p, &f.pipes, false), Some(1));
    }
    #[test]
    fn deadline_and_arrival_races_complete_exactly_once_in_lock_order() {
        use crate::syscall::ERROR_TIMEOUT;
        for timer_first in [false, true] {
            let mut f = Fixture::new();
            let mut p = process(&f);
            f.wait(1).register(&mut p, &f.pipes, false).unwrap();
            assert_eq!(timeout_completion(&p, 101), None);
            let mut results = std::vec::Vec::new();
            for timer in [timer_first, !timer_first] {
                let result = if timer {
                    timeout_completion(&p, 102)
                } else {
                    f.pipes.write(f.id, b"x").unwrap();
                    completion(&p, &f.pipes, false)
                };
                if let Some(result) = result {
                    results.push(result);
                    p.clear_wait();
                    p.state = ProcessState::Runnable;
                }
            }
            assert_eq!(results, [if timer_first { ERROR_TIMEOUT } else { 1 }]);
            assert_eq!(p.wait_readable, None);
        }
    }
    #[test]
    fn registration_and_event_are_serialized_with_the_actual_owner_lock() {
        use crate::owner_lock::OwnerLock;
        let lock = OwnerLock::new();
        let mut f = Fixture::new();
        let mut p = process(&f);
        while lock.try_acquire(0).is_err() {}
        // A second CPU cannot mutate the pipe or perform its wake scan in
        // the check/register interval; these are the real ownership rules.
        assert_eq!(lock.try_acquire(1), Err(0));
        f.wait(0).register(&mut p, &f.pipes, false).unwrap();
        assert_eq!(p.state, ProcessState::Waiting);
        lock.release(0);
        while lock.try_acquire(1).is_err() {}
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(completion(&p, &f.pipes, false), Some(1));
        lock.release(1);
    }
    #[test]
    fn event_during_cpu_departure_is_seen_by_scheduler_reconciliation() {
        let mut f = Fixture::new();
        let mut p = process(&f);
        p.state = ProcessState::Runnable;
        p.claim_cpu(0);
        p.state = ProcessState::Running;
        f.wait(0).register(&mut p, &f.pipes, false).unwrap();
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(completion(&p, &f.pipes, false), None);
        p.cpu_owner = None;
        assert_eq!(completion(&p, &f.pipes, false), Some(1));
    }
    #[test]
    fn console_arrival_after_registration_is_level_triggered() {
        let mut f = Fixture::new();
        let mut p = process(&f);
        let console = p.handles.insert(Object::Console, RIGHT_READ).unwrap();
        let wait = ReadWait::capture(&[f.read, console], 0, 0).unwrap();
        wait.register(&mut p, &f.pipes, false).unwrap();
        assert_eq!(completion(&p, &f.pipes, false), None);
        assert_eq!(completion(&p, &f.pipes, true), Some(2));
        f.pipes.write(f.id, b"x").unwrap();
        assert_eq!(completion(&p, &f.pipes, true), Some(3));
    }
    #[test]
    fn deadline_never_completes_a_stopped_or_cpu_owned_waiter() {
        let f = Fixture::new();
        let mut p = process(&f);
        p.state = ProcessState::Runnable;
        p.claim_cpu(0);
        p.state = ProcessState::Running;
        f.wait(1).register(&mut p, &f.pipes, false).unwrap();
        assert_eq!(timeout_completion(&p, 102), None);
        p.cpu_owner = None;
        assert_eq!(
            timeout_completion(&p, 102),
            Some(crate::syscall::ERROR_TIMEOUT)
        );
        p.stop = crate::process::StopState::Requested;
        assert_eq!(timeout_completion(&p, 102), None);
    }
}
