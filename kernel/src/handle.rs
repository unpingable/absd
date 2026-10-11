//! Per-process handle tables: the first ABSD-native object model.
//!
//! A handle is an opaque 64-bit value that only means something to the
//! process that owns the table it came from. The low byte is a slot index;
//! the rest is a tag unique to that issue of the slot, so a stale handle
//! (closed, or reaped) and a handle guessed from another process both fail
//! lookup. Rights are fixed at issue time and checked on every use.

use crate::object::{CellId, PipeId};

pub const MAX_HANDLES: usize = 64;
const INDEX_BITS: u32 = 8;
const INDEX_MASK: u64 = (1 << INDEX_BITS) - 1;

pub const RIGHT_WRITE: u8 = crate::syscall::RIGHT_WRITE as u8;
pub const RIGHT_WAIT: u8 = crate::syscall::RIGHT_WAIT as u8;
pub const RIGHT_READ: u8 = crate::syscall::RIGHT_READ as u8;
pub const RIGHT_KILL: u8 = crate::syscall::RIGHT_KILL as u8;
pub const ALL_RIGHTS: u8 = RIGHT_WRITE | RIGHT_WAIT | RIGHT_READ | RIGHT_KILL;

/// The kernel object a handle refers to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Object {
    None,
    /// The process-local serial output endpoint.
    Console,
    /// A child process, by PID.
    Process(u64),
    /// A versioned cell in the kernel object table.
    Cell(CellId),
    /// A bounded byte stream in the kernel object table.
    Pipe(PipeId),
    /// The one probed block storage device, addressed by sector.
    Block,
    /// The one probed network interface: whole Ethernet frames.
    Nic,
    /// The machine itself: the authority to end or restart it. The kernel
    /// issues one handle to init at boot and none to anything else.
    Machine,
}

impl Object {
    /// Rights have object-local meaning. Reject impossible combinations at
    /// the single handle-issue boundary rather than trusting every caller.
    pub const fn valid_rights(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Console | Self::Cell(_) | Self::Pipe(_) | Self::Block | Self::Nic => {
                RIGHT_READ | RIGHT_WRITE
            }
            Self::Process(_) => RIGHT_WAIT | RIGHT_KILL,
            // Stop now (the kill bit), restart at the end of the boot (the
            // write bit), and reset now without accounting (the wait bit):
            // `MACHINE_RIGHT_STOP`, `MACHINE_RIGHT_RESTART`,
            // `MACHINE_RIGHT_RECOVER`.
            Self::Machine => RIGHT_KILL | RIGHT_WRITE | RIGHT_WAIT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    pub object: Object,
    pub rights: u8,
    tag: u64,
}

impl Handle {
    const EMPTY: Self = Self {
        object: Object::None,
        rights: 0,
        tag: 0,
    };
    /// Every bit of `rights` must be held; a handle of the right kind that
    /// lacks a right is a distinct failure from a handle of the wrong kind.
    pub const fn require(&self, rights: u8) -> Result<(), HandleError> {
        #[cfg(absd_mutant_no_rights_check)]
        {
            let _ = rights;
            return Ok(());
        }
        #[cfg(not(absd_mutant_no_rights_check))]
        if self.rights & rights == rights {
            Ok(())
        } else {
            Err(HandleError::Rights)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleError {
    /// No live handle has this value in the caller's table.
    Invalid,
    /// The handle exists but lacks a required right.
    Rights,
    /// The table is full.
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleTable {
    slots: [Handle; MAX_HANDLES],
    next_tag: u64,
}

impl HandleTable {
    /// `seed` distinguishes tables from one another (the owner's PID).
    pub const fn new(seed: u64) -> Self {
        Self {
            slots: [Handle::EMPTY; MAX_HANDLES],
            next_tag: (seed << 24) | 1,
        }
    }
    const fn encode(index: usize, tag: u64) -> u64 {
        (tag << INDEX_BITS) | index as u64
    }
    pub fn has_free_slot(&self) -> bool {
        self.slots.iter().any(|slot| slot.object == Object::None)
    }
    pub fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.object != Object::None)
            .count()
    }
    /// Issues a handle for `object`; the value is never zero.
    pub fn insert(&mut self, object: Object, rights: u8) -> Result<u64, HandleError> {
        if object == Object::None {
            return Err(HandleError::Invalid);
        }
        if rights & !object.valid_rights() != 0 {
            return Err(HandleError::Rights);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.object == Object::None)
            .ok_or(HandleError::Full)?;
        let tag = self.next_tag;
        self.next_tag += 1;
        self.slots[index] = Handle {
            object,
            rights,
            tag,
        };
        Ok(Self::encode(index, tag))
    }
    /// Issues an ordered batch of handles. If any insertion fails, every
    /// handle issued by this call is removed before the error is returned.
    /// Object references are deliberately not managed here: callers take
    /// them only after the complete batch has been installed.
    pub fn insert_batch(
        &mut self,
        requested: &[(Object, u8)],
        issued: &mut [u64],
    ) -> Result<(), HandleError> {
        if issued.len() < requested.len() {
            return Err(HandleError::Full);
        }
        let mut installed = 0;
        for &(object, rights) in requested {
            match self.insert(object, rights) {
                Ok(handle) => {
                    issued[installed] = handle;
                    installed += 1;
                }
                Err(error) => {
                    for &handle in &issued[..installed] {
                        let _ = self.close(handle);
                    }
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    fn slot(&self, value: u64) -> Result<usize, HandleError> {
        let index = (value & INDEX_MASK) as usize;
        let tag = value >> INDEX_BITS;
        if index >= MAX_HANDLES
            || self.slots[index].object == Object::None
            || (!cfg!(absd_mutant_handle_ignore_tag) && self.slots[index].tag != tag)
        {
            return Err(HandleError::Invalid);
        }
        Ok(index)
    }
    /// Resolves a handle to its object and rights.
    pub fn lookup(&self, value: u64) -> Result<Handle, HandleError> {
        self.slot(value).map(|index| self.slots[index])
    }
    /// Resolves a handle that must refer to a console with `rights`.
    pub fn console(&self, value: u64, rights: u8) -> Result<(), HandleError> {
        let handle = self.lookup(value)?;
        if handle.object != Object::Console {
            return Err(HandleError::Invalid);
        }
        handle.require(rights)
    }
    /// The complete console authority this process may derive into a child.
    /// Multiple narrowed handles may contribute disjoint rights.
    pub fn console_rights(&self) -> u8 {
        self.slots
            .iter()
            .filter(|handle| handle.object == Object::Console)
            .fold(0, |rights, handle| rights | handle.rights)
    }
    /// Resolves a handle that must refer to a pipe with `rights`.
    pub fn pipe(&self, value: u64, rights: u8) -> Result<PipeId, HandleError> {
        let handle = self.lookup(value)?;
        let Object::Pipe(id) = handle.object else {
            return Err(HandleError::Invalid);
        };
        handle.require(rights)?;
        Ok(id)
    }
    /// Resolves a handle that must refer to a cell with `rights`.
    pub fn cell(&self, value: u64, rights: u8) -> Result<CellId, HandleError> {
        let handle = self.lookup(value)?;
        let Object::Cell(id) = handle.object else {
            return Err(HandleError::Invalid);
        };
        handle.require(rights)?;
        Ok(id)
    }
    /// Issues a second handle to `value`'s object holding only `rights`,
    /// which must be a subset of the original's. The caller owns the
    /// object reference the new handle implies.
    pub fn duplicate(&mut self, value: u64, rights: u8) -> Result<(u64, Object), HandleError> {
        let handle = self.lookup(value)?;
        if (rights & !handle.rights != 0
            && !(cfg!(absd_mutant_cell_duplicate_widen)
                && matches!(handle.object, Object::Cell(_))))
            || rights & !ALL_RIGHTS != 0
        {
            return Err(HandleError::Rights);
        }
        let issued = self.insert(handle.object, rights)?;
        Ok((issued, handle.object))
    }
    /// Removes and returns every live handle, for termination.
    pub fn drain(&mut self) -> impl Iterator<Item = Handle> + '_ {
        self.slots.iter_mut().filter_map(|slot| {
            if slot.object == Object::None {
                None
            } else {
                Some(core::mem::replace(slot, Handle::EMPTY))
            }
        })
    }
    /// Removes and returns one live handle, if any: lets termination release
    /// objects one at a time without holding a borrow on the table.
    pub fn take_any(&mut self) -> Option<Handle> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.object != Object::None)?;
        Some(core::mem::replace(slot, Handle::EMPTY))
    }
    /// Resolves a handle that must refer to a process with `rights`.
    pub fn process(&self, value: u64, rights: u8) -> Result<u64, HandleError> {
        let handle = self.lookup(value)?;
        let Object::Process(pid) = handle.object else {
            return Err(HandleError::Invalid);
        };
        handle.require(rights)?;
        Ok(pid)
    }
    /// Releases a handle; its value is never valid again. Returns what it
    /// held so the caller can drop the object reference.
    pub fn close(&mut self, value: u64) -> Result<Handle, HandleError> {
        let index = self.slot(value)?;
        Ok(core::mem::replace(&mut self.slots[index], Handle::EMPTY))
    }
    /// Releases every handle referring to process `pid`.
    pub fn close_process(&mut self, pid: u64) -> usize {
        let mut closed = 0;
        for slot in self.slots.iter_mut() {
            if slot.object == Object::Process(pid) {
                *slot = Handle::EMPTY;
                closed += 1;
            }
        }
        closed
    }
    /// Read-only qualification predicate for a Created child whose handle
    /// must be rolled back before its spawner can be reclaimed.
    pub fn has_process(&self, pid: u64) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.object == Object::Process(pid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn w1_seven_live_kinds_require_review_before_eighth() {
        // This exhaustive match is a review tripwire: adding an Object
        // variant must account for its kind here and in the W1 disposition.
        fn kind(object: Object) -> Option<usize> {
            match object {
                Object::None => None,
                Object::Console => Some(0),
                Object::Process(_) => Some(1),
                Object::Cell(_) => Some(2),
                Object::Pipe(_) => Some(3),
                Object::Block => Some(4),
                Object::Nic => Some(5),
                Object::Machine => Some(6),
            }
        }

        let witnesses = [
            Object::Console,
            Object::Process(1),
            Object::Cell(CellId::for_tests(1)),
            Object::Pipe(PipeId::for_tests(1)),
            Object::Block,
            Object::Nic,
            Object::Machine,
        ];
        assert_eq!(witnesses.len(), 7);
        assert_eq!(kind(Object::None), None);
        let mut seen = 0u8;
        for object in witnesses {
            let index = kind(object).expect("live kind");
            assert!(index < 7);
            let bit = 1u8 << index;
            assert_eq!(seen & bit, 0, "duplicate kind index");
            seen |= bit;
        }
        assert_eq!(seen, 0x7f);
    }

    #[test]
    fn handles_are_nonzero_unique_and_checked_for_rights() {
        let mut table = HandleTable::new(7);
        let console = table.insert(Object::Console, RIGHT_WRITE).unwrap();
        let child = table
            .insert(Object::Process(9), RIGHT_WAIT | RIGHT_KILL)
            .unwrap();
        assert_ne!(console, 0);
        assert_ne!(console, child);
        assert_eq!(table.console(console, RIGHT_WRITE), Ok(()));
        assert_eq!(table.console(console, RIGHT_WAIT), Err(HandleError::Rights));
        assert_eq!(table.process(console, 0), Err(HandleError::Invalid));
        assert_eq!(table.process(child, RIGHT_WAIT), Ok(9));
        assert_eq!(table.process(child, RIGHT_KILL), Ok(9));
        assert_eq!(table.process(child, RIGHT_WRITE), Err(HandleError::Rights));
        assert_eq!(table.console(child, 0), Err(HandleError::Invalid));
        assert_eq!(table.lookup(0), Err(HandleError::Invalid));
        assert_eq!(table.lookup(1), Err(HandleError::Invalid));
        assert_eq!(table.live_count(), 2);
    }

    #[test]
    fn duplicates_may_only_narrow_rights() {
        let mut table = HandleTable::new(4);
        let cell = table
            .insert(Object::Cell(CellId::for_tests(1)), RIGHT_READ | RIGHT_WRITE)
            .unwrap();
        let (readonly, object) = table.duplicate(cell, RIGHT_READ).unwrap();
        assert_eq!(object, Object::Cell(CellId::for_tests(1)));
        assert_ne!(readonly, cell);
        assert_eq!(table.cell(readonly, RIGHT_READ), Ok(CellId::for_tests(1)));
        assert_eq!(table.cell(readonly, RIGHT_WRITE), Err(HandleError::Rights));
        assert_eq!(
            table.duplicate(readonly, RIGHT_READ | RIGHT_WRITE),
            Err(HandleError::Rights)
        );
        assert_eq!(table.duplicate(cell, RIGHT_WAIT), Err(HandleError::Rights));
        assert_eq!(table.duplicate(cell, 1 << 7), Err(HandleError::Rights));
        assert_eq!(table.duplicate(0, RIGHT_READ), Err(HandleError::Invalid));
        assert_eq!(
            table.cell(cell, RIGHT_READ | RIGHT_WRITE),
            Ok(CellId::for_tests(1))
        );
        assert_eq!(table.live_count(), 2);
    }

    #[test]
    fn issue_paths_reject_rights_outside_each_object_kind() {
        let mut table = HandleTable::new(5);
        assert_eq!(
            table.insert(Object::Console, RIGHT_WAIT),
            Err(HandleError::Rights)
        );
        assert_eq!(
            table.insert(Object::Cell(CellId::for_tests(2)), RIGHT_KILL),
            Err(HandleError::Rights)
        );
        assert_eq!(
            table.insert(Object::Pipe(PipeId::for_tests(3)), RIGHT_WAIT),
            Err(HandleError::Rights)
        );
        assert_eq!(
            table.insert(Object::Process(7), RIGHT_READ),
            Err(HandleError::Rights)
        );
        assert_eq!(
            table.insert(Object::Machine, RIGHT_READ),
            Err(HandleError::Rights)
        );
        // Stop (kill bit), restart (write bit), and recover (wait bit) are
        // three separate machine rights.
        for right in [
            crate::syscall::MACHINE_RIGHT_STOP,
            crate::syscall::MACHINE_RIGHT_RESTART,
            crate::syscall::MACHINE_RIGHT_RECOVER,
        ] {
            let handle = table
                .insert(Object::Machine, right as u8)
                .expect("machine right within its kind");
            table.close(handle).expect("close machine handle");
        }
        let mut issued = [0; 2];
        assert_eq!(
            table.insert_batch(
                &[
                    (Object::Console, RIGHT_WRITE),
                    (Object::Process(7), RIGHT_WRITE),
                ],
                &mut issued,
            ),
            Err(HandleError::Rights)
        );
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn console_authority_is_the_union_of_live_console_handles() {
        let mut table = HandleTable::new(6);
        let write = table.insert(Object::Console, RIGHT_WRITE).unwrap();
        let read = table.insert(Object::Console, RIGHT_READ).unwrap();
        table.insert(Object::Process(9), RIGHT_WAIT).unwrap();
        assert_eq!(table.console_rights(), RIGHT_READ | RIGHT_WRITE);
        table.close(read).unwrap();
        assert_eq!(table.console_rights(), RIGHT_WRITE);
        table.close(write).unwrap();
        assert_eq!(table.console_rights(), 0);
    }

    #[test]
    fn process_handles_split_wait_and_kill_rights() {
        let mut table = HandleTable::new(10);
        let process = table
            .insert(Object::Process(11), RIGHT_WAIT | RIGHT_KILL)
            .unwrap();
        let (wait_only, _) = table.duplicate(process, RIGHT_WAIT).unwrap();
        let (kill_only, _) = table.duplicate(process, RIGHT_KILL).unwrap();
        assert_eq!(table.process(wait_only, RIGHT_WAIT), Ok(11));
        assert_eq!(
            table.process(wait_only, RIGHT_KILL),
            Err(HandleError::Rights)
        );
        assert_eq!(table.process(kill_only, RIGHT_KILL), Ok(11));
        assert_eq!(
            table.process(kill_only, RIGHT_WAIT),
            Err(HandleError::Rights)
        );
        assert_eq!(
            table.duplicate(wait_only, RIGHT_WAIT | RIGHT_KILL),
            Err(HandleError::Rights)
        );
    }

    #[test]
    fn closed_and_reissued_slots_reject_stale_values() {
        let mut table = HandleTable::new(1);
        let first = table.insert(Object::Console, RIGHT_WRITE).unwrap();
        assert_eq!(table.close(first).map(|h| h.object), Ok(Object::Console));
        assert_eq!(table.close(first), Err(HandleError::Invalid));
        assert_eq!(table.lookup(first), Err(HandleError::Invalid));
        let second = table.insert(Object::Console, RIGHT_WRITE).unwrap();
        assert_eq!(second & INDEX_MASK, first & INDEX_MASK);
        assert_ne!(second, first);
        assert_eq!(table.lookup(first), Err(HandleError::Invalid));
        assert_eq!(table.console(second, RIGHT_WRITE), Ok(()));
    }

    #[test]
    fn tables_of_different_processes_do_not_share_values() {
        let mut a = HandleTable::new(1);
        let mut b = HandleTable::new(2);
        let from_a = a.insert(Object::Console, RIGHT_WRITE).unwrap();
        let from_b = b.insert(Object::Console, RIGHT_WRITE).unwrap();
        assert_ne!(from_a, from_b);
        assert_eq!(b.lookup(from_a), Err(HandleError::Invalid));
        assert_eq!(a.lookup(from_b), Err(HandleError::Invalid));
    }

    #[test]
    fn table_is_bounded_and_process_handles_close_by_pid() {
        let mut table = HandleTable::new(3);
        for _ in 0..MAX_HANDLES {
            assert!(table.insert(Object::Process(5), RIGHT_WAIT).is_ok());
        }
        assert!(!table.has_free_slot());
        assert_eq!(
            table.insert(Object::Console, RIGHT_WRITE),
            Err(HandleError::Full)
        );
        assert_eq!(table.close_process(5), MAX_HANDLES);
        assert_eq!(table.live_count(), 0);
        assert_eq!(table.insert(Object::None, 0), Err(HandleError::Invalid));
    }

    #[test]
    fn batch_insert_rolls_back_after_mid_operation_capacity_failure() {
        let mut table = HandleTable::new(8);
        for _ in 0..MAX_HANDLES - 1 {
            table.insert(Object::Console, RIGHT_WRITE).unwrap();
        }
        let before = table.live_count();
        let mut issued = [0; 2];
        assert_eq!(
            table.insert_batch(
                &[
                    (Object::Cell(CellId::for_tests(2)), RIGHT_READ),
                    (Object::Cell(CellId::for_tests(2)), RIGHT_WRITE),
                ],
                &mut issued,
            ),
            Err(HandleError::Full)
        );
        assert_eq!(table.live_count(), before);
        assert_eq!(table.lookup(issued[0]), Err(HandleError::Invalid));
    }

    #[test]
    fn batch_insert_rolls_back_an_invalid_later_entry() {
        let mut table = HandleTable::new(9);
        let before = table.live_count();
        let mut issued = [0; 2];
        assert_eq!(
            table.insert_batch(
                &[(Object::Console, RIGHT_WRITE), (Object::None, 0)],
                &mut issued,
            ),
            Err(HandleError::Invalid)
        );
        assert_eq!(table.live_count(), before);
        assert_eq!(table.lookup(issued[0]), Err(HandleError::Invalid));
    }
}
