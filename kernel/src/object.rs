//! Kernel objects reached through handles. The first is the cell: a 64-bit
//! value with a version that only advances through a conditional
//! transition ("change it only if it is still at the version I saw").
//!
//! Cells live in a fixed table and are reference counted by handles; the
//! last close (explicit, or implicit at process termination) frees the
//! slot. Freed slots get a new generation so a stale reference cannot alias
//! a later cell.
//!
//! Every live handle holds exactly one reference on its object, taken with
//! the rights that handle was issued with, and release is called with those
//! same rights. Creating an object issues its first handle reference; there
//! is no separate temporary creation reference.

use absd_abi::syscall::{RIGHT_READ, RIGHT_WRITE};

const HANDLE_READ: u8 = RIGHT_READ as u8;
const HANDLE_WRITE: u8 = RIGHT_WRITE as u8;

pub const MAX_CELLS: usize = 32;

/// Identifies one issue of a cell slot: index plus generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellId {
    index: u16,
    generation: u32,
}

impl CellId {
    /// An identifier that never resolves; only for handle-table tests.
    #[cfg(test)]
    pub const fn for_tests(index: u16) -> Self {
        Self {
            index,
            generation: u32::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Cell {
    refs: u32,
    generation: u32,
    version: u64,
    value: u64,
}

impl Cell {
    const EMPTY: Self = Self {
        refs: 0,
        generation: 0,
        version: 0,
        value: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellError {
    /// No live cell matches the identifier.
    Gone,
    /// The table is full.
    Full,
    /// The cell moved on; `current` is its version now.
    Stale { current: u64 },
}

pub struct CellTable {
    cells: [Cell; MAX_CELLS],
    live: usize,
}

impl CellTable {
    pub const fn new() -> Self {
        Self {
            cells: [Cell::EMPTY; MAX_CELLS],
            live: 0,
        }
    }
    pub fn live(&self) -> usize {
        self.live
    }
    fn slot(&self, id: CellId) -> Result<usize, CellError> {
        let index = id.index as usize;
        if index >= MAX_CELLS
            || self.cells[index].refs == 0
            || self.cells[index].generation != id.generation
        {
            return Err(CellError::Gone);
        }
        Ok(index)
    }
    /// Creates a cell at version 0 holding `value`, counting the first
    /// handle issued with `rights` as its one reference.
    pub fn create(&mut self, value: u64, _rights: u8) -> Result<CellId, CellError> {
        let index = self
            .cells
            .iter()
            .position(|cell| cell.refs == 0)
            .ok_or(CellError::Full)?;
        let cell = &mut self.cells[index];
        cell.refs = 1;
        cell.version = 0;
        cell.value = value;
        self.live += 1;
        Ok(CellId {
            index: index as u16,
            generation: cell.generation,
        })
    }
    /// Adds a reference (a second handle to the same cell).
    pub fn retain(&mut self, id: CellId) -> Result<(), CellError> {
        let index = self.slot(id)?;
        self.cells[index].refs += 1;
        Ok(())
    }
    /// Drops a reference; returns true if that freed the cell.
    pub fn release(&mut self, id: CellId) -> Result<bool, CellError> {
        let index = self.slot(id)?;
        let cell = &mut self.cells[index];
        cell.refs -= 1;
        if cell.refs != 0 {
            return Ok(false);
        }
        cell.generation = cell.generation.wrapping_add(1);
        cell.version = 0;
        cell.value = 0;
        self.live -= 1;
        Ok(true)
    }
    /// Current `(version, value)`.
    pub fn read(&self, id: CellId) -> Result<(u64, u64), CellError> {
        let index = self.slot(id)?;
        Ok((self.cells[index].version, self.cells[index].value))
    }
    /// Stores `value` only if the cell is still at `expected`; returns the
    /// new version. A mismatch changes nothing and reports the version now.
    pub fn transition(&mut self, id: CellId, expected: u64, value: u64) -> Result<u64, CellError> {
        let index = self.slot(id)?;
        let cell = &mut self.cells[index];
        if cell.version != expected {
            return Err(CellError::Stale {
                current: cell.version,
            });
        }
        cell.version += 1;
        cell.value = value;
        Ok(cell.version)
    }
}

impl Default for CellTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_requires_the_expected_version() {
        let mut table = CellTable::new();
        let id = table.create(5, HANDLE_READ | HANDLE_WRITE).unwrap();
        assert_eq!(table.read(id), Ok((0, 5)));
        assert_eq!(table.transition(id, 0, 6), Ok(1));
        assert_eq!(table.read(id), Ok((1, 6)));
        assert_eq!(
            table.transition(id, 0, 7),
            Err(CellError::Stale { current: 1 })
        );
        assert_eq!(table.read(id), Ok((1, 6)));
        assert_eq!(table.transition(id, 1, 7), Ok(2));
        assert_eq!(table.read(id), Ok((2, 7)));
    }

    #[test]
    fn references_free_the_slot_and_stale_ids_do_not_alias() {
        let mut table = CellTable::new();
        let first = table.create(1, HANDLE_READ | HANDLE_WRITE).unwrap();
        assert_eq!(table.retain(first), Ok(()));
        assert_eq!(table.release(first), Ok(false));
        assert_eq!(table.live(), 1);
        assert_eq!(table.release(first), Ok(true));
        assert_eq!(table.live(), 0);
        assert_eq!(table.read(first), Err(CellError::Gone));
        assert_eq!(table.release(first), Err(CellError::Gone));
        let second = table.create(2, HANDLE_READ | HANDLE_WRITE).unwrap();
        assert_eq!(second.index, first.index);
        assert_ne!(second, first);
        assert_eq!(table.read(first), Err(CellError::Gone));
        assert_eq!(table.read(second), Ok((0, 2)));
    }

    #[test]
    fn table_is_bounded() {
        let mut table = CellTable::new();
        for _ in 0..MAX_CELLS {
            assert!(table.create(0, HANDLE_READ | HANDLE_WRITE).is_ok());
        }
        assert_eq!(
            table.create(0, HANDLE_READ | HANDLE_WRITE),
            Err(CellError::Full)
        );
        assert_eq!(table.live(), MAX_CELLS);
    }
}

pub const MAX_PIPES: usize = 48;
pub const PIPE_CAPACITY: usize = 1024;

/// Identifies one issue of a pipe slot: index plus generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipeId {
    index: u16,
    generation: u32,
}

impl PipeId {
    /// An identifier that never resolves; only for handle-table tests.
    #[cfg(test)]
    pub const fn for_tests(index: u16) -> Self {
        Self {
            index,
            generation: u32::MAX,
        }
    }
}

/// A bounded first-in first-out byte stream between processes. Handles
/// carrying the read right count as readers and those carrying the write
/// right as writers, so the pipe knows when to report end of file (no
/// writers left) or refuse a write (no readers left).
#[derive(Clone, Copy)]
struct Pipe {
    refs: u32,
    readers: u32,
    writers: u32,
    generation: u32,
    head: usize,
    len: usize,
    ring: [u8; PIPE_CAPACITY],
}

impl Pipe {
    const EMPTY: Self = Self {
        refs: 0,
        readers: 0,
        writers: 0,
        generation: 0,
        head: 0,
        len: 0,
        ring: [0; PIPE_CAPACITY],
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeError {
    Gone,
    Full,
}

/// What one pipe looks like to a would-be reader or writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipeStatus {
    pub available: usize,
    pub space: usize,
    pub readers: u32,
    pub writers: u32,
}

pub struct PipeTable {
    pipes: [Pipe; MAX_PIPES],
    live: usize,
}

impl PipeTable {
    pub const fn new() -> Self {
        Self {
            pipes: [Pipe::EMPTY; MAX_PIPES],
            live: 0,
        }
    }
    pub fn live(&self) -> usize {
        self.live
    }
    fn slot(&self, id: PipeId) -> Result<usize, PipeError> {
        let index = id.index as usize;
        if index >= MAX_PIPES
            || self.pipes[index].refs == 0
            || self.pipes[index].generation != id.generation
        {
            return Err(PipeError::Gone);
        }
        Ok(index)
    }
    /// Creates an empty pipe, counting the first handle and its rights.
    pub fn create(&mut self, rights: u8) -> Result<PipeId, PipeError> {
        let index = self
            .pipes
            .iter()
            .position(|pipe| pipe.refs == 0)
            .ok_or(PipeError::Full)?;
        let pipe = &mut self.pipes[index];
        pipe.refs = 1;
        pipe.readers = (rights & HANDLE_READ != 0) as u32;
        pipe.writers = (rights & HANDLE_WRITE != 0) as u32;
        pipe.head = 0;
        pipe.len = 0;
        self.live += 1;
        Ok(PipeId {
            index: index as u16,
            generation: pipe.generation,
        })
    }
    /// Counts a new handle with the given read/write capabilities.
    pub fn retain(&mut self, id: PipeId, reads: bool, writes: bool) -> Result<(), PipeError> {
        let index = self.slot(id)?;
        let pipe = &mut self.pipes[index];
        pipe.refs += 1;
        pipe.readers += reads as u32;
        pipe.writers += writes as u32;
        Ok(())
    }
    /// Drops a handle; returns the pipe's status afterwards, or `None` if
    /// that was the last reference and the pipe is gone.
    pub fn release(
        &mut self,
        id: PipeId,
        reads: bool,
        writes: bool,
    ) -> Result<Option<PipeStatus>, PipeError> {
        let index = self.slot(id)?;
        let pipe = &mut self.pipes[index];
        pipe.refs -= 1;
        pipe.readers -= reads as u32;
        pipe.writers -= writes as u32;
        if pipe.refs != 0 {
            return Ok(Some(self.status(id)?));
        }
        pipe.generation = pipe.generation.wrapping_add(1);
        pipe.head = 0;
        pipe.len = 0;
        self.live -= 1;
        Ok(None)
    }
    pub fn status(&self, id: PipeId) -> Result<PipeStatus, PipeError> {
        let index = self.slot(id)?;
        let pipe = &self.pipes[index];
        Ok(PipeStatus {
            available: pipe.len,
            space: PIPE_CAPACITY - pipe.len,
            readers: pipe.readers,
            writers: pipe.writers,
        })
    }
    /// Appends as much of `bytes` as fits; returns the count taken.
    pub fn write(&mut self, id: PipeId, bytes: &[u8]) -> Result<usize, PipeError> {
        let index = self.slot(id)?;
        let pipe = &mut self.pipes[index];
        let count = bytes.len().min(PIPE_CAPACITY - pipe.len);
        for (offset, &byte) in bytes[..count].iter().enumerate() {
            pipe.ring[(pipe.head + pipe.len + offset) % PIPE_CAPACITY] = byte;
        }
        pipe.len += count;
        Ok(count)
    }
    /// Removes up to `buffer.len()` bytes in order; returns the count.
    pub fn read(&mut self, id: PipeId, buffer: &mut [u8]) -> Result<usize, PipeError> {
        let index = self.slot(id)?;
        let pipe = &mut self.pipes[index];
        let count = buffer.len().min(pipe.len);
        for slot in buffer[..count].iter_mut() {
            *slot = pipe.ring[pipe.head];
            pipe.head = (pipe.head + 1) % PIPE_CAPACITY;
        }
        pipe.len -= count;
        Ok(count)
    }
}

impl Default for PipeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod pipe_tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;

    #[test]
    fn bytes_come_out_in_order_across_the_wrap() {
        let mut table = Box::new(PipeTable::new());
        let id = table.create(HANDLE_READ | HANDLE_WRITE).unwrap();
        let mut out = [0u8; 700];
        for round in 0..5u8 {
            let mut chunk = [0u8; 700];
            for (index, byte) in chunk.iter_mut().enumerate() {
                *byte = round.wrapping_mul(31).wrapping_add(index as u8);
            }
            assert_eq!(table.write(id, &chunk), Ok(700));
            assert_eq!(table.status(id).unwrap().available, 700);
            assert_eq!(table.read(id, &mut out), Ok(700));
            assert_eq!(out, chunk);
        }
        assert_eq!(table.read(id, &mut out), Ok(0));
    }

    #[test]
    fn writes_are_bounded_by_capacity() {
        let mut table = Box::new(PipeTable::new());
        let id = table.create(HANDLE_READ | HANDLE_WRITE).unwrap();
        let big = [7u8; PIPE_CAPACITY + 100];
        assert_eq!(table.write(id, &big), Ok(PIPE_CAPACITY));
        assert_eq!(table.write(id, &big), Ok(0));
        let status = table.status(id).unwrap();
        assert_eq!((status.available, status.space), (PIPE_CAPACITY, 0));
        let mut out = [0u8; 100];
        assert_eq!(table.read(id, &mut out), Ok(100));
        assert_eq!(table.write(id, &big), Ok(100));
    }

    #[test]
    fn reader_and_writer_counts_follow_handle_rights() {
        let mut table = Box::new(PipeTable::new());
        let id = table.create(HANDLE_READ | HANDLE_WRITE).unwrap();
        table.retain(id, true, false).unwrap();
        table.retain(id, false, true).unwrap();
        let status = table.status(id).unwrap();
        assert_eq!((status.readers, status.writers), (2, 2));
        let after = table.release(id, true, true).unwrap().unwrap();
        assert_eq!((after.readers, after.writers), (1, 1));
        let after = table.release(id, false, true).unwrap().unwrap();
        assert_eq!((after.readers, after.writers), (1, 0));
        assert_eq!(table.release(id, true, false), Ok(None));
        assert_eq!(table.live(), 0);
        assert_eq!(table.status(id), Err(PipeError::Gone));
        let again = table.create(HANDLE_READ | HANDLE_WRITE).unwrap();
        assert_ne!(again, id);
        assert_eq!(table.status(id), Err(PipeError::Gone));
    }

    #[test]
    fn table_is_bounded() {
        let mut table = Box::new(PipeTable::new());
        for _ in 0..MAX_PIPES {
            assert!(table.create(0).is_ok());
        }
        assert_eq!(table.create(0), Err(PipeError::Full));
    }

    #[test]
    fn arbitrary_handle_sequences_keep_pipe_reference_counts_balanced() {
        const SLOTS: usize = 32;
        let mut table = Box::new(PipeTable::new());
        let id = table.create(HANDLE_READ).unwrap();
        let mut handles = [None; SLOTS];
        handles[0] = Some((true, false));
        let mut random = 0x6d2b_79f5u32;

        for _ in 0..512 {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            let count = handles.iter().filter(|entry| entry.is_some()).count();
            let add = count == 1 || (count < SLOTS && random & 1 == 0);
            if add {
                let slot = handles.iter().position(Option::is_none).unwrap();
                let reads = random & 2 != 0;
                let writes = random & 4 != 0;
                table.retain(id, reads, writes).unwrap();
                handles[slot] = Some((reads, writes));
            } else {
                let mut ordinal = random as usize % count;
                let slot = handles
                    .iter()
                    .position(|entry| {
                        if entry.is_some() {
                            if ordinal == 0 {
                                return true;
                            }
                            ordinal -= 1;
                        }
                        false
                    })
                    .unwrap();
                let (reads, writes) = handles[slot].take().unwrap();
                assert!(table.release(id, reads, writes).unwrap().is_some());
            }

            let refs = handles.iter().filter(|entry| entry.is_some()).count() as u32;
            let readers = handles.iter().flatten().filter(|(reads, _)| *reads).count() as u32;
            let writers = handles
                .iter()
                .flatten()
                .filter(|(_, writes)| *writes)
                .count() as u32;
            let status = table.status(id).unwrap();
            assert_eq!(table.pipes[id.index as usize].refs, refs);
            assert_eq!((status.readers, status.writers), (readers, writers));
        }

        let mut remaining = handles.iter().flatten().copied().peekable();
        while let Some((reads, writes)) = remaining.next() {
            let result = table.release(id, reads, writes).unwrap();
            assert_eq!(result.is_some(), remaining.peek().is_some());
        }
        assert_eq!(table.live(), 0);
        assert_eq!(table.status(id), Err(PipeError::Gone));
    }
}
