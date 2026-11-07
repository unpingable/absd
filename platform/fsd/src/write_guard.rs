//! Writable entry's durable guard (schema v1, 512 bytes).
//!
//! A fresh image's trusted constructor seeds `Fresh` once. The file is
//! never created, resized, renamed or removed by a running service. Before
//! any other mutation, the service writes the same `Dirty` sector and
//! flushes it, without filesystem metadata writes. Failure at that step
//! permits no other mutation; a delayed dirty write can only make a later
//! boot refuse. A completed same-boot finalizer writes `Clean` last.
//!
//! Missing state is unknown. In particular, absence of the recovery ledger
//! after a failed first startup does not restore first-boot admission.
//!
//! Path (e), operator-authorized resume (`crate::resume`): a serving entry
//! (`Resume::Allowed`) admits a `Dirty` guard whose history is `Failed` or
//! `NotReady` when, and only when, the resume slot holds a record naming
//! exactly this disk's committed state. The guard is left `dirty`; the
//! record is consumed back to `none` as the first device write. Every
//! other entry (`Resume::Never`: the finalizer, enrollment, bounded
//! updates) never consults the slot and refuses as before.

use absd_fs::{Device, Error, Fs, OpenFlags, SECTOR};
use crate::recovery::{self, Boot, Previous, Refusal};
use crate::resume;

pub const PATH: &[u8] = b"/var/recovery.guard";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State { Fresh, Dirty, Clean }

impl State {
    pub const fn bytes(self) -> [u8; SECTOR] {
        let line: &[u8] = match self {
            Self::Fresh => b"absd-writable v1 fresh\n",
            Self::Dirty => b"absd-writable v1 dirty\n",
            Self::Clean => b"absd-writable v1 clean\n",
        };
        let mut out = [0; SECTOR];
        let mut at = 0;
        while at < line.len() { out[at] = line[at]; at += 1; }
        out
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        [Self::Fresh, Self::Dirty, Self::Clean].into_iter()
            .find(|state| bytes == state.bytes())
    }
}

/// Whether an entry may be admitted by an operator's resume record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resume {
    /// The serving file server (either program): the one entry that
    /// consumes a record.
    Allowed,
    /// The finalizer, enrollment and bounded updates: the slot is not read.
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission {
    pub previous: Previous,
    marker: State,
    /// The checked record this entry was admitted by, if any; consumed by
    /// [`begin`].
    resume: Option<resume::Record>,
}

impl Admission {
    /// The resume record this entry was admitted by, if any.
    pub fn resumed(&self) -> Option<&resume::Record> {
        self.resume.as_ref()
    }
}

fn read<D: Device>(fs: &mut Fs<D>) -> Result<State, Refusal> {
    let attr = fs.stat(PATH).map_err(|error| match error {
        Error::NotFound => Refusal::GuardMissing,
        other => Refusal::Storage(other),
    })?;
    if attr.kind != absd_fs::Kind::File || attr.size != SECTOR as u64 || attr.readonly {
        return Err(Refusal::GuardCorrupt);
    }
    let handle = fs.open(PATH, OpenFlags { read: true, ..OpenFlags::default() })
        .map_err(Refusal::Storage)?;
    let mut bytes = [0u8; SECTOR];
    let result = fs.read_at(handle, 0, &mut bytes);
    fs.close(handle).map_err(Refusal::Storage)?;
    if result.map_err(Refusal::Storage)? != SECTOR { return Err(Refusal::GuardCorrupt); }
    State::parse(&bytes).ok_or(Refusal::GuardCorrupt)
}

/// Read-only assessment shared by served and bounded file-server boots.
/// The resume arm replaces exactly the `(Dirty, Failed | NotReady)`
/// refusal, and only when the slot holds a record that checks against
/// this mount's state; a missing slot or `none` refuses as before, a
/// corrupt slot or a record naming another state refuses by name.
pub fn assess<D: Device>(fs: &mut Fs<D>, resume: Resume) -> Result<Admission, Refusal> {
    let marker = read(fs)?;
    let history = recovery::history(fs)?;
    let previous = history.previous;
    match (marker, previous) {
        (State::Fresh, Previous::None) | (State::Clean, Previous::Ended) => {
            Ok(Admission { previous, marker, resume: None })
        }
        (State::Dirty, Previous::Failed | Previous::NotReady) if resume == Resume::Allowed => {
            let record = match resume::read(fs)? {
                Some(resume::Slot::Record(record)) => record,
                Some(resume::Slot::None) | None => return Err(Refusal::Unfenced(previous)),
            };
            let Some(ledger) = history.ledger else { return Err(Refusal::Unfenced(previous)); };
            let state = resume::State {
                fs: fs.fs_id(),
                seq: fs.sequence(),
                image: fs.image_digest(),
                ledger_seq: ledger.seq,
                ledger_boot: ledger.boot,
                previous,
            };
            if resume::checks(&record, &state) {
                Ok(Admission { previous, marker, resume: Some(record) })
            } else {
                Err(Refusal::ResumeMismatch)
            }
        }
        _ => Err(Refusal::Unfenced(previous)),
    }
}

/// First mutation on writable entry. Recheck the read-only assessment and
/// leave the durable dirty marker before any metadata or user-data write.
/// An entry admitted by a resume record leaves the guard alone (it is
/// already dirty) and consumes the record instead: one sector write of
/// `none` at the slot and its flush, the first device write of the boot.
/// Failure of either poisons the mount and nothing else is written; a
/// delayed effect can only write `none`.
pub fn begin<D: Device>(fs: &mut Fs<D>, expected: Admission) -> Result<(), Refusal> {
    let mode = if expected.resume.is_some() { Resume::Allowed } else { Resume::Never };
    if assess(fs, mode)? != expected { return Err(Refusal::GuardCorrupt); }
    match expected.resume {
        Some(record) => fs
            .transition_sector_marker(resume::PATH, &resume::encode(&record), &resume::none())
            .map_err(Refusal::Storage),
        None => fs
            .transition_sector_marker(PATH, &expected.marker.bytes(), &State::Dirty.bytes())
            .map_err(Refusal::Storage),
    }
}

/// A bounded offline update (enrollment) changes no recovery facts. The
/// caller owns this writer and has completed all its work successfully.
/// Restore its original admission state only after sync and an unchanged
/// history check; failures retain dirty just as normal service failures do.
/// An entry admitted by a resume record is never a bounded update.
pub fn finish_update<D: Device>(fs: &mut Fs<D>, entry: Admission) -> Result<(), Refusal> {
    if entry.resume.is_some() || read(fs)? != State::Dirty || recovery::assess(fs)? != entry.previous {
        return Err(Refusal::GuardCorrupt);
    }
    fs.sync().map_err(Refusal::Storage)?;
    fs.transition_sector_marker(PATH, &State::Dirty.bytes(), &entry.marker.bytes())
        .map_err(Refusal::Storage)
}

/// Finalization is same-boot continuation under init's retained authority,
/// not recovery of an earlier unclean generation.
pub fn assess_finalization<D: Device>(
    fs: &mut Fs<D>, boot: &Boot, bounded: bool,
) -> Result<(), Refusal> {
    if read(fs)? != State::Dirty || !recovery::finalization_matches(fs, boot, bounded)? {
        return Err(Refusal::GuardCorrupt);
    }
    Ok(())
}

/// Only init's checked same-boot finalizer calls this after all services
/// and descendants have ended. The clean marker is the last mutation.
pub fn finish<D: Device>(fs: &mut Fs<D>, boot: &Boot, bounded: bool) -> Result<(), Refusal> {
    assess_finalization(fs, boot, bounded)?;
    recovery::completed_as(fs, boot, bounded).map_err(Refusal::Storage)?;
    fs.sync().map_err(Refusal::Storage)?;
    fs.transition_sector_marker(PATH, &State::Dirty.bytes(), &State::Clean.bytes())
        .map_err(Refusal::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
    use core::cell::RefCell;

    #[derive(Default, Clone)]
    struct Image {
        sectors: BTreeMap<u64, [u8; SECTOR]>,
        writes: usize,
        flushes: usize,
        fail_write: Option<usize>,
        fail_flush: Option<usize>,
        held: Vec<(u64, [u8; SECTOR])>,
    }
    #[derive(Clone, Default)]
    struct Disk(Rc<RefCell<Image>>);
    impl Device for Disk {
        fn sectors(&self) -> u64 { 2048 }
        fn read(&mut self, lba: u64, out: &mut [u8; SECTOR]) -> Result<(), Error> {
            *out = self.0.borrow().sectors.get(&lba).copied().unwrap_or([0; SECTOR]);
            Ok(())
        }
        fn write(&mut self, lba: u64, bytes: &[u8; SECTOR]) -> Result<(), Error> {
            let mut disk = self.0.borrow_mut();
            disk.writes += 1;
            if disk.fail_write == Some(disk.writes) {
                disk.fail_write = None;
                disk.held.push((lba, *bytes));
                return Err(Error::Device(-5));
            }
            disk.sectors.insert(lba, *bytes);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), Error> {
            let mut disk = self.0.borrow_mut();
            disk.flushes += 1;
            if disk.fail_flush == Some(disk.flushes) {
                disk.fail_flush = None;
                return Err(Error::Device(-5));
            }
            Ok(())
        }
    }
    fn put(fs: &mut Fs<Disk>, path: &[u8], bytes: &[u8]) {
        let handle = fs.open(path, OpenFlags { write: true, create: true,
            ..OpenFlags::default() }).unwrap();
        assert_eq!(fs.write_at(handle, 0, bytes).unwrap(), bytes.len());
        fs.close(handle).unwrap();
        fs.sync().unwrap();
    }
    fn image(seed: Option<&[u8]>) -> Disk {
        let disk = Disk::default();
        absd_fs::format(&mut disk.clone(), 7).unwrap();
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        fs.mkdir(b"/var").unwrap();
        if let Some(bytes) = seed { put(&mut fs, PATH, bytes); }
        fs.sync().unwrap();
        disk
    }
    fn boot() -> Boot { [b'1'; 32] }
    fn counters(disk: &Disk) -> (usize, usize) {
        let d = disk.0.borrow(); (d.writes, d.flushes)
    }
    fn assessment(disk: &Disk) -> Result<Admission, Refusal> {
        let before = counters(disk);
        let mut fs = Fs::mount(disk.clone(), false).unwrap();
        let result = assess(&mut fs, Resume::Allowed);
        assert_eq!(counters(disk), before, "read-only admission issued write/flush");
        result
    }
    fn release_held(disk: &Disk) {
        let held = core::mem::take(&mut disk.0.borrow_mut().held);
        for (lba, bytes) in held { disk.0.borrow_mut().sectors.insert(lba, bytes); }
    }
    fn stopped_boot(bounded: bool) -> Disk {
        let disk = image(Some(&State::Fresh.bytes()));
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        let entry = assess(&mut fs, Resume::Never).unwrap();
        begin(&mut fs, entry).unwrap();
        recovery::charge(&mut fs, &boot()).unwrap();
        if !bounded {
            put(&mut fs, recovery::SERVED_READY, &recovery::format_fact(&boot(), None));
            put(&mut fs, recovery::SERVED_END, &recovery::format_fact(&boot(), Some("halt")));
        }
        recovery::stopped(&mut fs, &boot()).unwrap();
        fs.sync().unwrap();
        disk
    }

    #[test]
    fn schema_matches_shared_golden_sectors_and_refuses_partial_seeds() {
        for (state, golden) in [
            (State::Fresh, include_bytes!("../../fixtures/storage-fence/guard-v1-fresh.bin")),
            (State::Dirty, include_bytes!("../../fixtures/storage-fence/guard-v1-dirty.bin")),
            (State::Clean, include_bytes!("../../fixtures/storage-fence/guard-v1-clean.bin")),
        ] {
            assert_eq!(&state.bytes(), golden);
            assert_eq!(State::parse(golden), Some(state));
            assert_eq!(State::parse(&golden[..SECTOR - 1]), None);
            for at in 0..SECTOR {
                let mut changed = *golden;
                changed[at] ^= 1;
                assert_eq!(State::parse(&changed), None);
            }
        }
        assert_eq!(assessment(&image(None)), Err(Refusal::GuardMissing));
        for bytes in [&[0u8; SECTOR][..], &State::Fresh.bytes()[..SECTOR - 1]] {
            assert_eq!(assessment(&image(Some(bytes))), Err(Refusal::GuardCorrupt));
        }
    }

    #[test]
    fn arming_is_one_sector_and_one_flush_without_metadata_changes() {
        let disk = image(Some(&State::Fresh.bytes()));
        let old = disk.0.borrow().sectors.clone();
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        let before = counters(&disk);
        let sequence = fs.sequence();
        let entry = assess(&mut fs, Resume::Never).unwrap();
        begin(&mut fs, entry).unwrap();
        assert_eq!(counters(&disk), (before.0 + 1, before.1 + 1));
        assert_eq!(fs.sequence(), sequence);
        let now = &disk.0.borrow().sectors;
        let changed = now.iter().filter(|(lba, bytes)| old.get(lba) != Some(bytes)).collect::<Vec<_>>();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].1, &State::Dirty.bytes());
    }

    #[test]
    fn dirty_guard_refuses_retry_when_failure_precedes_ledger_creation() {
        let disk = image(Some(&State::Fresh.bytes()));
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        let entry = assess(&mut fs, Resume::Never).unwrap();
        begin(&mut fs, entry).unwrap();
        disk.0.borrow_mut().fail_write = Some(counters(&disk).0 + 1);
        assert!(recovery::charge(&mut fs, &boot()).is_err());
        assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::None)));
        release_held(&disk);
        assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::None)));
    }

    #[test]
    fn failed_dirty_write_or_flush_never_permits_another_mutation() {
        for flush in [false, true] {
            let disk = image(Some(&State::Fresh.bytes()));
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Never).unwrap();
            let before = counters(&disk);
            if flush { disk.0.borrow_mut().fail_flush = Some(before.1 + 1); }
            else { disk.0.borrow_mut().fail_write = Some(before.0 + 1); }
            assert!(begin(&mut fs, entry).is_err());
            let stopped = counters(&disk);
            assert!(recovery::charge(&mut fs, &boot()).is_err());
            assert_eq!(counters(&disk), stopped);
            release_held(&disk);
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::None)));
        }
    }

    #[test]
    fn only_same_boot_finalization_cleans_served_and_bounded_boots() {
        for bounded in [false, true] {
            let disk = stopped_boot(bounded);
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            assert!(assess_finalization(&mut fs, &[b'2'; 32], bounded).is_err());
            finish(&mut fs, &boot(), bounded).unwrap();
            assert_eq!(assessment(&disk).unwrap().previous, Previous::Ended);
            assert!(finish(&mut fs, &boot(), bounded).is_err(), "duplicate finalizer admitted");
        }
    }

    #[test]
    fn bounded_update_restores_only_unchanged_history_after_success() {
        let disk = image(Some(&State::Fresh.bytes()));
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        let entry = assess(&mut fs, Resume::Never).unwrap();
        begin(&mut fs, entry).unwrap();
        put(&mut fs, b"/var/updated", b"verified update");
        assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::None)));
        finish_update(&mut fs, entry).unwrap();
        assert_eq!(assess(&mut fs, Resume::Never).unwrap(), entry);
        begin(&mut fs, entry).unwrap();
        recovery::charge(&mut fs, &boot()).unwrap();
        assert!(finish_update(&mut fs, entry).is_err());
        assert!(assess(&mut fs, Resume::Never).is_err());
    }

    #[test]
    fn every_finalizer_write_and_flush_interruption_is_conservative() {
        let original = stopped_boot(false);
        let before = counters(&original);
        finish(&mut Fs::mount(original.clone(), true).unwrap(), &boot(), false).unwrap();
        let after = counters(&original);
        for flush in [false, true] {
            let count = if flush { after.1 - before.1 } else { after.0 - before.0 };
            assert!(count > 0);
            for offset in 1..=count {
                let disk = stopped_boot(false);
                let before = counters(&disk);
                if flush { disk.0.borrow_mut().fail_flush = Some(before.1 + offset); }
                else { disk.0.borrow_mut().fail_write = Some(before.0 + offset); }
                match Fs::mount(disk.clone(), true) {
                    Ok(mut fs) => assert!(finish(&mut fs, &boot(), false).is_err()),
                    Err(Error::Device(-5)) if flush => {},
                    other => panic!("unexpected mount outcome: {}", other.is_ok()),
                }
                // Clean is possible only after all ordinary filesystem
                // writes and their successful flush preceded its command.
                for delayed in [false, true] {
                    if delayed { release_held(&disk); }
                    match assessment(&disk) {
                        Ok(entry) => assert_eq!((entry.marker, entry.previous), (State::Clean, Previous::Ended)),
                        Err(Refusal::Unfenced(_)) => {},
                        other => panic!("unexpected recovery after interruption: {other:?}"),
                    }
                }
            }
        }
    }

    // -- operator-authorized resume (coordination record #63, ACCEPTANCE-v5 B1, R4e) --

    /// The recovered boot's identity; `boot()` is the original history's.
    fn recovered() -> Boot { [b'2'; 32] }

    /// A served image after an unclean stop with history `p`: guard
    /// `dirty`, the slot `none`, the old boot's ledger, and (for `Failed`)
    /// its `served-ready` fact; for `NotReady` the old ledger with no
    /// matching fact. Then the host's act: the record for exactly this
    /// committed state written at the slot.
    fn authorized(p: Previous) -> (Disk, resume::Record) {
        let disk = image(Some(&State::Fresh.bytes()));
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        put(&mut fs, resume::PATH, &resume::none());
        let entry = assess(&mut fs, Resume::Never).unwrap();
        begin(&mut fs, entry).unwrap();
        recovery::charge(&mut fs, &boot()).unwrap();
        if p == Previous::Failed {
            put(&mut fs, recovery::SERVED_READY, &recovery::format_fact(&boot(), None));
        }
        fs.sync().unwrap();
        drop(fs);
        assert_eq!(assessment(&disk), Err(Refusal::Unfenced(p)));
        let mut read_only = Fs::mount(disk.clone(), false).unwrap();
        let ledger = recovery::history(&mut read_only).unwrap().ledger.unwrap();
        let record = resume::Record {
            id: [b'a'; 32], fs: read_only.fs_id(), seq: read_only.sequence(), image: read_only.image_digest(),
            ledger_seq: ledger.seq, ledger_boot: ledger.boot, previous: p, time: 1,
        };
        drop(read_only);
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        fs.transition_sector_marker(resume::PATH, &resume::none(), &resume::encode(&record)).unwrap();
        drop(fs);
        (disk, record)
    }

    fn slot_sector(disk: &Disk, bytes: &[u8; SECTOR]) -> u64 {
        *disk.0.borrow().sectors.iter().find(|(_, held)| *held == bytes).map(|(lba, _)| lba)
            .expect("slot sector")
    }

    fn slot_bytes(disk: &Disk, lba: u64) -> [u8; SECTOR] {
        disk.0.borrow().sectors.get(&lba).copied().unwrap_or([0; SECTOR])
    }

    fn admitted_by(disk: &Disk, record: &resume::Record) {
        let entry = assessment(disk).expect("re-admission");
        assert_eq!((entry.previous, entry.marker, entry.resumed()), (record.previous, State::Dirty, Some(record)));
    }

    #[test]
    fn a_checking_record_admits_only_the_serving_entry_and_only_the_exact_state() {
        for p in [Previous::Failed, Previous::NotReady] {
            let (disk, record) = authorized(p);
            admitted_by(&disk, &record);
            // R4f: the finalizer, enrollment and bounded updates never resume.
            let mut fs = Fs::mount(disk.clone(), false).unwrap();
            assert_eq!(assess(&mut fs, Resume::Never), Err(Refusal::Unfenced(p)));
            assert!(assess_finalization(&mut fs, &boot(), false).is_err());
            drop(fs);
            // Transplanted or forged records: refused by name, before any write.
            let lba = slot_sector(&disk, &resume::encode(&record));
            for (name, bytes) in [
                ("seq", resume::encode(&resume::Record { seq: record.seq + 1, ..record })),
                ("fs", resume::encode(&resume::Record { fs: record.fs + 1, ..record })),
                ("image", resume::encode(&resume::Record { image: [0xab; 32], ..record })),
                ("ledger_seq", resume::encode(&resume::Record { ledger_seq: record.ledger_seq + 1, ..record })),
                ("ledger_boot", resume::encode(&resume::Record { ledger_boot: [b'9'; 32], ..record })),
                ("previous", resume::encode(&resume::Record {
                    previous: if p == Previous::Failed { Previous::NotReady } else { Previous::Failed }, ..record })),
            ] {
                disk.0.borrow_mut().sectors.insert(lba, bytes);
                assert_eq!(assessment(&disk), Err(Refusal::ResumeMismatch), "{name}");
            }
            for bytes in [
                *include_bytes!("../../fixtures/storage-fence/resume-v1-torn-40.bin"),
                *include_bytes!("../../fixtures/storage-fence/resume-v1-torn-200.bin"),
                [0u8; SECTOR],
            ] {
                disk.0.borrow_mut().sectors.insert(lba, bytes);
                assert_eq!(assessment(&disk), Err(Refusal::ResumeCorrupt));
            }
            disk.0.borrow_mut().sectors.insert(lba, resume::none());
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(p)));
            disk.0.borrow_mut().sectors.insert(lba, resume::encode(&record));
            admitted_by(&disk, &record);
        }
    }

    #[test]
    fn consumption_is_one_slot_write_and_one_flush_that_leaves_the_guard_dirty() {
        for p in [Previous::Failed, Previous::NotReady] {
            let (disk, record) = authorized(p);
            let old = disk.0.borrow().sectors.clone();
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let before = counters(&disk);
            let sequence = fs.sequence();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            begin(&mut fs, entry).unwrap();
            assert_eq!(counters(&disk), (before.0 + 1, before.1 + 1));
            assert_eq!(fs.sequence(), sequence);
            let now = &disk.0.borrow().sectors;
            let changed = now.iter().filter(|(lba, bytes)| old.get(lba) != Some(bytes)).collect::<Vec<_>>();
            assert_eq!(changed.len(), 1);
            assert_eq!(changed[0].1, &resume::none());
            assert!(old.values().any(|bytes| bytes == &State::Dirty.bytes()));
            assert!(now.values().any(|bytes| bytes == &State::Dirty.bytes()));
            // An entry admitted by a record is never a bounded update.
            assert!(finish_update(&mut fs, entry).is_err());
            drop(fs);
            // Consumed: the slot is none, the guard dirty, the history unchanged.
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(p)));
            let _ = record;
        }
    }

    /// ACCEPTANCE-v5 B1 (a)-(h), DESIGN-v5 2.6 boundary table, for both
    /// histories `p`: what the next read-only assessment says after an
    /// interruption at each consumption and charge write or flush.
    #[test]
    fn consumption_and_charge_boundaries_hold_for_both_histories() {
        for p in [Previous::Failed, Previous::NotReady] {
            // (a) the consumption write fails and has not landed: R valid, p, re-admitted.
            // (b) the held write lands after the next assessment: none, p, refused.
            let (disk, record) = authorized(p);
            let lba = slot_sector(&disk, &resume::encode(&record));
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            let before = counters(&disk);
            disk.0.borrow_mut().fail_write = Some(before.0 + 1);
            assert!(begin(&mut fs, entry).is_err());
            assert!(fs.poisoned());
            assert!(recovery::charge(&mut fs, &recovered()).is_err());
            assert_eq!(counters(&disk).0, before.0 + 1, "(a) nothing else was written");
            drop(fs);
            assert_eq!(slot_bytes(&disk, lba), resume::encode(&record));
            admitted_by(&disk, &record);
            release_held(&disk);
            assert_eq!(slot_bytes(&disk, lba), resume::none());
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(p)), "(b)");

            // (c) the consumption flush fails: the write landed, the mount is
            // poisoned, nothing else is written; none, p, refused.
            let (disk, record) = authorized(p);
            let lba = slot_sector(&disk, &resume::encode(&record));
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            let before = counters(&disk);
            disk.0.borrow_mut().fail_flush = Some(before.1 + 1);
            assert!(begin(&mut fs, entry).is_err());
            assert!(fs.poisoned());
            assert!(recovery::charge(&mut fs, &recovered()).is_err());
            assert_eq!(counters(&disk).0, before.0 + 1, "(c) nothing else was written");
            drop(fs);
            assert_eq!(slot_bytes(&disk, lba), resume::none());
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(p)), "(c)");

            // (d) charge's ledger write fails before landing: none, p, refused;
            // once it lands late: not_ready.
            let (disk, record) = authorized(p);
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            begin(&mut fs, entry).unwrap();
            disk.0.borrow_mut().fail_write = Some(counters(&disk).0 + 1);
            assert!(recovery::charge(&mut fs, &recovered()).is_err());
            drop(fs);
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(p)), "(d)");
            release_held(&disk);
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::NotReady)), "(d) landed late");
            let _ = record;

            // (e) the ledger landed, the first fact write fails: not_ready for both p.
            let (disk, _) = authorized(p);
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            begin(&mut fs, entry).unwrap();
            disk.0.borrow_mut().fail_write = Some(counters(&disk).0 + 2);
            assert!(recovery::charge(&mut fs, &recovered()).is_err());
            drop(fs);
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::NotReady)), "(e)");
            release_held(&disk);
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::NotReady)), "(e) landed late");

            // (f) every fact landed, charge's sync fails: not_ready.
            let (disk, _) = authorized(p);
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            begin(&mut fs, entry).unwrap();
            disk.0.borrow_mut().fail_flush = Some(counters(&disk).1 + 1);
            assert!(recovery::charge(&mut fs, &recovered()).is_err());
            assert!(fs.poisoned());
            drop(fs);
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::NotReady)), "(f)");

            // (g) success, then an orderly end: clean+ended, admitted by the unchanged arm.
            let (disk, _) = authorized(p);
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            begin(&mut fs, entry).unwrap();
            let (ledger, how) = recovery::charge(&mut fs, &recovered()).unwrap();
            assert_eq!((ledger.boot, how), (recovered(), p));
            put(&mut fs, recovery::SERVED_READY, &recovery::format_fact(&recovered(), None));
            put(&mut fs, recovery::SERVED_END, &recovery::format_fact(&recovered(), Some("halt")));
            recovery::stopped(&mut fs, &recovered()).unwrap();
            fs.sync().unwrap();
            finish(&mut fs, &recovered(), false).unwrap();
            drop(fs);
            let entry = assessment(&disk).unwrap();
            assert_eq!((entry.marker, entry.previous, entry.resumed()), (State::Clean, Previous::Ended, None), "(g)");

            // (h) success, then an abrupt end: charge alone establishes
            // not_ready; the recovered boot's own ready fact makes it failed.
            let (disk, _) = authorized(p);
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            begin(&mut fs, entry).unwrap();
            recovery::charge(&mut fs, &recovered()).unwrap();
            drop(fs);
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::NotReady)), "(h) charged only");
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            put(&mut fs, recovery::SERVED_READY, &recovery::format_fact(&recovered(), None));
            drop(fs);
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(Previous::Failed)), "(h) ready then gone");
        }
    }

    /// Every write and flush offset of consumption plus charge, both
    /// histories, with and without the failed effect landing late: the
    /// next assessment is the original history's re-admission with R
    /// still on the disk, or a refusal of `p` or `not_ready`; never an
    /// admission of a changed state.
    #[test]
    fn every_consumption_and_charge_interruption_is_conservative() {
        for p in [Previous::Failed, Previous::NotReady] {
            let (original, record) = authorized(p);
            let before = counters(&original);
            let mut fs = Fs::mount(original.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            begin(&mut fs, entry).unwrap();
            recovery::charge(&mut fs, &recovered()).unwrap();
            drop(fs);
            let after = counters(&original);
            for flush in [false, true] {
                let count = if flush { after.1 - before.1 } else { after.0 - before.0 };
                assert!(count >= 2);
                for offset in 1..=count {
                    let (disk, record) = authorized(p);
                    let lba = slot_sector(&disk, &resume::encode(&record));
                    let before = counters(&disk);
                    if flush { disk.0.borrow_mut().fail_flush = Some(before.1 + offset); }
                    else { disk.0.borrow_mut().fail_write = Some(before.0 + offset); }
                    match Fs::mount(disk.clone(), true) {
                        Ok(mut fs) => {
                            let outcome = assess(&mut fs, Resume::Allowed)
                                .and_then(|entry| begin(&mut fs, entry))
                                .and_then(|()| recovery::charge(&mut fs, &recovered()).map(|_| ()));
                            assert!(outcome.is_err(), "p={p:?} flush={flush} offset={offset}");
                        }
                        Err(Error::Device(-5)) if flush => {}
                        other => panic!("unexpected mount outcome: {}", other.is_ok()),
                    }
                    for delayed in [false, true] {
                        if delayed { release_held(&disk); }
                        match assessment(&disk) {
                            Ok(entry) => {
                                assert_eq!(entry.resumed(), Some(&record), "p={p:?} flush={flush} offset={offset}");
                                assert_eq!(slot_bytes(&disk, lba), resume::encode(&record));
                            }
                            Err(Refusal::Unfenced(how)) => assert!(how == p || how == Previous::NotReady,
                                "p={p:?} flush={flush} offset={offset} delayed={delayed}: {how:?}"),
                            other => panic!("unexpected assessment after interruption: {other:?}"),
                        }
                    }
                }
            }
            let _ = record;
        }
    }

    /// ACCEPTANCE-v5 R4e, the disclosed pre-charge replay limit: after
    /// consumption and before charge's first in-place write the five
    /// fields are unchanged, so a raw restore of the saved slot sector
    /// re-admits the identical state. Raw writes are outside every tool.
    #[test]
    fn replay_before_charge_readmits_the_identical_state_and_after_charge_mismatches() {
        for p in [Previous::Failed, Previous::NotReady] {
            let (disk, record) = authorized(p);
            let lba = slot_sector(&disk, &resume::encode(&record));
            let saved = slot_bytes(&disk, lba);
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            begin(&mut fs, entry).unwrap();
            disk.0.borrow_mut().fail_write = Some(counters(&disk).0 + 1);
            assert!(recovery::charge(&mut fs, &recovered()).is_err());
            drop(fs);
            assert_eq!(assessment(&disk), Err(Refusal::Unfenced(p)));
            disk.0.borrow_mut().sectors.insert(lba, saved);
            admitted_by(&disk, &record);
            // R4d: once the ledger moved, the same sector no longer names the state.
            let mut fs = Fs::mount(disk.clone(), true).unwrap();
            let entry = assess(&mut fs, Resume::Allowed).unwrap();
            begin(&mut fs, entry).unwrap();
            recovery::charge(&mut fs, &recovered()).unwrap();
            drop(fs);
            disk.0.borrow_mut().sectors.insert(lba, saved);
            assert_eq!(assessment(&disk), Err(Refusal::ResumeMismatch));
        }
    }
}
