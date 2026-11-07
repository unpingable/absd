use absd_fs::{Device, Error, Fs, SECTOR};
use absd_fsd::Server;
use std::collections::BTreeMap;
struct RegionDevice(BTreeMap<u64, [u8; SECTOR]>);
impl Device for RegionDevice {
    fn sectors(&self) -> u64 {
        16384
    }
    fn read(&mut self, n: u64, b: &mut [u8; SECTOR]) -> Result<(), Error> {
        *b = self.0.get(&n).copied().unwrap_or([0; SECTOR]);
        Ok(())
    }
    fn write(&mut self, n: u64, b: &[u8; SECTOR]) -> Result<(), Error> {
        self.0.insert(n, *b);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
#[test]
fn actual_fsd_refresh_keeps_unknown_mtime_zero_and_invalidates_corrected_generations() {
    let mut disk = RegionDevice(Default::default());
    absd_fs::format(&mut disk, 7).unwrap();
    let fs = Fs::mount(disk, true).unwrap();
    let mut server = Server::new(fs, 0, Vec::new());
    NOW.store(1000, Relaxed);
    GENERATION.store(1, Relaxed);
    *SAMPLE.lock().unwrap() = Some((1_700_000_000_000_000_000, 2));
    refresh_civil_clock(&mut server, 1000);
    server.fs.mkdir(b"/known").unwrap();
    assert_eq!(server.fs.stat(b"/known").unwrap().mtime, 1_700_000_000);
    // Within the cache window, unknown must discard the old known sample.
    NOW.store(1001, Relaxed);
    *SAMPLE.lock().unwrap() = None;
    refresh_civil_clock(&mut server, 1001);
    server.fs.mkdir(b"/unknown").unwrap();
    assert_eq!(server.fs.stat(b"/unknown").unwrap().mtime, 0);
    assert_eq!(wall_clock_seconds(), Err(-5));
    // A correction is observable on the next operation, including backwards.
    NOW.store(1002, Relaxed);
    GENERATION.store(2, Relaxed);
    *SAMPLE.lock().unwrap() = Some((100_000_000_000, 2));
    refresh_civil_clock(&mut server, 1002);
    server.fs.mkdir(b"/corrected").unwrap();
    assert_eq!(server.fs.stat(b"/corrected").unwrap().mtime, 100);
    NOW.store(1003, Relaxed);
    GENERATION.store(3, Relaxed);
    *SAMPLE.lock().unwrap() = Some((50_000_000_000, 2));
    refresh_civil_clock(&mut server, 1003);
    server.fs.mkdir(b"/backwards").unwrap();
    assert_eq!(server.fs.stat(b"/backwards").unwrap().mtime, 50);
}
