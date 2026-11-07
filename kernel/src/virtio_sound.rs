//! Experimental, BSP-only VirtIO Sound driver. Static buffers are pinned for
//! the boot; a failed device is quarantined, never recycled on a timeout.
//! Initialization/control waits are bounded. Ordinary PCM submission only polls
//! already-completed entries and never waits for the device to consume audio.
use crate::{mmio, pci};
use absd_kernel::dma_policy;
use absd_kernel::{
    sound_pci::{Bar, Capabilities},
    sound_protocol as wire,
    sound_queue::{Buffer, Queue, SLOTS},
};
use core::fmt::Write;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Absent,
    Unsupported,
    Device,
    Timeout,
    Full,
    Invalid,
    Retired,
}
#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub submitted_frames: u64,
    pub completed_frames: u64,
    pub latency_bytes: u32,
    pub pending: usize,
    pub running: bool,
    pub failed: bool,
}
// These globals never participate in an exclusive Driver borrow. Queues use
// shared interior mutability; buffers are accessed only through raw pointers.
static mut QUEUES: [Queue; 4] = [const { Queue::new() }; 4];
struct DmaBuffers {
    request: [u8; 24],
    reply: [u8; 36],
    headers: [[u8; 4]; SLOTS],
    pcm: [[u8; wire::PERIOD_BYTES]; SLOTS],
    statuses: [[u8; 8]; SLOTS],
}
static mut DMA: DmaBuffers = DmaBuffers {
    request: [0; 24],
    reply: [0; 36],
    headers: [[0; 4]; SLOTS],
    pcm: [[0; wire::PERIOD_BYTES]; SLOTS],
    statuses: [[0; 8]; SLOTS],
};
fn queue(index: usize) -> &'static Queue {
    unsafe { &*addr_of!(QUEUES[index]) }
}
struct Driver {
    function: Option<pci::Function>,
    caps: Option<Capabilities>,
    notify: [u64; 4],
    lengths: [u32; SLOTS],
    stream: u32,
    attempted: bool,
    running: bool,
    stopping: bool,
    failed: bool,
    submitted: u64,
    completed: u64,
    latency: u32,
}
static mut DRIVER: Driver = Driver {
    function: None,
    caps: None,
    notify: [0; 4],
    lengths: [0; SLOTS],
    stream: 0,
    attempted: false,
    running: false,
    stopping: false,
    failed: false,
    submitted: 0,
    completed: 0,
    latency: 0,
};
fn queue_error(e: absd_kernel::sound_queue::Error) -> Error {
    match e {
        absd_kernel::sound_queue::Error::Full => Error::Full,
        absd_kernel::sound_queue::Error::Invalid => Error::Invalid,
        _ => Error::Device,
    }
}
// Callers validate register ranges during discovery; each offset below is in
// the required 56-byte common config. DMA memory is never a userspace address.
fn r8(a: u64) -> u8 {
    unsafe { read_volatile(a as *const u8) }
}
fn r16(a: u64) -> u16 {
    unsafe { read_volatile(a as *const u16) }
}
fn r32(a: u64) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
fn w8(a: u64, v: u8) {
    unsafe { write_volatile(a as *mut u8, v) }
}
fn w16(a: u64, v: u16) {
    unsafe { write_volatile(a as *mut u16, v) }
}
fn w32(a: u64, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}
fn w64(a: u64, v: u64) {
    w32(a, v as u32);
    w32(a + 4, (v >> 32) as u32);
}
fn bounded(mut ready: impl FnMut() -> Result<bool, Error>) -> Result<(), Error> {
    let calibration = unsafe { read_volatile(addr_of!(crate::TIMER_TSC_CYCLES)) };
    if calibration == 0 {
        return Err(Error::Timeout);
    }
    let start = crate::tsc_ordered();
    // Calibration spans approximately five PIT ticks. CPU-iteration ceiling
    // also bounds the wait if TSC stops. Neither is a PCM pacing clock.
    let limit = calibration.saturating_mul(100);
    for _ in 0..5_000_000 {
        if ready()? {
            return Ok(());
        }
        if crate::tsc_ordered().wrapping_sub(start) > limit {
            break;
        }
        core::hint::spin_loop();
    }
    Err(Error::Timeout)
}
impl Driver {
    fn discover(&mut self) -> Result<(), Error> {
        let f = pci::find_id(0x1af4, 0x1059).ok_or(Error::Absent)?;
        pci::claim(f, "virtio-sound").map_err(|_| Error::Device)?;
        self.function = Some(f);
        crate::serial::write("PCM PCI CLAIMED\n");
        pci::disable_dma(f);
        if pci::bus_master(f) {
            return Err(Error::Device);
        }
        let mut config = [0; 256];
        for i in (0..256).step_by(4) {
            config[i..i + 4].copy_from_slice(&pci::read32(f, i as u8).to_le_bytes());
        }
        let mut bars = [None; 6];
        let mut i = 0;
        while i < 6 {
            let raw = pci::read32(f, 0x10 + 4 * i as u8);
            let wide = raw & 1 == 0 && (raw >> 1) & 3 == 2;
            if let Ok(base) = pci::memory_bar(f, i as u8) {
                let size = pci::memory_bar_size(f, i as u8).map_err(|_| Error::Device)?;
                bars[i] = Some(Bar { base, size });
            }
            i += if wide { 2 } else { 1 };
        }
        let mut caps = Capabilities::parse(&config, bars).map_err(|_| Error::Unsupported)?;
        for region in [
            &mut caps.common,
            &mut caps.notify,
            &mut caps.isr,
            &mut caps.device,
        ] {
            // A finite mapping bound for this initial QEMU-only backend.
            if region.length > 4096 {
                return Err(Error::Unsupported);
            }
            region.address = mmio::map(region.address, region.length as u64, mmio::Cache::Uncached)
                .map_err(|_| Error::Device)?;
        }
        pci::enable_memory(f);
        self.caps = Some(caps);
        crate::serial::write("PCM PCI MAPPED\n");
        let c = caps.common.address;
        w8(c + 20, 0);
        bounded(|| Ok(r8(c + 20) == 0))?;
        w8(c + 20, 3);
        w32(c, 1);
        if r32(c + 4) & 1 == 0 {
            return Err(Error::Unsupported);
        }
        w32(c + 8, 0);
        w32(c + 12, 0);
        w32(c + 8, 1);
        w32(c + 12, 1); // VERSION_1 only, no optional transport features.
        w8(c + 20, 11);
        if r8(c + 20) & 8 == 0 {
            return Err(Error::Unsupported);
        }
        if r16(c + 18) < 4 {
            return Err(Error::Unsupported);
        }
        w16(c + 16, 0xffff);
        for q in 0..4 {
            w16(c + 22, q as u16);
            if r16(c + 24) < 16 || r16(c + 28) != 0 {
                return Err(Error::Unsupported);
            }
            w16(c + 24, 16);
            w16(c + 26, 0xffff);
            let (d, a, u) = queue(q).addresses();
            w64(c + 32, d);
            w64(c + 40, a);
            w64(c + 48, u);
            self.notify[q] = caps.notification(r16(c + 30)).map_err(|_| Error::Device)?;
            w16(c + 28, 1);
        }
        crate::serial::write("PCM QUEUES READY\n");
        crate::dma::arm(f, &dma_policy::VIRTIO_SOUND).map_err(|_| Error::Device)?;
        if !pci::bus_master(f) {
            return Err(Error::Device);
        }
        w8(c + 20, 15);
        let streams = r32(caps.device.address + 4);
        let _ = writeln!(crate::serial::Serial, "PCM STREAMS {streams}");
        if streams == 0 || streams > 16 {
            return Err(Error::Unsupported);
        }
        let mut chosen = None;
        for stream in 0..streams {
            self.control(&wire::query(stream), 36)?;
            if wire::accept_info(&self.response()).is_ok() {
                chosen = Some(stream);
                break;
            }
        }
        self.stream = chosen.ok_or(Error::Unsupported)?;
        self.control(&wire::params(self.stream), 4)?;
        self.control(&wire::command(wire::PREPARE, self.stream), 4)?;
        self.control(&wire::command(wire::START, self.stream), 4)?;
        self.running = true;
        Ok(())
    }
    fn response(&self) -> [u8; 36] {
        core::array::from_fn(|i| unsafe { read_volatile(addr_of!(DMA.reply[i])) })
    }
    fn control(&mut self, request: &[u8], reply_len: usize) -> Result<(), Error> {
        if request.len() < 8 || request.len() > 24 || !(4..=36).contains(&reply_len) {
            return Err(Error::Invalid);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                request.as_ptr(),
                addr_of_mut!(DMA.request).cast::<u8>(),
                request.len(),
            );
        }
        for i in 0..36 {
            unsafe { write_volatile(addr_of_mut!(DMA.reply[i]), 0xff) };
        }
        let a = unsafe { addr_of!(DMA.request) as u64 };
        let _ = writeln!(
            crate::serial::Serial,
            "PCM CONTROL code={:02x?} reply={reply_len}",
            &request[..4]
        );
        let head = queue(0)
            .submit([
                Buffer {
                    address: a,
                    length: 4,
                    writable: false,
                },
                Buffer {
                    address: a + 4,
                    length: (request.len() - 4) as u32,
                    writable: false,
                },
                Buffer {
                    address: unsafe { addr_of!(DMA.reply) as u64 },
                    length: reply_len as u32,
                    writable: true,
                },
            ])
            .map_err(queue_error)?;
        w16(self.notify[0], 0);
        bounded(|| match queue(0).poll().map_err(queue_error)? {
            None => Ok(false),
            Some((h, n))
                if h == head
                    && wire::control_length(
                        u32::from_le_bytes(request[..4].try_into().unwrap()),
                        reply_len as u32,
                        n,
                        &self.response(),
                        cfg!(feature = "native-pcm-qemu82"),
                    ) =>
            {
                Ok(true)
            }
            Some((h, n)) => {
                let _ = writeln!(
                    crate::serial::Serial,
                    "PCM CONTROL SHORT head={h} expected={head} bytes={n} response={:02x?}",
                    self.response()
                );
                Err(Error::Device)
            }
        })?;
        let response = self.response();
        let _ = writeln!(
            crate::serial::Serial,
            "PCM CONTROL RESPONSE {:02x?}",
            &response[..reply_len]
        );
        wire::status(&response).map_err(|_| Error::Device)
    }
    fn poll(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Device);
        }
        if !self.running {
            return Err(Error::Retired);
        }
        let caps = self.caps.ok_or(Error::Absent)?;
        if r8(caps.common.address + 20) & 0xcf != 15 {
            return Err(Error::Device);
        }
        for _ in 0..SLOTS {
            let Some((head, n)) = queue(2).poll().map_err(queue_error)? else {
                break;
            };
            if n != 8 {
                return Err(Error::Device);
            }
            let slot = head as usize / 3;
            let status = core::array::from_fn::<_, 8, _>(|i| unsafe {
                read_volatile(addr_of!(DMA.statuses[slot][i]))
            });
            self.latency = wire::tx_status(&status).map_err(|_| Error::Device)?;
            self.completed += self.lengths[slot] as u64 / 4;
        }
        // Acknowledge any legacy status even though PCI INTx is masked.
        let _ = r8(caps.isr.address);
        Ok(())
    }
    fn submit(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.stopping {
            return Err(Error::Retired);
        }
        if bytes.is_empty() || bytes.len() > wire::PERIOD_BYTES || !bytes.len().is_multiple_of(4) {
            return Err(Error::Invalid);
        }
        self.poll()?;
        let slot = queue(2).free_slot().map_err(queue_error)?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                addr_of_mut!(DMA.pcm[slot]).cast::<u8>(),
                bytes.len(),
            );
        }
        unsafe {
            write_volatile(addr_of_mut!(DMA.headers[slot]), self.stream.to_le_bytes());
        }
        for i in 0..8 {
            unsafe { write_volatile(addr_of_mut!(DMA.statuses[slot][i]), 0xff) };
        }
        self.lengths[slot] = bytes.len() as u32;
        queue(2)
            .submit([
                Buffer {
                    address: unsafe { addr_of!(DMA.headers[slot]) as u64 },
                    length: 4,
                    writable: false,
                },
                Buffer {
                    address: unsafe { addr_of!(DMA.pcm[slot]) as u64 },
                    length: bytes.len() as u32,
                    writable: false,
                },
                Buffer {
                    address: unsafe { addr_of!(DMA.statuses[slot]) as u64 },
                    length: 8,
                    writable: true,
                },
            ])
            .map_err(queue_error)?;
        self.submitted += bytes.len() as u64 / 4;
        w16(self.notify[2], 2);
        Ok(())
    }
    fn quarantine(&mut self) {
        self.failed = true;
        self.running = false;
        if let Some(caps) = self.caps {
            w8(caps.common.address + 20, 0);
        }
        if let Some(f) = self.function {
            pci::disable_dma(f);
        }
        // No reuse, even if reset later completes. Keep every buffer pinned.
    }
}
fn with_driver<T>(f: impl FnOnce(&mut Driver) -> Result<T, Error>) -> Result<T, Error> {
    crate::kernel_lock::assert_bsp_device_access();
    // Same serialized BSP entry discipline as the existing PCI drivers.
    let d = unsafe { &mut *addr_of_mut!(DRIVER) };
    let result = f(d);
    if matches!(
        result,
        Err(Error::Device | Error::Timeout | Error::Unsupported)
    ) {
        d.quarantine();
    }
    result
}
pub fn init() -> Result<(), Error> {
    with_driver(|d| {
        if d.attempted {
            return Err(Error::Retired);
        }
        d.attempted = true;
        d.discover()
    })
}
pub fn submit(bytes: &[u8]) -> Result<(), Error> {
    with_driver(|d| d.submit(bytes))
}
pub fn status() -> Result<Status, Error> {
    with_driver(|d| {
        d.poll()?;
        Ok(Status {
            submitted_frames: d.submitted,
            completed_frames: d.completed,
            latency_bytes: d.latency,
            pending: queue(2).outstanding(),
            running: d.running,
            failed: d.failed,
        })
    })
}
/// The first request disables submission, including when pending TX returns Full.
/// A caller polls completion and retries to finish the clean device withdrawal.
/// Failure always quarantines the whole boot's static DMA storage.
pub fn stop() -> Result<(), Error> {
    with_driver(|d| {
        d.stopping = true;
        d.poll()?;
        if queue(2).outstanding() != 0 {
            return Err(Error::Full);
        }
        d.control(&wire::command(wire::STOP, d.stream), 4)?;
        d.control(&wire::command(wire::RELEASE, d.stream), 4)?;
        let c = d.caps.ok_or(Error::Absent)?.common.address;
        w8(c + 20, 0);
        bounded(|| Ok(r8(c + 20) == 0))?;
        pci::disable_dma(d.function.ok_or(Error::Absent)?);
        d.running = false;
        Ok(())
    })
}
/// Producer withdrawal is cancellation, not a successful drain.
pub fn cancel() {
    let _ = with_driver(|d| {
        d.quarantine();
        Ok(())
    });
}
