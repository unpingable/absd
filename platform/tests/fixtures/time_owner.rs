// Only syscall/grant/log transport is substituted. Production Service source
// is copied verbatim into the owner module, with these cases appended there.
extern crate self as absd_runtime;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering::Relaxed},
};
static NOW: AtomicU64 = AtomicU64::new(0);
static GRANT: AtomicU64 = AtomicU64::new(1);
static REQUESTS: Mutex<Vec<[u8; 64]>> = Mutex::new(Vec::new());
static GENERATION: AtomicU64 = AtomicU64::new(0);
static SAMPLE: Mutex<Option<(u64, u32)>> = Mutex::new(None);
static NOTES: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub fn boot_millis() -> u64 {
    NOW.load(Relaxed)
}
pub fn ticks() -> u64 {
    boot_millis()
}
pub fn clock_owner_handle() -> u64 {
    GRANT.load(Relaxed)
}
mod oplog {
    pub fn line(message: String) {
        crate::NOTES.lock().unwrap().push(message);
    }
}
pub unsafe fn syscall3(call: u64, a: u64, b: u64, _: u64) -> i64 {
    match call {
        0x7fb0 => {
            let mut bytes = [0u8; 96];
            bytes[..4].copy_from_slice(&1u32.to_le_bytes());
            let sample = *SAMPLE.lock().unwrap();
            let ns = sample.map_or(u64::MAX, |(ns, _)| ns);
            bytes[16..24].copy_from_slice(&ns.to_le_bytes());
            bytes[24..32].copy_from_slice(&ticks().to_le_bytes());
            bytes[32..40].copy_from_slice(&ticks().to_le_bytes());
            if let Some((_, source)) = sample {
                bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
                bytes[8..12].copy_from_slice(&source.to_le_bytes());
                bytes[48..56].copy_from_slice(&GENERATION.load(Relaxed).to_le_bytes());
                if source == 3 {
                    let requests = REQUESTS.lock().unwrap();
                    let request = requests
                        .iter()
                        .rev()
                        .find(|r| r[4] == 1 && r[8] == 3)
                        .unwrap();
                    bytes[72..76].copy_from_slice(&request[12..16]);
                    bytes[92..94].copy_from_slice(&request[56..58]);
                }
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), a as *mut u8, 96);
            }
            0
        }
        0x7fb1 => {
            assert_eq!(a, 1);
            let mut request = [0u8; 64];
            unsafe {
                std::ptr::copy_nonoverlapping(b as *const u8, request.as_mut_ptr(), 64);
            }
            assert_eq!(&request[..4], &1u32.to_le_bytes());
            if request[4] == 1 {
                GENERATION.fetch_add(1, Relaxed);
                *SAMPLE.lock().unwrap() = Some((
                    u64::from_le_bytes(request[16..24].try_into().unwrap()),
                    u32::from_le_bytes(request[8..12].try_into().unwrap()),
                ));
            }
            REQUESTS.lock().unwrap().push(request);
            0
        }
        _ => panic!("unexpected substituted syscall {call:x}"),
    }
}

pub fn hardware_rtc_seconds() -> Result<u64, i64> {
    Err(-5)
}
