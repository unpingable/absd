//! Transport fixture for the production observation reader and native CLIs.
#[path = "../../runtime/src/observation.rs"]
pub mod observation;

pub fn link_anchor() {}

fn frame(text: &str) -> [u8; observation::BYTES] {
    let text = text.trim();
    assert_eq!(text.len(), observation::BYTES * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}

pub unsafe fn syscall3(number: u64, handle: u64, address: u64, query: u64) -> i64 {
    assert_eq!(number, 0x7fc1);
    assert_eq!(handle, 0);
    let scenario = std::env::var("OBSERVATION_MOCK").unwrap_or_default();
    if scenario == "denied" { return -1; }
    if scenario == "ap-unsupported" && (query == 256 || (512..768).contains(&query)) {
        return -38;
    }
    let mut bytes = match query {
        3 => frame(include_str!("observation-process-v1.hex")),
        n if n < 32 => {
            let mut bytes = [0; observation::BYTES];
            bytes[..8].copy_from_slice(&1u64.to_le_bytes());
            bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
            bytes[24..32].copy_from_slice(&n.to_le_bytes());
            bytes
        }
        257 => frame(include_str!("../../runtime/fixtures/capacity-v1.hex")),
        256 if scenario == "unavailable" => frame(include_str!("observation-nic-unavailable-v1.hex")),
        256 => frame(include_str!("observation-nic-v1.hex")),
        512 if scenario == "unavailable" => frame(include_str!("observation-candidate-inactive-v1.hex")),
        512 => frame(include_str!("observation-candidate-v1.hex")),
        513..=767 => return -2,
        _ => return -22,
    };
    if scenario == "unsupported-version" { bytes[0] = 2; }
    if scenario == "readable-wait" && query == 3 {
        bytes[8 * 8..9 * 8].copy_from_slice(&9u64.to_le_bytes());
    }
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()); }
    0
}
