//! Pre-main FSD protocol admission, shared by the native runtime and host controls.
use crate::{
    proto::{Frame, op},
    version,
};
use alloc::vec::Vec;
pub fn check(
    name: &[u8],
    require_release: bool,
    exchange: impl FnOnce(Vec<u8>, u64) -> Result<(i64, Vec<u8>), i64>,
) -> Result<version::Version, (version::Refusal, i32)> {
    let logger = name == b"logd";
    let ticks = if logger { 1000 } else { version::ANSWER_TICKS };
    version::check(
        exchange(Frame::request(op::VERSION).finish(), ticks),
        require_release,
    )
    .map_err(|refusal| {
        let status = if logger && refusal == version::Refusal::NoAnswer {
            crate::journal_rpc::REATTACH_EXIT_STATUS
        } else {
            version::REFUSED_STATUS
        };
        (refusal, status)
    })
}
