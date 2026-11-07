//! Bounded queries using an explicit read-only Diagnostics grant. Only root
//! init may fall back to its private Console. Readout grants neither process
//! control nor device read/write authority.
use super::{handle_error, stats, table};
use absd_kernel::observation as wire;
use absd_kernel::syscall::{ERROR_FAULT, ERROR_INVALID};
use absd_kernel::user_memory::{check_user_range, copy_to_user};

pub(super) unsafe fn read(current: usize, handle: u64, address: u64, query: u64) -> i64 {
    let process = &unsafe { table() }.entries[current];
    let allow_console =
        absd_kernel::kernel_log::root_init_role(process.pid, process.parent, process.program);
    if let Err(error) =
        absd_kernel::kernel_log::authorize_reader_for(&process.handles, handle, allow_console)
    {
        return unsafe { handle_error(error) };
    }
    // A read grant does not pin its holder to the BSP. Device access still
    // belongs there; do not send an ordinary AP caller to the fatal backstop.
    #[cfg(target_arch = "x86_64")]
    if (query == wire::QUERY_NIC || (512..768).contains(&query))
        && crate::cpu::id() != crate::kernel_lock::BSP
    {
        return absd_kernel::syscall::ERROR_NOT_IMPLEMENTED;
    }
    let space = unsafe { table() }.entries[current].address_space;
    if unsafe { check_user_range(&space, address, wire::BYTES, true) }.is_err() {
        unsafe { stats() }.pointer_refusals += 1;
        return ERROR_FAULT;
    }
    let record = if query < absd_kernel::process::MAX_PROCESSES as u64 {
        wire::process_record(
            &unsafe { table() }.entries[query as usize],
            crate::sched::now(),
            query as usize,
        )
    } else if query == wire::QUERY_CAPACITY {
        wire::capacity_record(crate::sched::now())
    } else if query == wire::QUERY_NIC {
        #[cfg(target_arch = "x86_64")]
        {
            crate::nic_device::observation()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            return absd_kernel::syscall::ERROR_NOT_IMPLEMENTED;
        }
    } else if (512..768).contains(&query) {
        #[cfg(target_arch = "x86_64")]
        {
            match crate::nic_device::candidate_observation((query - 512) as usize) {
                Some(record) => record,
                None => return absd_kernel::syscall::ERROR_NOT_FOUND,
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            return absd_kernel::syscall::ERROR_NOT_IMPLEMENTED;
        }
    } else {
        return ERROR_INVALID;
    };
    if unsafe { copy_to_user(&space, address, &record) }.is_err() {
        unsafe { stats() }.pointer_refusals += 1;
        return ERROR_FAULT;
    }
    0
}
