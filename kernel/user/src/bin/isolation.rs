//! Two instances use identical virtual heap and stack addresses while
//! retaining PID-derived contents across yields and timer preemption.
#![no_std]
#![no_main]

use absd_abi::layout::USER_HEAP_BASE;
use absd_user::{Start, getpid, map, unmap, yield_now};

absd_user::entry!(main);

const PAGE_BYTES: usize = 4096;
const HEAP_WORDS: usize = PAGE_BYTES / size_of::<u64>();
const STACK_WORDS: usize = 128;
const ROUNDS: u64 = 200;

fn word(pid: u64, index: usize, salt: u64) -> u64 {
    pid.rotate_left(17) ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ salt
}

fn main(_start: Start) -> i32 {
    let pid = getpid();
    let Ok(heap) = map(1) else {
        return 109;
    };
    if heap as u64 != USER_HEAP_BASE {
        return 110;
    }
    let mut stack = [0u64; STACK_WORDS];
    for index in 0..HEAP_WORDS {
        unsafe {
            heap.cast::<u64>()
                .add(index)
                .write_volatile(word(pid, index, 0x4845_4150));
        }
    }
    for (index, slot) in stack.iter_mut().enumerate() {
        unsafe { core::ptr::write_volatile(slot, word(pid, index, 0x0053_5441_434b)) };
    }

    for _ in 0..ROUNDS {
        yield_now();
        for _ in 0..2_000 {
            unsafe { core::arch::asm!("pause", options(nomem, nostack)) };
        }
        for index in 0..HEAP_WORDS {
            let actual = unsafe { heap.cast::<u64>().add(index).read_volatile() };
            if actual != word(pid, index, 0x4845_4150) {
                return 111;
            }
        }
        for (index, slot) in stack.iter().enumerate() {
            let actual = unsafe { core::ptr::read_volatile(slot) };
            if actual != word(pid, index, 0x0053_5441_434b) {
                return 112;
            }
        }
    }
    if unmap(heap, 1).is_err() {
        return 113;
    }
    0
}
