//! Same fault/isolation workload on both ISAs; native instructions stay in arch.
use crate::*;
use absd_abi::layout::{USER_HEAP_END, USER_STACK_BASE, USER_STACK_TOP};
#[repr(align(16))]
struct ReadOnly([u64; 2]);
static READONLY: ReadOnly = ReadOnly([0x1234; 2]);
/// Workers execute one native instruction, or one permitted stack growth.
pub fn worker(role: u64) -> i32 {
    match role {
        10 => arch::probe_read(USER_HEAP_END - 4096),
        11 => arch::probe_write(READONLY.0.as_ptr() as u64),
        12 => {
            let page = map(1).unwrap();
            arch::probe_execute(page);
        }
        13 => arch::probe_undefined(),
        14 => {
            let page = map(1).unwrap();
            arch::probe_alignment(unsafe { page.add(15) });
        }
        15 => arch::probe_stack(USER_STACK_BASE - 16),
        16 => arch::probe_write(0x100000),
        17 => arch::probe_stack(USER_STACK_TOP - 3 * 4096 + 128),
        _ => return 97,
    }
    0
}
pub fn run(console: Console) {
    let base = resource_census().unwrap();
    for role in 10..=17 {
        let child = spawn_with(program::HELLO_A, 0, role).unwrap();
        let result = wait_identified_timeout(Some(child), 0).unwrap();
        if role == 17 {
            assert_eq!(result.outcome, Outcome::Exited(0));
            console
                .line(format_args!(
                    "FLT1 {role} {} 1 0000000000000000 0000000000000000 0000000000000000\n",
                    result.pid
                ))
                .unwrap();
        } else {
            let Outcome::Faulted {
                vector,
                address,
                error,
            } = result.outcome
            else {
                panic!("native fault not isolated")
            };
            console
                .line(format_args!(
                    "FLT1 {role} {} 2 {vector:016x} {address:016x} {error:016x}\n",
                    result.pid
                ))
                .unwrap();
        }
        assert_eq!(resource_census().unwrap(), base);
    }
    // Post-fault liveness and FP context ownership, plus exact reclamation.
    let a = spawn_with(program::HELLO_A, 0, 3).unwrap();
    let b = spawn_with(program::HELLO_A, 0, 4).unwrap();
    assert_eq!(wait(Some(a)), Ok(Outcome::Exited(0)));
    assert_eq!(wait(Some(b)), Ok(Outcome::Exited(0)));
    assert_eq!(resource_census().unwrap(), base);
    console
        .write_str("PORTABLE B3 FAULT RECLAMATION FP HEALTH OK\n")
        .unwrap();
}
