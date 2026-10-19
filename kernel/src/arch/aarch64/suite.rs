static mut RESTART: bool = false;
pub fn arm_restart() {
    unsafe {
        RESTART = true;
    }
}
pub unsafe fn finish_process_suite() -> ! {
    unsafe {
        crate::sched::flush_rt_trace();
        let stats = crate::sched::stats();
        let table = crate::sched::table();
        let frames = crate::vm::frames();
        #[cfg(feature = "frame-admission-v0")]
        {
            let accounting = frames.admission_accounting();
            crate::out("SERVED FRAME ACCOUNTING records=");
            crate::number(accounting.records as u64);
            crate::out(" total=");
            crate::number(accounting.total);
            crate::out(" used=");
            crate::number(accounting.used);
            crate::out(" idle=");
            crate::number(accounting.idle);
            crate::out(if accounting.clean() {
                " status=ok\n"
            } else {
                " status=failed\n"
            });
            if !accounting.clean() {
                RESTART = false;
                crate::exit_qemu(1);
            }
        }
        assert_eq!(stats.init_status, Some(0));
        assert_eq!(table.occupied_count(), 0);
        assert!(crate::sched::object_tables_empty());
        assert_eq!(frames.allocated_frames(), stats.frame_baseline);
        assert!(stats.preempts > 0, "no actual preemption");
        let preempts = stats.preempts;
        crate::smp::finish();
        crate::out("ARM A2 RECLAIM OK preempts=");
        crate::number(preempts);
        crate::out("\nARM A2 OK\n");
        if RESTART {
            crate::out("ARM PSCI RESET\n");
            crate::machine_reset();
        }
        crate::out("ARM PSCI POWEROFF\n");
        crate::poweroff()
    }
}
