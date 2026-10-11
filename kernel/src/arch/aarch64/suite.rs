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
