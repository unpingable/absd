// N-way progress is independent of legacy fixture words. Separate each
// writer's counter by 64 bytes so qualification does not manufacture packed
// cross-core LOCKINC contention. The shared page itself is page-aligned.
const fn nway_progress(id: usize) -> usize { 64 + 8 * id }
// Included by the existing closed SMP fixture; no public placement ABI.
fn nway_epoch_reject(before: &[u64; 6], cpus: usize) -> bool {
    let mut mask = 0;
    for (cpu, epoch) in before.iter().enumerate().take(cpus) {
        if *epoch != load(400 + cpu) {
            mask |= 1 << cpu;
            store(486 + cpu, load(486 + cpu) + 1);
        }
    }
    if mask != 0 {
        store(482, load(482) + 1);
        store(483, load(483) | mask);
    }
    mask != 0
}
fn nway_overlap(cpus: usize) -> Result<(), &'static str> {
    // Only role128 observes. Its own CPU contributes progress without a
    // syscall; either of the two fixed workers contributes on every peer.
    let begin = deadline();
    store(480, 1);
    store(492, begin);
    'attempt: loop {
        require(deadline().wrapping_sub(begin) < 1 << 34, "N-way overlap deadline")?;
        store(481, load(481) + 1);
        let before: [u64; 6] = core::array::from_fn(|cpu| load(400 + cpu));
        core::sync::atomic::fence(Ordering::SeqCst);
        let first: [u64; 6] = core::array::from_fn(|cpu| load(nway_progress(2 * cpu)) + load(nway_progress(2 * cpu + 1)));
        // One increment establishes the observer's own progress. Further
        // increments would add contention without strengthening the proof.
        word(nway_progress(0)).fetch_add(1, Ordering::SeqCst);
        store(480, 2);
        let last = loop {
            let sample: [u64; 6] = core::array::from_fn(|cpu| load(nway_progress(2 * cpu)) + load(nway_progress(2 * cpu + 1)));
            if (0..cpus).all(|cpu| sample[cpu] > first[cpu]) {
                break sample;
            }
            let missing = (0..cpus).fold(0, |mask, cpu| mask | (u64::from(sample[cpu] <= first[cpu]) << cpu));
            store(484, missing);
            store(485, load(485) + 1);
            if nway_epoch_reject(&before, cpus) {
                continue 'attempt;
            }
            require(deadline().wrapping_sub(begin) < 1 << 34, "N-way overlap deadline")?;
            core::hint::spin_loop();
        };
        core::sync::atomic::fence(Ordering::SeqCst);
        let after: [u64; 6] = core::array::from_fn(|cpu| load(400 + cpu));
        if (0..cpus).any(|cpu| before[cpu] != after[cpu]) {
            nway_epoch_reject(&before, cpus);
            continue;
        }
        for cpu in 0..cpus {
            store(420 + cpu, before[cpu]);
            store(430 + cpu, after[cpu]);
            store(440 + cpu, first[cpu]);
            store(450 + cpu, last[cpu]);
        }
        store(480, 4);
        require(test(35, 0, 0) == 0, "N-way overlap acceptance")?;
        store(480, 5);
        store(410, 1);
        return Ok(());
    }
}
fn nway_workers(id: usize) -> Result<(), &'static str> {
    store(272 + id, 1);
    let begin = deadline();
    while load(305) != 1 {
        require(
            deadline().wrapping_sub(begin) < 1 << 34,
            "N-way worker setup",
        )?;
        // Setup is not the preemption witness. Block between readiness
        // checks so AP setup traffic cannot monopolize the global lock
        // while CPU0 is still constructing the remaining workers.
        sleep(1);
    }
    if id == 0 {
        nway_overlap(test(30, 0, 0) as usize)?;
    }
    let image = [
        XMM_SENTINELS[0][0] ^ id as u64,
        XMM_SENTINELS[0][1] ^ id as u64,
    ];
    let sentinel = image.as_ptr();
    let tag = 0x1122_3344_5566_7788u64 ^ id as u64;
    let progress = word(nway_progress(id)) as *const AtomicU64;
    let stop = word(306) as *const AtomicU64;
    let mut intact: u64;
    unsafe {
        core::arch::asm!(
        "movdqu xmm15, [{sentinel}]",
        "mov r12, {tag}",
        "2:", "lock inc qword ptr [{progress}]", "pause",
        "cmp qword ptr [{stop}], 0", "je 2b",
        "mov r13, {tag}", "cmp r12,r13", "jne 3f",
        "movdqu xmm14,[{sentinel}]", "pcmpeqb xmm14,xmm15", "pmovmskb {intact:e},xmm14",
        "jmp 4f", "3:", "xor {intact:e},{intact:e}", "4:",
        tag=in(reg) tag, sentinel=in(reg) sentinel, progress=in(reg) progress, stop=in(reg) stop,
        intact=out(reg) intact,out("r12") _,out("r13") _,out("xmm14") _,out("xmm15") _,
        options(nostack));
    }
    require(intact == 0xffff, "N-way timer register state")?;
    require(
        test(31, cpu(), id as u64) == cpu() as i64,
        "N-way worker witness",
    )
}
fn nway_migrant(steal: bool) -> Result<(), &'static str> {
    require(cpu() == 0 && test(31, 0, 0) == 0, "N-way initial claim")?;
    store(336, getpid());
    store(339, 1);
    let cpus = test(30, 0, 0) as usize;
    let stages = if steal { 2 } else { cpus };
    for stage in 1..=stages {
        if steal && stage == 1 {
            let begin = deadline();
            while cpu() == 0 {
                require(
                    deadline().wrapping_sub(begin) < 1 << 34,
                    "N-way steal deadline",
                )?;
                core::hint::spin_loop();
            }
        } else {
            poll(338, stage as u64)?;
            let destination = if steal { 0 } else { stage % cpus };
            let begin = deadline();
            while cpu() != destination as u64 {
                require(
                    deadline().wrapping_sub(begin) < 1 << 34,
                    "N-way migration deadline",
                )?;
                core::hint::spin_loop();
            }
        }
        require(
            test(31, cpu(), stage as u64) == cpu() as i64,
            "N-way migration user witness",
        )?;
        store(337, cpu());
        store(339, stage as u64 + 1);
    }
    Ok(())
}
fn nway_kills(target: usize) -> Result<(), &'static str> {
    for round in 0..16 {
        store(320 + target, 0);
        let child = spawn(144 + target as u64, 0)?;
        let pid = info(Some(child)).map_err(|_| "N-way victim info")?.pid;
        poll(320 + target, pid)?;
        let begin = deadline();
        // Kernel-saved timer frame is direct evidence of involuntary entry.
        // The CPU1 helper targets CPU0; its private query has the same closed role gate.
        while test(33, pid, 0) <= 0 {
            require(
                deadline().wrapping_sub(begin) < 1 << 34,
                "N-way victim preemption",
            )?;
            core::hint::spin_loop();
        }
        let begin = deadline();
        while deadline().wrapping_sub(begin) < (1 + round * 13) << 17 {
            core::hint::spin_loop();
        }
        let begin = deadline();
        loop {
            match kill(child) {
                Ok(()) => break,
                Err(absd_user::Error::Again) => {
                    require(
                        deadline().wrapping_sub(begin) < 1 << 34,
                        "N-way active victim selection",
                    )?;
                    sleep(1);
                }
                Err(_) => return Err("N-way remote kill"),
            }
        }
        require(
            wait(Some(child)).map_err(|_| "N-way total fence")? == Outcome::Killed,
            "N-way kill outcome",
        )?;
    }
    Ok(())
}
fn nway_pipe_fault(target: usize) -> Result<(), &'static str> {
    let pipe = Pipe::create().map_err(|_| "N-way pipe create")?;
    store(30, 0);
    let reader = spawn(184 + target as u64, pipe.raw())?;
    let pid = info(Some(reader)).map_err(|_| "N-way reader info")?.pid;
    poll(30, pid)?;
    require(
        pipe.write_once(b"n").map_err(|_| "N-way pipe write")? == 1,
        "N-way pipe completion",
    )?;
    exited(reader, 7)?;
    close(pipe.raw()).map_err(|_| "N-way pipe close")?;
    let fault = spawn(176 + target as u64, 0)?;
    require(
        matches!(
            wait(Some(fault)).map_err(|_| "N-way fault fence")?,
            Outcome::Faulted { vector: 14, .. }
        ),
        "N-way fault outcome",
    )
}
fn nway_composition_actor(start: Start) -> Result<(), &'static str> {
    require(cpu() == 0 && test(31, 0, 0) == 0, "composition initial CPU")?;
    store(336, getpid());
    store(339, 1);
    poll(338, 1)?;
    let target = load(337);
    let begin = deadline();
    while cpu() != target {
        require(deadline().wrapping_sub(begin) < 1 << 34, "composition migration deadline")?;
        core::hint::spin_loop();
    }
    require(test(31, target, 1) == target as i64, "composition AP witness")?;
    store(339, 2);
    match start.arg {
        162 => {
            let pipe = Pipe::from_raw(start.handle);
            let mut byte = [0u8; 1];
            require(pipe.read_once(&mut byte).map_err(|_| "composition read")? == 1
                && byte == *b"n", "composition wake result")?;
            require(test(31, target, 2) == target as i64, "composition wake placement")
        }
        163 => {
            unsafe { (0x10_0000 as *mut u64).write_volatile(1); }
            Err("composition fault resumed")
        }
        164 => Ok(()),
        165 => loop { core::hint::spin_loop(); },
        _ => Err("unknown composition role"),
    }
}
fn nway_compositions(cpus: usize) -> Result<(), &'static str> {
    for target in 1..cpus {
        for role in 162..=165 {
            for index in 336..=339 { store(index, 0); }
            store(30, 0);
            let pipe = if role == 162 {
                Some(Pipe::create().map_err(|_| "composition pipe")?)
            } else { None };
            let child = spawn(role, pipe.as_ref().map_or(0, |p| p.raw()))?;
            let pid = info(Some(child)).map_err(|_| "composition child identity")?.pid;
            poll(336, pid)?;
            poll(339, 1)?;
            if role == 162 { require(test(26, pid, 0) == 0, "composition block arm")?; }
            require(test(20, pid, target as u64) == 0, "composition directed migration")?;
            store(337, target as u64);
            store(338, 1);
            poll(339, 2)?;
            match role {
                162 => {
                    poll(30, pid)?;
                    require(test(20, pid, 0) == absd_abi::syscall::ERROR_AGAIN,
                        "composition blocked migration refusal")?;
                    require(pipe.as_ref().unwrap().write_once(b"n").map_err(|_| "composition write")? == 1,
                        "composition write result")?;
                    exited(child, 7)?;
                    close(pipe.unwrap().raw()).map_err(|_| "composition close")?;
                }
                163 => require(matches!(wait(Some(child)).map_err(|_| "composition fault wait")?,
                    Outcome::Faulted { vector: 14, .. }), "composition fault outcome")?,
                164 => exited(child, 7)?,
                165 => {
                    let begin = deadline();
                    while test(36, pid, target as u64) <= 0 {
                        require(deadline().wrapping_sub(begin) < 1 << 34, "composition target timer")?;
                        sleep(1);
                    }
                    require(test(24, pid, 0) == 0, "composition stop arm")?;
                    let begin = deadline();
                    loop {
                        match kill(child) {
                            Ok(()) => break,
                            Err(absd_user::Error::Again) => {
                                require(deadline().wrapping_sub(begin) < 1 << 34, "composition owned victim")?;
                                sleep(1);
                            }
                            Err(_) => return Err("composition kill"),
                        }
                    }
                    require(wait(Some(child)).map_err(|_| "composition kill wait")? == Outcome::Killed,
                        "composition kill outcome")?;
                }
                _ => unreachable!(),
            }
        }
    }
    Ok(())
}
fn nway_root() -> Result<(), &'static str> {
    let cpus = test(30, 0, 0) as usize;
    require(matches!(cpus, 2 | 4 | 6) && cpu() == 0, "N-way count")?;
    let mut children: [Option<Child>; 12] = [None; 12];
    let mut pids = [0u64; 12];
    for (id, child) in children.iter_mut().enumerate().take(cpus * 2) {
        *child = Some(spawn(128 + id as u64, 0)?);
        pids[id] = info(*child).map_err(|_| "N-way worker info")?.pid;
    }
    for id in 0..cpus * 2 {
        poll(272 + id, 1)?;
    }
    store(305, 1);
    let begin = deadline();
    while load(410) != 1
        || (0..cpus * 2).any(|id| load(nway_progress(id)) < 128 || test(33, pids[id], 0) <= 0)
    {
        require(
            deadline().wrapping_sub(begin) < 1 << 34,
            "N-way all-worker progress",
        )?;
        core::hint::spin_loop();
    }
    store(306, 1);
    for child in children.into_iter().take(cpus * 2) {
        exited(child.unwrap(), 7)?;
    }
    for _ in 0..16 {
        for index in 336..=339 {
            store(index, 0);
        }
        let child = spawn(160, 0)?;
        let pid = info(Some(child)).map_err(|_| "N-way migrant info")?.pid;
        poll(336, pid)?;
        poll(339, 1)?;
        for stage in 1..=cpus {
            require(
                test(20, pid, (stage % cpus) as u64) == 0,
                "N-way transfer request",
            )?;
            store(338, stage as u64);
            poll(339, stage as u64 + 1)?;
        }
        exited(child, 7)?;
    }
    for _ in 0..16 {
        for index in 336..=339 {
            store(index, 0);
        }
        let child = spawn(161, 0)?;
        let pid = info(Some(child)).map_err(|_| "N-way steal info")?.pid;
        poll(336, pid)?;
        poll(339, 1)?;
        let begin = deadline();
        while test(6, 0, 0) != 1 {
            require(deadline().wrapping_sub(begin) < 1 << 34, "N-way idle fence")?;
        }
        require(test(21, pid, 0) == 0, "N-way arm competing steal")?;
        poll(339, 2)?;
        require(
            load(337) > 0 && load(337) < cpus as u64,
            "N-way steal winner",
        )?;
        require(test(20, pid, 0) == 0, "N-way stolen return")?;
        store(338, 2);
        poll(339, 3)?;
        exited(child, 7)?;
    }
    for target in 1..cpus {
        nway_kills(target)?;
        nway_pipe_fault(target)?;
    }
    exited(spawn(196, 0)?, 7)?;
    nway_compositions(cpus)?;
    require(test(23, 0, 0) == 0, "N-way exact proof")?;
    require(test(2, 1, 0) == 0, "N-way case count")
}
fn nway_actor(start: Start) -> Result<(), &'static str> {
    match start.arg {
        128..=139 => nway_workers((start.arg - 128) as usize),
        160 => nway_migrant(false),
        161 => nway_migrant(true),
        162..=165 => nway_composition_actor(start),
        144..=149 => {
            store(320 + (start.arg - 144) as usize, getpid());
            loop {
                core::hint::spin_loop();
            }
        }
        176..=181 => {
            unsafe {
                (0x10_0000 as *mut u64).write_volatile(1);
            }
            Err("N-way fault resumed")
        }
        184..=189 => {
            let pipe = Pipe::from_raw(start.handle);
            let mut byte = [0u8; 1];
            require(
                pipe.read_once(&mut byte).map_err(|_| "N-way read")? == 1 && byte == *b"n",
                "N-way wake value",
            )?;
            require(test(31, cpu(), 0) == cpu() as i64, "N-way wake witness")
        }
        196 => {
            nway_kills(0)?;
            nway_pipe_fault(0)
        }
        _ => Err("unknown N-way role"),
    }
}
