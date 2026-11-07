//! Ordinary native userspace producer for the private PCM experiment.
//! PCM generation occurs here, never in QEMU or the host verifier.
use absd_abi::syscall::{ERROR_AGAIN, ERROR_BAD_HANDLE, ERROR_INVALID};
use absd_user::{Console, close, sleep, syscall3, time};
use core::fmt::Write;
fn call(n: u64, a: u64, b: u64, c: u64) -> i64 {
    unsafe { syscall3(n, a, b, c) }
}
fn triangle(frame: u64, period: u64) -> i16 {
    let phase = frame % period;
    let ramp = if phase < period / 2 {
        phase
    } else {
        period - phase
    };
    (ramp as i32 * 32000 / period as i32 - 8000) as i16
}
pub fn run(console: Console) -> Result<(), &'static str> {
    run_tone(console, false)
}
pub fn underrun(console: Console) -> Result<(), &'static str> {
    run_tone(console, true)
}
fn run_tone(mut console: Console, pause: bool) -> Result<(), &'static str> {
    let raw = call(0x7fe0, 0, 0, 0);
    if raw < 0 {
        return Err("PCM root grant");
    }
    let h = raw as u64;
    if call(0x7fe1, console.raw(), 0, 4) != ERROR_BAD_HANDLE {
        return Err("PCM wrong-kind grant accepted");
    }
    if call(0x7fe1, h, 0, 1921) != ERROR_INVALID {
        return Err("PCM oversize accepted");
    }
    let start = time();
    let mut retries = 0u64;
    let mut record = [0u64; 6];
    for period in 0..200u64 {
        if pause && period == 100 {
            loop {
                if call(0x7fe2, h, record.as_mut_ptr() as u64, 48) != 0 {
                    return Err("underrun status");
                }
                if record[4] == 0 {
                    break;
                }
                if time().wrapping_sub(start) > 10000 {
                    return Err("underrun deadline");
                }
                sleep(1);
            }
            let before = time();
            sleep(150);
            let _ = writeln!(
                console,
                "PCM UNDERRUN empty_queue_ticks={}",
                time().wrapping_sub(before)
            );
        }
        let mut pcm = [0u8; 1920];
        for i in 0..480u64 {
            let frame = period * 480 + i;
            let l = triangle(frame, 100).to_le_bytes();
            let r = triangle(frame, 60).to_le_bytes();
            let p = i as usize * 4;
            pcm[p..p + 2].copy_from_slice(&l);
            pcm[p + 2..p + 4].copy_from_slice(&r);
        }
        loop {
            match call(0x7fe1, h, pcm.as_ptr() as u64, 1920) {
                1920 => break,
                ERROR_AGAIN => {
                    retries += 1;
                    sleep(1);
                }
                _ => return Err("PCM submit"),
            }
            if time().wrapping_sub(start) > 10000 {
                return Err("PCM submit deadline");
            }
        }
    }
    loop {
        if call(0x7fe2, h, record.as_mut_ptr() as u64, 48) != 0 {
            return Err("PCM status");
        }
        if record[4] == 0 {
            break;
        }
        if time().wrapping_sub(start) > 10000 {
            return Err("PCM drain deadline");
        }
        sleep(1);
    }
    if record[0] != 1
        || record[1] != 48000 | (2 << 32) | (16 << 40)
        || record[2] != 96000
        || record[3] != 96000
    {
        return Err("PCM completion count");
    }
    let _ = writeln!(
        console,
        "PCM TONE frames={} completed={} elapsed_ticks={} full_retries={} latency_bytes={}",
        record[2],
        record[3],
        time().wrapping_sub(start),
        retries,
        record[5] & 0xffff_ffff
    );
    // Device completion returns guest DMA ownership, not downstream audibility.
    // Give the pinned QEMU WAV backend a bounded 50 ms capture grace before
    // STOP/RELEASE. The verifier still checks every expected signal frame.
    sleep(50);
    if call(0x7fe3, h, 0, 0) != 0 {
        return Err("PCM stop");
    }
    close(h).map_err(|_| "PCM close")?;
    let _ = console.write_str("PCM NATIVE TONE STOPPED left=480Hz right=800Hz peak=8000\n");
    Ok(())
}

#[path = "pcm_stop.rs"]
mod pcm_stop;

struct StopDevice {
    handle: u64,
    pcm: [u8; 1920],
}

impl pcm_stop::Device for StopDevice {
    fn submit(&mut self) -> i64 {
        call(0x7fe1, self.handle, self.pcm.as_ptr() as u64, 1920)
    }
    fn stop(&mut self) -> i64 {
        call(0x7fe3, self.handle, 0, 0)
    }
    fn status(&mut self, state: &mut [u64; 6]) -> i64 {
        call(0x7fe2, self.handle, state.as_mut_ptr() as u64, 48)
    }
    fn time(&mut self) -> u64 {
        time()
    }
    fn sleep(&mut self, ticks: u64) {
        sleep(ticks)
    }
}

pub fn stop_pending(mut console: Console) -> Result<(), &'static str> {
    use absd_abi::syscall::ERROR_IO;
    let h = call(0x7fe0, 0, 0, 0);
    if h < 0 {
        return Err("stop grant");
    }
    let mut device = StopDevice {
        handle: h as u64,
        pcm: [0x20u8; 1920],
    };
    let codes = pcm_stop::Codes {
        again: ERROR_AGAIN,
        io: ERROR_IO,
    };
    let stopped = pcm_stop::run(&mut device, &codes)?;
    close(device.handle).map_err(|_| "stop close")?;
    let _ = match stopped {
        pcm_stop::Stopped::Pending { frames, elapsed } => writeln!(
            console,
            "PCM STOP PENDING OK frames={frames} elapsed_ticks={elapsed} submit_refused=1 reset_observed=1"
        ),
        pcm_stop::Stopped::AlreadyDrained { frames, elapsed } => writeln!(
            console,
            "PCM STOP DRAINED BEFORE STOP OK frames={frames} elapsed_ticks={elapsed} submit_refused=1 reset_observed=1"
        ),
    };
    Ok(())
}

pub fn death_child(console: Console, h: u64) -> Result<(), &'static str> {
    use absd_abi::syscall::ERROR_RIGHTS;
    if call(0x7fe0, 0, 0, 0) != ERROR_RIGHTS {
        return Err("child minted playback authority");
    }
    let _ = console.write_str("PCM CHILD ROOT GRANT REFUSED\n");
    let pcm = [0x10u8; 1920];
    loop {
        match call(0x7fe1, h, pcm.as_ptr() as u64, 1920) {
            1920 => {}
            ERROR_AGAIN => sleep(1),
            _ => return Err("child submit"),
        }
    }
}
pub fn producer_death(mut console: Console) -> Result<(), &'static str> {
    use absd_abi::syscall::{ERROR_IO, ERROR_RIGHTS, RIGHT_READ};
    use absd_user::{Outcome, duplicate, kill, spawn_with, wait_timeout};
    let h = call(0x7fe0, 0, 0, 0);
    if h < 0 {
        return Err("death grant");
    }
    let h = h as u64;
    let reader = duplicate(h, RIGHT_READ).map_err(|_| "death reader")?;
    if call(0x7fe1, reader, 0, 4) != ERROR_RIGHTS {
        return Err("read-only playback accepted write");
    }
    let child = spawn_with(absd_abi::program::INIT, h, 0x504351).map_err(|_| "death spawn")?;
    close(h).map_err(|_| "death parent writer close")?;
    let mut state = [0u64; 6];
    let start = time();
    loop {
        if call(0x7fe2, reader, state.as_mut_ptr() as u64, 48) != 0 {
            return Err("death status before kill");
        }
        if state[2] > 0 && state[4] > 0 {
            break;
        }
        if time().wrapping_sub(start) > 2000 {
            return Err("child made no PCM progress");
        }
        sleep(1);
    }
    // state is the last pre-kill snapshot, not an atomic DMA/termination sample.
    kill(child).map_err(|_| "death kill")?;
    if wait_timeout(Some(child), 1000) != Ok(Outcome::Killed) {
        return Err("death wait");
    }
    if call(0x7fe2, reader, state.as_mut_ptr() as u64, 48) != ERROR_IO {
        return Err("dead last writer device not withdrawn");
    }
    if call(0x7fe0, 0, 0, 0) != ERROR_AGAIN {
        return Err("quarantined stream reopened");
    }
    close(reader).map_err(|_| "death reader close")?;
    let _ = writeln!(
        console,
        "PCM PRODUCER DEATH OK submitted={} pending_at_kill={} elapsed_ticks={} reopen_refused=1",
        state[2],
        state[4],
        time().wrapping_sub(start)
    );
    Ok(())
}
