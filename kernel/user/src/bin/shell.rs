//! The first interactive program: reads lines from the console, runs the
//! named catalog program with an optional numeric argument, and reports how
//! it ended. A trailing `&` starts the program as a background job; `jobs`
//! lists them, `wait` collects them in order; a trailing `|` captures the
//! program's output through a pipe and prints it afterwards with its size;
//! `kill N` ends job N; `quit` ends the session.
#![no_std]
#![no_main]

use absd_user::cprintln;
use absd_user::{
    Child, Console, INFO_STATE_LIVE, INFO_STATE_WAITING, Outcome, Pipe, RIGHT_READ, RIGHT_WRITE,
    Start, close, duplicate, info, kill, program, spawn_captured, spawn_with, wait,
};

absd_user::entry!(main);

const LINE_CAPACITY: usize = 96;
const MAX_JOBS: usize = 8;

#[derive(Clone, Copy)]
struct Job {
    number: u64,
    child: Child,
    program: usize,
}

struct Shell {
    console: Console,
    jobs: [Option<Job>; MAX_JOBS],
    next_job: u64,
}

fn main(start: Start) -> i32 {
    let mut shell = Shell {
        console: start.console,
        jobs: [None; MAX_JOBS],
        next_job: 1,
    };
    let _ = shell
        .console
        .write_str("absd shell: program [argument] [& or |], jobs, wait, kill N, or quit\n");
    let mut line = [0u8; LINE_CAPACITY];
    let mut length = 0;
    let _ = shell.console.write_str("> ");
    loop {
        let mut chunk = [0u8; 32];
        let Ok(count) = shell.console.read_once(&mut chunk) else {
            return 85;
        };
        for &byte in &chunk[..count] {
            match byte {
                b'\n' | b'\r' => {
                    let command = &line[..length];
                    length = 0;
                    if command == b"quit" {
                        let _ = shell.console.write_str("shell: bye\n");
                        return 0;
                    }
                    shell.run(command);
                    let _ = shell.console.write_str("> ");
                }
                _ if length < LINE_CAPACITY => {
                    line[length] = byte;
                    length += 1;
                }
                _ => {}
            }
        }
    }
}

impl Shell {
    fn run(&mut self, command: &[u8]) {
        let mut words = command
            .split(|&byte| byte == b' ')
            .filter(|word| !word.is_empty());
        let Some(name) = words.next() else {
            return;
        };
        match name {
            b"jobs" => return self.list_jobs(),
            b"wait" => return self.collect_jobs(),
            b"kill" => {
                let number = words.next().map_or(0, parse_decimal);
                return self.kill_job(number);
            }
            _ => {}
        }
        let mut argument = 0;
        let mut background = false;
        let mut capture = false;
        for word in words {
            match word {
                b"&" => background = true,
                b"|" => capture = true,
                _ => argument = parse_decimal(word),
            }
        }
        let Some(index) = program::NAMES
            .iter()
            .position(|known| known.as_bytes() == name)
        else {
            let _ = self.console.write_str("shell: unknown program ");
            let _ = self.console.write_all(name);
            let _ = self.console.write_str("\n");
            return;
        };
        if capture {
            return self.run_captured(index, argument);
        }
        let child = match spawn_with(index as u64, 0, argument) {
            Ok(child) => child,
            Err(error) => {
                let _ = cprintln!(self.console, "shell: spawn failed: {error:?}");
                return;
            }
        };
        if background {
            self.start_job(child, index);
        } else {
            self.report(child, index, None);
        }
    }

    /// Runs a program with a pipe as its console, then prints what it wrote.
    fn run_captured(&mut self, index: usize, argument: u64) {
        let Ok(pipe) = Pipe::create() else {
            let _ = self.console.write_str("shell: no pipe available\n");
            return;
        };
        let reading = duplicate(pipe.raw(), RIGHT_READ).map(Pipe::from_raw);
        let writing = duplicate(pipe.raw(), RIGHT_WRITE);
        let _ = close(pipe.raw());
        let (Ok(reading), Ok(writing)) = (reading, writing) else {
            let _ = self.console.write_str("shell: could not split the pipe\n");
            return;
        };
        let child = spawn_captured(index as u64, writing, argument);
        let _ = close(writing);
        let child = match child {
            Ok(child) => child,
            Err(error) => {
                let _ = close(reading.raw());
                let _ = cprintln!(self.console, "shell: spawn failed: {error:?}");
                return;
            }
        };
        let mut captured = [0u8; 512];
        let mut filled = 0;
        loop {
            let room = &mut captured[filled..];
            if room.is_empty() {
                // Drain what does not fit so the child is never stuck.
                let mut sink = [0u8; 64];
                match reading.read_once(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            match reading.read_once(room) {
                Ok(0) | Err(_) => break,
                Ok(count) => filled += count,
            }
        }
        let _ = close(reading.raw());
        self.report(child, index, None);
        let _ = cprintln!(
            self.console,
            "shell: captured {filled} bytes from {}",
            program::NAMES[index]
        );
        let _ = self.console.write_all(&captured[..filled]);
    }

    fn start_job(&mut self, child: Child, program: usize) {
        let Some(slot) = self.jobs.iter().position(Option::is_none) else {
            let _ = self.console.write_str("shell: job table full\n");
            let _ = wait(Some(child));
            return;
        };
        let number = self.next_job;
        self.next_job += 1;
        self.jobs[slot] = Some(Job {
            number,
            child,
            program,
        });
        let pid = info(Some(child)).map_or(0, |record| record.pid);
        let _ = cprintln!(
            self.console,
            "shell: started {} as job {number} (pid {pid})",
            program::NAMES[program]
        );
    }

    fn list_jobs(&mut self) {
        let mut any = false;
        for job in self.jobs.iter().flatten() {
            any = true;
            let (pid, state) = match info(Some(job.child)) {
                Ok(record) if record.state == INFO_STATE_LIVE => (record.pid, "running"),
                Ok(record) if record.state == INFO_STATE_WAITING => (record.pid, "waiting"),
                Ok(record) => (record.pid, "finished"),
                Err(_) => (0, "gone"),
            };
            let _ = cprintln!(
                self.console,
                "job {}: {} pid {pid} {state}",
                job.number,
                program::NAMES[job.program]
            );
        }
        if !any {
            let _ = self.console.write_str("shell: no jobs\n");
        }
    }

    /// Ends a job now; `wait` still collects its outcome afterwards.
    fn kill_job(&mut self, number: u64) {
        let Some(job) = self.jobs.iter().flatten().find(|job| job.number == number) else {
            let _ = cprintln!(self.console, "shell: no job {number}");
            return;
        };
        let _ = match kill(job.child) {
            Ok(()) => cprintln!(self.console, "shell: killed job {number}"),
            Err(error) => cprintln!(self.console, "shell: kill failed: {error:?}"),
        };
    }

    fn collect_jobs(&mut self) {
        for slot in 0..MAX_JOBS {
            let Some(job) = self.jobs[slot].take() else {
                continue;
            };
            self.report(job.child, job.program, Some(job.number));
        }
    }

    /// One line per outcome, written atomically so a background job's own
    /// output cannot split it.
    fn report(&mut self, child: Child, program: usize, job: Option<u64>) {
        let name = program::NAMES[program];
        let outcome = wait(Some(child));
        let _ = match (job, outcome) {
            (Some(number), Ok(Outcome::Exited(status))) => {
                cprintln!(self.console, "shell: job {number} ({name}) exited {status}")
            }
            (Some(number), Ok(Outcome::Killed)) => {
                cprintln!(self.console, "shell: job {number} ({name}) killed")
            }
            (None, Ok(Outcome::Killed)) => cprintln!(self.console, "shell: {name} killed"),
            (Some(number), Ok(Outcome::Faulted { vector, .. })) => cprintln!(
                self.console,
                "shell: job {number} ({name}) faulted vector {vector}"
            ),
            (Some(number), Err(error)) => cprintln!(
                self.console,
                "shell: job {number} ({name}) wait failed: {error:?}"
            ),
            (None, Ok(Outcome::Exited(status))) => {
                cprintln!(self.console, "shell: {name} exited {status}")
            }
            (None, Ok(Outcome::Faulted { vector, .. })) => {
                cprintln!(self.console, "shell: {name} faulted vector {vector}")
            }
            (None, Err(error)) => {
                cprintln!(self.console, "shell: {name} wait failed: {error:?}")
            }
        };
    }
}

fn parse_decimal(word: &[u8]) -> u64 {
    word.iter()
        .take_while(|byte| byte.is_ascii_digit())
        .fold(0u64, |value, &byte| {
            value.wrapping_mul(10).wrapping_add((byte - b'0') as u64)
        })
}
