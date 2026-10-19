//! Live heap at rest per run of the file server's lock-contention scenario
//! (docs/fsd-heap-step-20261013, Task 1). A counting global allocator over
//! `System`; `harness = false` and a single-threaded `main`, so nothing
//! of the test harness (threads, output capture) is in the count.
//!
//! Each scenario gets a fresh copy of one image, a fresh server and fresh
//! pipes, then runs `HEAP_SCENARIO_RUNS` times (default 20). After each run,
//! once every channel has settled, the process's live bytes and blocks are
//! read before anything is formatted. Run 1 is warm-up (first-use
//! capacity); every run k >= 2 must leave the same live bytes and blocks,
//! or the binary prints the growth and exits 1 after all scenarios.
//! `HEAP_SCENARIO_LEAK_PROBE=<bytes>` leaks that much per run, to show the
//! check reports growth.
//!
//! Opt-in (ruling R6): unless `HEAP_SCENARIO_DRIVER=1` is set, the binary
//! prints `HEAP SCENARIO DRIVER SKIPPED set HEAP_SCENARIO_DRIVER=1` and
//! exits 0, so a plain `cargo test -p absd-fsd` (check-all.sh) does not
//! run it. The gate reads only that variable.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use common::{Scenario, Sim, image, rest_census, run_scenario};

struct Counting;

static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE_BLOCKS: AtomicU64 = AtomicU64::new(0);
static ALLOCS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as u64, Relaxed);
            LIVE_BLOCKS.fetch_add(1, Relaxed);
            ALLOCS.fetch_add(1, Relaxed);
        }
        block
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let block = unsafe { System.alloc_zeroed(layout) };
        if !block.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as u64, Relaxed);
            LIVE_BLOCKS.fetch_add(1, Relaxed);
            ALLOCS.fetch_add(1, Relaxed);
        }
        block
    }
    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        unsafe { System.dealloc(block, layout) };
        LIVE_BYTES.fetch_sub(layout.size() as u64, Relaxed);
        LIVE_BLOCKS.fetch_sub(1, Relaxed);
    }
    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(block, layout, new_size) };
        if !moved.is_null() {
            // One block either way; a realloc counts as an allocation.
            LIVE_BYTES.fetch_add(new_size as u64, Relaxed);
            LIVE_BYTES.fetch_sub(layout.size() as u64, Relaxed);
            ALLOCS.fetch_add(1, Relaxed);
        }
        moved
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

// `common::SimScope`'s hooks: this driver counts the simulator's
// allocations too (they are held constant across runs, as in Task 1).
fn sim_enter() {}
fn sim_exit() {}

#[derive(Clone, Copy)]
struct Rest {
    bytes: u64,
    blocks: u64,
    allocs: u64,
}

fn sample() -> Rest {
    Rest {
        bytes: LIVE_BYTES.load(Relaxed),
        blocks: LIVE_BLOCKS.load(Relaxed),
        allocs: ALLOCS.load(Relaxed),
    }
}

/// Ruling R6: the driver runs only when asked; the gate reads nothing else.
fn gate() {
    if std::env::var_os("HEAP_SCENARIO_DRIVER").is_none_or(|value| value != "1") {
        println!("HEAP SCENARIO DRIVER SKIPPED set HEAP_SCENARIO_DRIVER=1");
        std::process::exit(0);
    }
}

fn main() {
    gate();
    let runs: usize = match std::env::var("HEAP_SCENARIO_RUNS") {
        Ok(text) => text.parse().expect("HEAP_SCENARIO_RUNS: a number"),
        Err(_) => 20,
    };
    assert!(runs >= 3, "HEAP_SCENARIO_RUNS must be at least 3 (run 1 is warm-up)");
    // A check of the check: `HEAP_SCENARIO_LEAK_PROBE=<bytes>` leaks that
    // many bytes after every run, which must be reported as GROWTH.
    let leak: usize = match std::env::var("HEAP_SCENARIO_LEAK_PROBE") {
        Ok(text) => text.parse().expect("HEAP_SCENARIO_LEAK_PROBE: a number"),
        Err(_) => 0,
    };
    if leak > 0 {
        println!("HEAP SCENARIO LEAK PROBE bytes_per_run={leak}");
    }
    // The first line also allocates stdout's buffer before any sample.
    println!("HEAP SCENARIO START runs={runs}");
    let base = image();
    let mut failed = false;
    for scenario in Scenario::ALL {
        let name = scenario.name();
        let disk = base.copy();
        let mut sim = Sim::new(&disk);
        let mut series: Vec<Rest> = Vec::with_capacity(runs);
        for k in 1..=runs {
            run_scenario(&mut sim, scenario);
            if leak > 0 {
                std::mem::forget(vec![0u8; leak]);
            }
            let rest = sample();
            let (objects, bound, opens, draining) = rest_census(&sim.h.server);
            series.push(rest);
            println!(
                "HEAP SCENARIO RUN scenario={name} run={k} live_bytes={} live_blocks={} allocs={} rest={objects}/{bound}/{opens}/{draining}",
                rest.bytes, rest.blocks, rest.allocs
            );
        }
        // Runs k >= 2: run k against run k+1 (series index k-1 against k).
        let differs = (1..runs - 1).find(|&at| {
            series[at].bytes != series[at + 1].bytes || series[at].blocks != series[at + 1].blocks
        });
        match differs {
            None => println!(
                "HEAP SCENARIO COUNTING OK scenario={name} runs={runs} live_bytes={} live_blocks={}",
                series[1].bytes, series[1].blocks
            ),
            Some(at) => {
                // The first run that differs from the one before it, and
                // the mean change per run from run 2 to the last.
                let span = (runs - 2) as i64;
                let last = series[runs - 1];
                let bytes = (last.bytes as i64 - series[1].bytes as i64) / span;
                let blocks = (last.blocks as i64 - series[1].blocks as i64) / span;
                // The first differing pair too: an integer mean can be 0
                // for one small step.
                let (before, after) = (series[at], series[at + 1]);
                println!(
                    "HEAP SCENARIO COUNTING GROWTH scenario={name} first_run={} bytes_per_run={bytes} blocks_per_run={blocks} run{}={}/{} run{}={}/{}",
                    at + 2,
                    at + 1,
                    before.bytes,
                    before.blocks,
                    at + 2,
                    after.bytes,
                    after.blocks
                );
                failed = true;
            }
        }
        drop(sim);
        drop(disk);
    }
    std::io::stdout().flush().unwrap();
    if failed {
        std::process::exit(1);
    }
}
