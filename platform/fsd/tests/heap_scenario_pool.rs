//! Mapped pages per run of the file server's lock-contention scenario and
//! its controls under the production page-mapping allocator
//! (docs/fsd-heap-step-20261013, Task 2).
//!
//! `runtime/src/allocator.rs` is included as a module, so its
//! `MapAllocator` serves this process's heap through the hooks below:
//! `map` / `unmap` / `try_unmap` over a static arena of [`ARENA_PAGES`]
//! pages (the guest's 32 MiB heap window, `MAX_GROW_PAGES`) with the
//! kernel's contract as `tests/runtime_allocator.rs` models it: the lowest
//! free run of pages, fresh pages zeroed, an unmap validated over its whole
//! range (an invalid one ends the process). Nothing here allocates: the
//! arena, its page bitmap, the counters and the ring of map requests are
//! statics, since the allocator they serve is the global one.
//!
//! The global allocator routes by scope: inside a `common::SimScope` (the
//! image builder, the block device, the kernel's pipes, the frames sshd
//! and the probes build, and this driver's own output and bookkeeping)
//! an allocation goes to `System`; everywhere else, the file server's
//! code included, to `HEAP`, the `MapAllocator`. A free goes back to
//! whichever allocator owns its address, so a block never changes owner.
//! The arena therefore holds what the guest's file server would map:
//! the server, its filesystem, the loop's inboxes and replies, its log,
//! plus whatever std itself allocates outside a scope (constant).
//!
//! The free-list shape comes from `MapAllocator::for_each_free`, which
//! `allocator.rs` compiles only under `cfg(test)`. Cargo builds a
//! `harness = false` test target with `--cfg test` (not `--test`), so it is
//! there; a build without it would print `free_nodes=na` and
//! `largest_free_bytes=na` instead.
//!
//! Each series runs in a child process of its own (a fresh heap), one at a
//! time; the parent only starts them. A child runs its scenario
//! `HEAP_SCENARIO_RUNS` times (default 20) and prints, after each run once
//! every channel has settled, one `HEAP SCENARIO POOL RUN` line, then the
//! series' verdict. Growth is printed, never failed on: the exit status is
//! 0 unless a scenario assertion fails.
//!
//! The series: Task 1's four scenarios, `large-release` (ruling R4),
//! `slot-drift` (M4b), `mixed` (lock-contention then large-release, one
//! pair per run) and `lock-contention.nolog` (the loop's log not
//! mirrored), each on Task 1's image and again (`@guest`) on
//! `common::guest_image`, an image at the guest's object count.
//! `HEAP_SCENARIO_ONLY=<series,...>` picks some; `HEAP_SCENARIO_LEAK_PROBE=
//! <bytes>` leaks that much from the measured heap after every run, to show
//! that the driver prints a step.
//!
//! Opt-in (ruling R6): unless `HEAP_SCENARIO_DRIVER=1` is set, the binary
//! prints `HEAP SCENARIO DRIVER SKIPPED set HEAP_SCENARIO_DRIVER=1` and
//! exits 0, so a plain `cargo test -p absd-fsd` (check-all.sh) does not
//! run it. The gate reads only that variable.
//!
//! `steps` counts every run whose mapped pages differ from the run before
//! it, from run 1 -> 2 on (run 1 against BASE is not a step; BASE is
//! printed on the verdict line as `base_pages`). A realloc keeps its
//! block's owner; one crossing a scope (a HEAP block grown inside a
//! `SimScope`, or a System block outside one) is counted on the REST line
//! and fails the run unless `HEAP_SCENARIO_ALLOW_CROSS=1`.

mod common;

#[path = "../../runtime/src/allocator.rs"]
#[allow(dead_code)]
mod allocator;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::io::Write;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use common::{Scenario, SimScope, Sim, guest_image, image, rest_census, run_scenario};

const PAGE: usize = 4096;
/// The guest's heap window (`allocator.rs` `MAX_GROW_PAGES`).
const ARENA_PAGES: usize = 8192;
/// `allocator.rs`: a pooled growth maps at least this many pages.
const MIN_GROW_PAGES: usize = 4;
/// `allocator.rs`: the largest single map, and the dedicated class's bound.
const MAX_MAP_PAGES: usize = 64;
/// Map requests remembered (`heap_diag`), oldest overwritten first.
const RING: usize = 1 << 16;

#[repr(C, align(4096))]
struct Arena(UnsafeCell<[u8; ARENA_PAGES * PAGE]>);
// One thread allocates (`harness = false`, a single-threaded `main`).
unsafe impl Sync for Arena {}
static ARENA: Arena = Arena(UnsafeCell::new([0; ARENA_PAGES * PAGE]));

#[derive(Clone, Copy)]
struct Request {
    size: usize,
    pages: usize,
}

/// The kernel's side and the request record; touched only by the hooks,
/// which run under the allocator's lock, and read between runs.
struct Book {
    used: [u64; ARENA_PAGES / 64],
    mapped: usize,
    pool_pages: usize,
    dedicated_pages: usize,
    /// The class of the request `heap_diag` last named: its maps follow.
    dedicated: bool,
    /// Pooled growth requests (size, pages), in order; `pooled_total` counts
    /// every one ever made.
    pooled: [Request; RING],
    pooled_total: usize,
    pool_unmaps: usize,
}

struct BookCell(UnsafeCell<Book>);
unsafe impl Sync for BookCell {}
static BOOK: BookCell = BookCell(UnsafeCell::new(Book {
    used: [0; ARENA_PAGES / 64],
    mapped: 0,
    pool_pages: 0,
    dedicated_pages: 0,
    dedicated: false,
    pooled: [Request { size: 0, pages: 0 }; RING],
    pooled_total: 0,
    pool_unmaps: 0,
}));

// SAFETY: one thread ever allocates (`harness = false`, a single-threaded
// `main`, children are processes), and the hooks run under the allocator's
// lock or between runs; no two `&mut Book` are used at once, and nothing
// that holds one allocates.
fn book() -> &'static mut Book {
    unsafe { &mut *BOOK.0.get() }
}

fn arena_base() -> usize {
    ARENA.0.get() as usize
}

fn in_arena(pointer: *mut u8) -> bool {
    let address = pointer as usize;
    address >= arena_base() && address < arena_base() + ARENA_PAGES * PAGE
}

/// Ends the process without allocating (the allocator's lock is held).
fn die(message: &[u8], code: i32) -> ! {
    let _ = std::io::stderr().write_all(message);
    std::process::exit(code);
}

fn page_used(book: &Book, page: usize) -> bool {
    book.used[page / 64] & (1 << (page % 64)) != 0
}

fn set_pages(book: &mut Book, first: usize, pages: usize, used: bool) {
    for page in first..first + pages {
        if used {
            book.used[page / 64] |= 1 << (page % 64);
        } else {
            book.used[page / 64] &= !(1 << (page % 64));
        }
    }
}

/// `allocator.rs` `dedicated_pages` (private there) as `heap_diag` sees a
/// request: a page-sized size and its exact page count, at most 64. A
/// pooled request of 4096 bytes or more (alignment over a page, or over
/// 64 pages) always names more pages than that.
fn is_dedicated(size: usize, pages: usize) -> bool {
    size >= PAGE && pages <= MAX_MAP_PAGES && pages == size.div_ceil(PAGE)
}

// The hooks `allocator.rs` calls at the crate root (`runtime/src/lib.rs`
// defines them over the kernel's map/unmap in the guest).

/// The lowest free run of `pages` pages, zeroed, or null.
fn map(pages: u64) -> *mut u8 {
    let pages = pages as usize;
    let book = book();
    if pages == 0 || pages > MAX_MAP_PAGES {
        return ptr::null_mut();
    }
    let mut first = 0;
    while first + pages <= ARENA_PAGES {
        match (first..first + pages).find(|&page| page_used(book, page)) {
            Some(taken) => first = taken + 1,
            None => {
                let pointer = unsafe { (ARENA.0.get() as *mut u8).add(first * PAGE) };
                unsafe { ptr::write_bytes(pointer, 0, pages * PAGE) };
                set_pages(book, first, pages, true);
                book.mapped += pages;
                if book.dedicated {
                    book.dedicated_pages += pages;
                } else {
                    book.pool_pages += pages;
                }
                return pointer;
            }
        }
    }
    ptr::null_mut()
}

const UNMAP_POISON: u8 = 0xdd;

/// Unmaps a whole mapped range, or `false` without changing anything when
/// the range is not one.
fn unmap_range(pointer: *mut u8, pages: u64) -> bool {
    let pages = pages as usize;
    let book = book();
    if !in_arena(pointer) || pages == 0 || pages > MAX_MAP_PAGES {
        return false;
    }
    let offset = pointer as usize - arena_base();
    let first = offset / PAGE;
    if !offset.is_multiple_of(PAGE)
        || first + pages > ARENA_PAGES
        || !(first..first + pages).all(|page| page_used(book, page))
    {
        return false;
    }
    unsafe { ptr::write_bytes(pointer, UNMAP_POISON, pages * PAGE) };
    set_pages(book, first, pages, false);
    book.mapped -= pages;
    true
}

/// A dedicated block's own pages (`dealloc`).
fn unmap(pointer: *mut u8, pages: u64) {
    if !unmap_range(pointer, pages) {
        die(b"HEAP SCENARIO POOL FAILED unmap of an unmapped range\n", 102);
    }
    let book = book();
    match book.dedicated_pages.checked_sub(pages as usize) {
        Some(left) => book.dedicated_pages = left,
        None => die(b"HEAP SCENARIO POOL FAILED dedicated pages below zero\n", 102),
    }
}

/// One free pooled run (R16): only when the window is full.
fn try_unmap(pointer: *mut u8, pages: u64) -> bool {
    if !unmap_range(pointer, pages) {
        die(b"HEAP SCENARIO POOL FAILED pool unmap of an unmapped range\n", 102);
    }
    let book = book();
    match book.pool_pages.checked_sub(pages as usize) {
        Some(left) => book.pool_pages = left,
        None => die(b"HEAP SCENARIO POOL FAILED pool pages below zero\n", 102),
    }
    true
}

/// Called before every map the allocator asks for: the request's size and
/// pages. Records the pooled ones (the runtime prints `HEAP MAP` here).
fn heap_diag(size: usize, pages: usize) {
    let book = book();
    book.dedicated = is_dedicated(size, pages);
    if !book.dedicated {
        book.pooled[book.pooled_total % RING] = Request { size, pages };
        book.pooled_total += 1;
    }
}

fn heap_diag_pool_unmap(_size: usize, _pages: usize) {
    book().pool_unmaps += 1;
}

static HEAP: allocator::MapAllocator = allocator::MapAllocator::new();

/// `SimScope` depth: above zero, allocations are the simulator's.
static SIM_DEPTH: AtomicUsize = AtomicUsize::new(0);

fn sim_enter() {
    SIM_DEPTH.fetch_add(1, Relaxed);
}

fn sim_exit() {
    SIM_DEPTH.fetch_sub(1, Relaxed);
}

/// `HEAP` outside a `SimScope`, `System` inside; a free goes to the owner
/// of its address, and so does a `realloc` (`HEAP`'s is `GlobalAlloc`'s
/// default: allocate, copy, free, all in `HEAP`).
struct Routed;

/// Reallocs whose block's owner differs from the current scope's allocator.
static CROSS_REALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every block is freed or grown by the allocator that made it
// (decided by address: inside the arena is HEAP's); HEAP and System are
// each sound global allocators; one thread allocates.
unsafe impl GlobalAlloc for Routed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if SIM_DEPTH.load(Relaxed) > 0 {
            unsafe { System.alloc(layout) }
        } else {
            unsafe { HEAP.alloc(layout) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if in_arena(pointer) {
            unsafe { HEAP.dealloc(pointer, layout) }
        } else {
            unsafe { System.dealloc(pointer, layout) }
        }
    }
    /// By owner, never by scope: a block stays with its allocator.
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let owned = in_arena(pointer);
        if owned == (SIM_DEPTH.load(Relaxed) > 0) {
            CROSS_REALLOCS.fetch_add(1, Relaxed);
        }
        if owned {
            unsafe { HEAP.realloc(pointer, layout, new_size) }
        } else {
            unsafe { System.realloc(pointer, layout, new_size) }
        }
    }
}

#[global_allocator]
static GLOBAL: Routed = Routed;

/// The free list: (nodes, largest node's bytes, all its bytes), or `None`
/// without `cfg(test)`. Every node must lie on mapped pages.
#[cfg(test)]
fn free_shape() -> Option<(usize, usize, usize)> {
    let (mut nodes, mut largest, mut total, mut outside) = (0usize, 0usize, 0usize, 0usize);
    let book = book();
    // The closure runs under the allocator's lock: it must not allocate.
    HEAP.for_each_free(|address, size| {
        nodes += 1;
        largest = largest.max(size);
        total += size;
        let first = (address - arena_base()) / PAGE;
        let end = (address - arena_base() + size).div_ceil(PAGE);
        if !in_arena(address as *mut u8) || !(first..end).all(|page| page_used(book, page)) {
            outside += 1;
        }
    });
    assert_eq!(outside, 0, "free-list nodes on unmapped pages");
    Some((nodes, largest, total))
}

#[cfg(not(test))]
fn free_shape() -> Option<(usize, usize, usize)> {
    None
}

#[derive(Clone, Copy)]
struct Sample {
    mapped: usize,
    pool: usize,
    dedicated: usize,
    free: Option<(usize, usize, usize)>,
    pooled_total: usize,
    pool_unmaps: usize,
    cross_reallocs: usize,
}

/// Read before anything is formatted.
fn sample() -> Sample {
    let free = free_shape();
    let book = book();
    assert_eq!(book.mapped, book.pool_pages + book.dedicated_pages, "page classes");
    assert_eq!(
        book.mapped,
        book.used.iter().map(|word| word.count_ones() as usize).sum::<usize>(),
        "mapped pages against the bitmap"
    );
    Sample {
        mapped: book.mapped,
        pool: book.pool_pages,
        dedicated: book.dedicated_pages,
        free,
        pooled_total: book.pooled_total,
        pool_unmaps: book.pool_unmaps,
        cross_reallocs: CROSS_REALLOCS.load(Relaxed),
    }
}

fn free_fields(out: &mut impl Write, free: Option<(usize, usize, usize)>) {
    match free {
        Some((nodes, largest, _)) => write!(out, "free_nodes={nodes} largest_free_bytes={largest}"),
        None => write!(out, "free_nodes=na largest_free_bytes=na"),
    }
    .unwrap();
}

/// The pooled growth requests between two samples: `size` for a
/// `MIN_GROW_PAGES` growth, `size:pages` otherwise; `none` for none.
fn sizes(out: &mut impl Write, from: usize, to: usize) {
    if from == to {
        write!(out, "none").unwrap();
        return;
    }
    let start = if to - from > RING {
        write!(out, "truncated:{},", to - from - RING).unwrap();
        to - RING
    } else {
        from
    };
    for index in start..to {
        let request = book().pooled[index % RING];
        if index > start {
            write!(out, ",").unwrap();
        }
        if request.pages == MIN_GROW_PAGES {
            write!(out, "{}", request.size).unwrap();
        } else {
            write!(out, "{}:{}", request.size, request.pages).unwrap();
        }
    }
}

/// The series one child runs: (scenarios per run, the server's slots,
/// whether the loop's log is mirrored). A name ending `@guest` runs on
/// `common::guest_image` instead of Task 1's image.
fn series(name: &str) -> (Vec<Scenario>, usize, bool) {
    let name = name.strip_suffix("@guest").unwrap_or(name);
    let all = [
        Scenario::LockContention,
        Scenario::PlainLock,
        Scenario::ContentionNoKill,
        Scenario::ContentionNoScratch,
        Scenario::LargeRelease,
        Scenario::SlotDrift,
    ];
    if name == "mixed" {
        return (vec![Scenario::LockContention, Scenario::LargeRelease], common::SLOTS, true);
    }
    if name == "lock-contention.nolog" {
        return (vec![Scenario::LockContention], common::SLOTS, false);
    }
    match all.into_iter().find(|s| s.name() == name) {
        Some(scenario) => (vec![scenario], scenario.slots(), true),
        None => panic!("no series {name}"),
    }
}

const SERIES: [&str; 16] = [
    "lock-contention",
    "plain-lock",
    "contention-no-kill",
    "contention-no-scratch",
    "large-release",
    "slot-drift",
    "mixed",
    "lock-contention.nolog",
    "lock-contention@guest",
    "plain-lock@guest",
    "contention-no-kill@guest",
    "contention-no-scratch@guest",
    "large-release@guest",
    "slot-drift@guest",
    "mixed@guest",
    "lock-contention.nolog@guest",
];

/// The run after which mapped pages never change again (1-based), or
/// `None` when the last run itself changed them.
fn plateau(pages: &[usize]) -> Option<usize> {
    let last = *pages.last().unwrap();
    let mut at = pages.len();
    while at > 1 && pages[at - 2] == last {
        at -= 1;
    }
    (at < pages.len() || pages.len() == 1).then_some(at)
}

fn verdict(out: &mut impl Write, name: &str, base: usize, pages: &[usize]) {
    let steps = pages.windows(2).filter(|pair| pair[0] != pair[1]).count();
    write!(out, "HEAP SCENARIO POOL scenario={name} runs={} pages=", pages.len()).unwrap();
    for (index, p) in pages.iter().enumerate() {
        write!(out, "{}{p}", if index > 0 { "," } else { "" }).unwrap();
    }
    write!(out, " steps={steps} plateau_at=").unwrap();
    match plateau(pages) {
        Some(run) => write!(out, "{run}"),
        None => write!(out, "none"),
    }
    .unwrap();
    // M1: the first run whose mapped pages differ from the run before.
    match pages.windows(2).position(|pair| pair[0] != pair[1]) {
        Some(at) => write!(
            out,
            " first_step=run{}={},run{}={}",
            at + 1,
            pages[at],
            at + 2,
            pages[at + 1]
        ),
        None => write!(out, " first_step=none"),
    }
    .unwrap();
    writeln!(out, " base_pages={base}").unwrap();
}

/// A member's name in a series of several (`mixed.large-release@guest`),
/// or the series' own name.
fn member_label(name: &str, scenarios: &[Scenario], scenario: Scenario) -> String {
    if scenarios.len() == 1 {
        return name.to_string();
    }
    match name.split_once('@') {
        Some((stem, image)) => format!("{stem}.{}@{image}", scenario.name()),
        None => format!("{name}.{}", scenario.name()),
    }
}

fn run_child(name: &str, runs: usize, leak: usize, allow_cross: bool) {
    let (scenarios, slots, log) = {
        let _sim = SimScope::new();
        series(name)
    };
    let guest = name.ends_with("@guest");
    let base = if guest { guest_image() } else { image() };
    let disk = base.copy();
    let mut sim = Sim::with(&disk, slots, log);
    // Per member, the mapped pages after each run (the simulator's).
    let mut pages: Vec<Vec<usize>> = {
        let _sim = SimScope::new();
        scenarios.iter().map(|_| Vec::with_capacity(runs)).collect()
    };
    let start = sample();
    {
        let _sim = SimScope::new();
        let mut out = std::io::stdout().lock();
        write!(
            out,
            "HEAP SCENARIO POOL BASE scenario={name} image={} fs_objects={} slots={slots} log={} mapped_pages={} pool_pages={} dedicated_live={} ",
            if guest { "guest-scale" } else { "task1" },
            sim.h.server.fs.object_count(),
            if log { "fsd" } else { "none" },
            start.mapped,
            start.pool,
            start.dedicated
        )
        .unwrap();
        free_fields(&mut out, start.free);
        writeln!(out).unwrap();
    }
    let mut before = start;
    for k in 1..=runs {
        for (member, &scenario) in scenarios.iter().enumerate() {
            run_scenario(&mut sim, scenario);
            if leak > 0 {
                // The check of the check: a server-side block that outlives
                // the run.
                std::mem::forget(vec![0u8; leak]);
            }
            let after = sample();
            let (objects, bound, opens, draining) = rest_census(&sim.h.server);
            let _sim = SimScope::new();
            // `stat` takes `&self`; what it allocates is transient and, in
            // this scope, not the measured heap's.
            let log_bytes = match sim.h.server.fs.stat(b"/var/log/fsd") {
                Ok(attr) => attr.size.to_string(),
                Err(_) => "none".to_string(),
            };
            pages[member].push(after.mapped);
            let label = member_label(name, &scenarios, scenario);
            let mut out = std::io::stdout().lock();
            write!(
                out,
                "HEAP SCENARIO POOL RUN scenario={label} run={k} mapped_pages={} pool_pages={} dedicated_live={} ",
                after.mapped, after.pool, after.dedicated
            )
            .unwrap();
            free_fields(&mut out, after.free);
            write!(out, " pool_maps_this_run={} sizes=", after.pooled_total - before.pooled_total).unwrap();
            sizes(&mut out, before.pooled_total, after.pooled_total);
            writeln!(out).unwrap();
            writeln!(
                out,
                "HEAP SCENARIO POOL REST scenario={label} run={k} rest={objects}/{bound}/{opens}/{draining} idle_commits={} pool_unmaps_this_run={} pool_held_bytes={} log_bytes={log_bytes} cross_scope_reallocs={}",
                sim.idle_commits,
                after.pool_unmaps - before.pool_unmaps,
                match after.free {
                    // Pooled bytes not on the free list: held blocks.
                    Some((_, _, free)) => (after.pool * PAGE - free).to_string(),
                    None => "na".to_string(),
                },
                after.cross_reallocs - before.cross_reallocs
            )
            .unwrap();
            drop(out);
            assert!(
                allow_cross || after.cross_reallocs == before.cross_reallocs,
                "{name} run {k}: a realloc crossed a scope (HEAP_SCENARIO_ALLOW_CROSS=1 to report only)"
            );
            drop(label);
            before = after;
        }
    }
    let _sim = SimScope::new();
    let mut out = std::io::stdout().lock();
    if scenarios.len() > 1 {
        // A member's own series, then the pair's (after the last member).
        for (member, scenario) in scenarios.iter().enumerate() {
            verdict(&mut out, &member_label(name, &scenarios, *scenario), start.mapped, &pages[member]);
        }
    }
    verdict(&mut out, name, start.mapped, pages.last().unwrap());
    out.flush().unwrap();
}

/// Ruling R6: the driver runs only when asked; the gate reads nothing else.
fn gate() {
    if std::env::var_os("HEAP_SCENARIO_DRIVER").is_none_or(|value| value != "1") {
        println!("HEAP SCENARIO DRIVER SKIPPED set HEAP_SCENARIO_DRIVER=1");
        std::process::exit(0);
    }
}

fn main() {
    let _sim = SimScope::new();
    gate();
    let runs: usize = match std::env::var("HEAP_SCENARIO_RUNS") {
        Ok(text) => text.parse().expect("HEAP_SCENARIO_RUNS: a number"),
        Err(_) => 20,
    };
    assert!(runs >= 3, "HEAP_SCENARIO_RUNS must be at least 3 (run 1 is warm-up)");
    // A check of the check: `HEAP_SCENARIO_LEAK_PROBE=<bytes>` leaks that
    // many bytes from the measured heap after every run.
    let leak: usize = match std::env::var("HEAP_SCENARIO_LEAK_PROBE") {
        Ok(text) => text.parse().expect("HEAP_SCENARIO_LEAK_PROBE: a number"),
        Err(_) => 0,
    };
    let allow_cross = std::env::var_os("HEAP_SCENARIO_ALLOW_CROSS").is_some_and(|value| value == "1");
    if let Ok(name) = std::env::var("HEAP_SCENARIO_CHILD") {
        drop(_sim);
        run_child(&name, runs, leak, allow_cross);
        return;
    }
    let only = std::env::var("HEAP_SCENARIO_ONLY").ok();
    let names: Vec<String> = match &only {
        Some(list) => list.split(',').map(str::to_string).collect(),
        None => SERIES.iter().map(|s| s.to_string()).collect(),
    };
    for name in &names {
        assert!(SERIES.contains(&name.as_str()), "HEAP_SCENARIO_ONLY: no series {name}");
    }
    println!(
        "HEAP SCENARIO POOL START runs={runs} leak_probe={leak} series={} arena_pages={ARENA_PAGES} free_list={}",
        names.join(","),
        if cfg!(test) { "for_each_free" } else { "na (built without --cfg test)" }
    );
    std::io::stdout().flush().unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut failed = Vec::new();
    for name in &names {
        let status = std::process::Command::new(&exe)
            .env("HEAP_SCENARIO_CHILD", name)
            .env("HEAP_SCENARIO_RUNS", runs.to_string())
            .status()
            .unwrap();
        if !status.success() {
            println!("HEAP SCENARIO POOL FAILED scenario={name} status={status}");
            failed.push(name.clone());
        }
    }
    std::io::stdout().flush().unwrap();
    if !failed.is_empty() {
        std::process::exit(1);
    }
}
