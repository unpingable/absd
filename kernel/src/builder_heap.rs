//! #115 builder class heap (`builder-class-heap`): the kernel side of
//! `absd_kernel::builder_class`.
//!
//! - At publication (`activate_spawn`) each process's class is fixed from its
//!   parent's recorded identity and class; the durable worker is designated
//!   at most once per boot, by pid.
//! - `map` and `unmap` of a compiler or tool use the 512 MiB class window;
//!   every other process keeps the profile's bounds.
//! - At construction (`spawn_from_budget`) a compiler, tool or the durable
//!   file server gets its admission budget, which the existing core admits
//!   before any frame is allocated. A refusal, or a construction that runs
//!   past the budget, fails the spawn: the child is reclaimed and never
//!   published, and the caller gets the error.
//! - One `BUILDER PROCESS` line per published class or file-server process
//!   at release: heap high-water marks, refusals, owned frames, its
//!   reservation, the admission accounting and its own kernel-stack use.
//!
//! The hooks sit on existing source lines, so a build without the feature
//! keeps every panic location, and therefore its code, unchanged.
use crate::serial;
use absd_kernel::builder_class::{Class, Parent, budget, classify};
use absd_kernel::layout::{BUILDER_CLASS_HEAP_END, BUILDER_CLASS_HEAP_PAGES, USER_HEAP_BASE};
use absd_kernel::memory::{FrameAllocator, PAGE_SIZE};
use absd_kernel::process::MAX_PROCESSES;

/// Owned frames are counted (one tag scan) each time the heap peak has
/// grown by this many pages since the last count.
const SAMPLE_PAGES: u64 = 256;

#[derive(Clone, Copy)]
struct Record {
    pid: u32,
    parent: u32,
    program: usize,
    class: Class,
    tracked: bool,
    now: u64,
    peak: u64,
    va_high: u64,
    maps: u64,
    window_refusals: u64,
    frame_refusals: u64,
    sample_heap: u64,
    sample_owned: u64,
}

impl Record {
    const EMPTY: Self = Self {
        pid: 0,
        parent: 0,
        program: usize::MAX,
        class: Class::Ordinary,
        tracked: false,
        now: 0,
        peak: 0,
        va_high: 0,
        maps: 0,
        window_refusals: 0,
        frame_refusals: 0,
        sample_heap: 0,
        sample_owned: 0,
    };
}

static mut RECORDS: [Record; MAX_PROCESSES] = [Record::EMPTY; MAX_PROCESSES];
/// The designated durable worker's pid, once per boot (0: none yet).
static mut WORKER: u32 = 0;

/// Kernel-serialized: every caller runs inside a syscall, spawn or reclaim.
fn records() -> &'static mut [Record; MAX_PROCESSES] {
    unsafe { &mut *core::ptr::addr_of_mut!(RECORDS) }
}
fn worker() -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(WORKER)) }
}
/// The record of the process in table slot `index`, if it is `pid`.
fn record(index: usize, pid: u32) -> Option<&'static mut Record> {
    records()
        .get_mut(index)
        .filter(|record| record.tracked && record.pid == pid)
}

fn parent_facts(parent: u64) -> Option<Parent> {
    let parent = u32::try_from(parent).ok().filter(|&pid| pid != 0)?;
    let record = records()
        .iter()
        .find(|record| record.tracked && record.pid == parent)?;
    Some(Parent {
        class: record.class,
        is_init: record.parent == 0 && crate::sched::program_name(record.program) == "init",
    })
}
fn durable() -> bool {
    crate::sched::boot_mode() == crate::sched::BootMode::Durable
}
fn class_of(parent: u64, program: usize) -> Class {
    classify(
        durable(),
        crate::sched::program_name(program) == "external-workload",
        parent_facts(parent),
        worker() != 0,
    )
}
fn class_name(class: Class) -> &'static str {
    match class {
        Class::Ordinary => "ordinary",
        Class::Worker => "worker",
        Class::Compiler => "compiler",
        Class::Tool => "tool",
    }
}

/// `activate_spawn`: fix the class of a newly published process.
pub fn published(index: usize, pid: u64, parent: u64, program: usize) {
    let class = class_of(parent, program);
    if class == Class::Worker {
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(WORKER), pid as u32) };
    }
    records()[index] = Record {
        pid: pid as u32,
        parent: parent as u32,
        program,
        class,
        tracked: true,
        ..Record::EMPTY
    };
    if class != Class::Ordinary || crate::sched::program_name(program) == "external-workload" {
        serial::write("BUILDER CLASS pid=");
        serial::decimal(pid);
        serial::write(" parent=");
        serial::decimal(parent);
        serial::write(" class=");
        serial::write(class_name(class));
        serial::write(" window_pages=");
        serial::decimal(if class.builder() {
            BUILDER_CLASS_HEAP_PAGES
        } else {
            absd_kernel::layout::USER_HEAP_PAGES
        });
        serial::write("\n");
    }
}

/// End of the caller's heap window: the class window for a compiler or
/// tool, otherwise the ordinary bound it is given.
pub fn window_end(index: usize, pid: u32, ordinary: u64) -> u64 {
    match record(index, pid) {
        Some(record) if record.class.builder() => BUILDER_CLASS_HEAP_END,
        _ => ordinary,
    }
}

/// `spawn_from_budget`: the admission budget of the process being built,
/// unless its caller already supplied one.
pub fn construction_budget(supplied: Option<usize>, parent: u64, program: usize) -> Option<usize> {
    if supplied.is_some() {
        return supplied;
    }
    let file_server = durable()
        && crate::sched::program_name(program) == "file-server"
        && parent_facts(parent).is_some_and(|parent| parent.is_init);
    budget(class_of(parent, program), file_server)
}

/// The spawn failed after admission was decided: either the core refused
/// the budget (`admit`) or construction ran past it (`construct`). The child
/// was reclaimed and is never published.
pub fn construction_refused(
    frames: &FrameAllocator,
    pid: u64,
    parent: u64,
    total: Option<usize>,
    stage: &str,
) {
    let Some(total) = total else {
        return;
    };
    serial::write("BUILDER SPAWN REFUSED pid=");
    serial::decimal(pid);
    serial::write(" parent=");
    serial::decimal(parent);
    serial::write(" frames=");
    serial::decimal(total as u64);
    serial::write(" stage=");
    serial::write(stage);
    serial::write(" owned_after=");
    serial::decimal(frames.frames_owned_by(pid as u32) as u64);
    serial::write(" reservation_after=");
    serial::decimal(u64::from(frames.reservation(pid as u32).is_some()));
    accounting(frames);
    serial::write("\n");
}

/// A successful `map` of `pages` pages at `base`.
pub fn mapped(frames: &FrameAllocator, index: usize, pid: u32, base: u64, pages: u64) {
    let Some(record) = record(index, pid) else {
        return;
    };
    record.now += pages;
    record.maps += 1;
    record.va_high = record
        .va_high
        .max((base - USER_HEAP_BASE) / PAGE_SIZE + pages);
    if record.now > record.peak {
        record.peak = record.now;
        if record.peak >= record.sample_heap + SAMPLE_PAGES {
            record.sample_heap = record.now;
            record.sample_owned = frames.frames_owned_by(pid) as u64;
        }
    }
}

/// A successful `unmap` of `pages` pages.
pub fn unmapped(index: usize, pid: u32, pages: u64) {
    if let Some(record) = record(index, pid) {
        record.now = record.now.saturating_sub(pages);
    }
}

/// `map` returned `ERROR_NO_MEMORY`: no free run in the window, or the
/// frames (pool or reservation) ran out part way.
pub fn refused(index: usize, pid: u32, window: bool) {
    if let Some(record) = record(index, pid) {
        if window {
            record.window_refusals += 1;
        } else {
            record.frame_refusals += 1;
        }
    }
}

/// `release_resources`, before the address space is destroyed.
pub fn released(frames: &FrameAllocator, pid: u32, kernel_stack_used: u64) {
    let Some(index) = records()
        .iter()
        .position(|record| record.tracked && record.pid == pid)
    else {
        return;
    };
    let record = core::mem::replace(&mut records()[index], Record::EMPTY);
    let file_server = crate::sched::program_name(record.program) == "file-server";
    if record.class == Class::Ordinary && !file_server {
        return;
    }
    serial::write("BUILDER PROCESS pid=");
    serial::decimal(u64::from(pid));
    serial::write(" parent=");
    serial::decimal(u64::from(record.parent));
    serial::write(" class=");
    serial::write(class_name(record.class));
    serial::write(" heap_peak_pages=");
    serial::decimal(record.peak);
    serial::write(" heap_va_high_pages=");
    serial::decimal(record.va_high);
    serial::write(" maps=");
    serial::decimal(record.maps);
    serial::write(" window_refusals=");
    serial::decimal(record.window_refusals);
    serial::write(" frame_refusals=");
    serial::decimal(record.frame_refusals);
    serial::write(" owned_at_sample=");
    serial::decimal(record.sample_owned);
    serial::write(" heap_at_sample=");
    serial::decimal(record.sample_heap);
    serial::write(" owned_at_release=");
    serial::decimal(frames.frames_owned_by(pid) as u64);
    match frames.reservation(pid) {
        Some((total, used)) => {
            serial::write(" reservation_total=");
            serial::decimal(total as u64);
            serial::write(" reservation_used=");
            serial::decimal(used as u64);
        }
        None => serial::write(" reservation=none"),
    }
    serial::write(" boot_allocated_peak=");
    serial::decimal(frames.peak_allocated() as u64);
    serial::write(" kernel_stack_used_bytes=");
    serial::decimal(kernel_stack_used);
    serial::write(" kernel_stack_bytes=");
    serial::decimal(crate::sched::KERNEL_STACK_BYTES);
    accounting(frames);
    serial::write("\n");
}

fn accounting(frames: &FrameAllocator) {
    let accounting = frames.admission_accounting();
    serial::write(" admission_records=");
    serial::decimal(accounting.records as u64);
    serial::write(" admission_total=");
    serial::decimal(accounting.total);
    serial::write(" admission_used=");
    serial::decimal(accounting.used);
    serial::write(" admission_idle=");
    serial::decimal(accounting.idle);
    serial::write(" admission_consistent=");
    serial::decimal(u64::from(accounting.consistent));
}
