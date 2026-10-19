//! Foreground native measurement; elapsed times are observations, not deadlines.
use absd_kernel::memory::{Frame, FrameAllocator, FrameOwner, MAX_TRACKED_FRAMES, PAGE_SIZE};
use std::{hint::black_box, time::Instant};

fn main() {
    println!(
        "allocator_bytes={} batch=64 samples=101 timer_included=true",
        std::mem::size_of::<FrameAllocator>()
    );
    for held in [0, 256, 8192, 60000] {
        let mut frames = Box::new(FrameAllocator::new());
        frames.add_usable(PAGE_SIZE, MAX_TRACKED_FRAMES as u64 * PAGE_SIZE);
        if held != 0 {
            frames
                .allocate_contiguous(held, FrameOwner::Kernel)
                .unwrap();
        }
        #[cfg(feature = "frame-reservation-experiment")]
        frames.admit(1, 64).unwrap();
        let mut pages = [Frame(0); 64];
        let mut samples = Vec::new();
        for _ in 0..101 {
            let start = Instant::now();
            for page in &mut pages {
                *page = black_box(frames.allocate(FrameOwner::UserPage(1)).unwrap());
            }
            samples.push(start.elapsed().as_nanos() as f64 / pages.len() as f64);
            for page in pages {
                frames.free(page, FrameOwner::UserPage(1)).unwrap();
            }
        }
        samples.sort_by(f64::total_cmp);
        println!(
            "held_prefix_frames={held} alloc_ns_median={:.2} p99={:.2} min={:.2} max={:.2}",
            samples[50], samples[99], samples[0], samples[100]
        );
    }

    // A full-window alternating pattern has ample free single frames but no
    // two-frame run. This intentionally remains a worst-case contiguous scan.
    let mut frames = Box::new(FrameAllocator::new());
    frames.add_usable(0, MAX_TRACKED_FRAMES as u64 * PAGE_SIZE);
    frames
        .allocate_contiguous(MAX_TRACKED_FRAMES, FrameOwner::Kernel)
        .unwrap();
    for index in (0..MAX_TRACKED_FRAMES).step_by(2) {
        frames
            .free(Frame(index as u64 * PAGE_SIZE), FrameOwner::Kernel)
            .unwrap();
    }
    let mut samples = Vec::new();
    for _ in 0..101 {
        let start = Instant::now();
        assert!(black_box(frames.allocate_contiguous(2, FrameOwner::Kernel)).is_none());
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    println!(
        "fragmented_free_frames={} contiguous_count=2 refused=true scan_ns_median={} p99={} max={}",
        frames.free_frames(),
        samples[50],
        samples[99],
        samples[100]
    );
}
