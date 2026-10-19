//! Sequential competing transitions force the retained first-fit worst case.
use absd_kernel::memory::{Frame, FrameAllocator, FrameOwner, MAX_TRACKED_FRAMES, PAGE_SIZE};
use std::{hint::black_box, time::Instant};

fn main() {
    for held in [256, 8192, 60000] {
        let mut frames = Box::new(FrameAllocator::new());
        frames.add_usable(PAGE_SIZE, MAX_TRACKED_FRAMES as u64 * PAGE_SIZE);
        let competing = FrameOwner::UserPage(2);
        let protected = FrameOwner::UserPage(1);
        assert_eq!(
            frames.allocate_contiguous(held, competing),
            Some(Frame(PAGE_SIZE))
        );
        #[cfg(feature = "frame-reservation-experiment")]
        frames.admit(1, 1).unwrap();
        let mut samples = Vec::new();
        for _ in 0..101 {
            // B returns the lowest frame and immediately reclaims it. The
            // remaining occupied prefix must be examined again to keep exact
            // first-fit order, without an additional allocation index.
            frames.free(Frame(PAGE_SIZE), competing).unwrap();
            assert_eq!(frames.allocate(competing), Some(Frame(PAGE_SIZE)));
            let start = Instant::now();
            let page = black_box(frames.allocate(protected).unwrap());
            samples.push(start.elapsed().as_nanos());
            assert_eq!(page, Frame((held as u64 + 1) * PAGE_SIZE));
            frames.free(page, protected).unwrap();
        }
        samples.sort_unstable();
        assert_eq!(frames.allocated_frames(), held);
        #[cfg(feature = "frame-reservation-experiment")]
        assert_eq!(frames.reservation(1), Some((1, 0)));
        println!(
            "competing_prefix_frames={held} samples=101 allocation_ns_median={} p99={} max={} timer_included=true serialized_transitions=true",
            samples[50], samples[99], samples[100]
        );
    }
}
