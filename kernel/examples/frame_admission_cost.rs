use absd_kernel::memory::{FrameAllocator, FrameOwner, PAGE_SIZE};
use std::time::Instant;
fn main() {
    let mut f = Box::new(FrameAllocator::new());
    f.add_usable(PAGE_SIZE, 65536 * PAGE_SIZE);
    println!("allocator_bytes={}", std::mem::size_of::<FrameAllocator>());
    for scenario in 0..3 {
        #[cfg(feature = "frame-reservation-experiment")]
        if scenario == 1 {
            for pid in 1..=16 {
                f.admit(pid, 8).unwrap();
            }
        }
        let owner = FrameOwner::UserPage(if scenario == 2 { 16 } else { 100 });
        let mut samples = Vec::new();
        for _ in 0..11 {
            let t = Instant::now();
            for _ in 0..200_000 {
                let page = std::hint::black_box(f.allocate(owner).unwrap());
                f.free(page, owner).unwrap();
            }
            samples.push(t.elapsed().as_nanos() as f64 / 200_000.0);
        }
        samples.sort_by(f64::total_cmp);
        println!(
            "scenario={scenario} alloc_free_ns_median={:.2} min={:.2} max={:.2}",
            samples[5], samples[0], samples[10]
        );
        let mut batch_samples = Vec::new();
        // Eight is also the admitted allowance, so every sample has real backing.
        let mut pages = [absd_kernel::memory::Frame(0); 8];
        for _ in 0..10000 {
            let t = Instant::now();
            for page in &mut pages {
                *page = std::hint::black_box(f.allocate(owner).unwrap());
            }
            batch_samples.push(t.elapsed().as_nanos() as f64 / 8.0);
            for page in pages {
                f.free(page, owner).unwrap();
            }
        }
        batch_samples.sort_by(f64::total_cmp);
        println!(
            "scenario={scenario} alloc_only_ns_median={:.2} p99={:.2} batch=8 timer_included=true",
            batch_samples[5000], batch_samples[9900]
        );
    }
    #[cfg(feature = "frame-reservation-experiment")]
    {
        f.retire_reservation(16).unwrap();
        let mut samples = Vec::new();
        for _ in 0..1000 {
            let t = Instant::now();
            f.admit(100, 8).unwrap();
            samples.push(t.elapsed().as_nanos());
            f.retire_reservation(100).unwrap();
        }
        samples.sort();
        println!(
            "admit_existing_pid_ns_median={} p99={} scan_frames=65536",
            samples[500], samples[990]
        );
    }
}
